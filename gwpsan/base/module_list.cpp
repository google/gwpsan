// Copyright 2024 The GWPSan Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "gwpsan/base/module_list.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/string.h"

SAN_WEAK_IMPORT int main();

namespace gwpsan {
namespace {
constinit internal::ModulesInfo modules;
}  // namespace

namespace internal {

ModulesInfo ParseModuleList(char* buffer, uptr own_addr, uptr main_addr) {
  ModulesInfo info;
  for (char* line = buffer;;) {
    char* pos = line;
    line = internal_strchr(line, '\n');
    if (!line)
      break;
    line[0] = 0;
    line++;
    uptr start = 0, end = 0, offset = 0;
    for (; *pos != '-'; pos++)
      start = start * 16 + (*pos <= '9' ? *pos - '0' : *pos - 'a' + 10);
    for (pos++; *pos != ' '; pos++)
      end = end * 16 + (*pos <= '9' ? *pos - '0' : *pos - 'a' + 10);
    const bool non_exec =
        pos[1] != 'r' || pos[2] != '-' || pos[3] != 'x' || pos[4] != 'p';
    for (pos += 6; *pos != ' '; pos++)
      offset = offset * 16 + (*pos <= '9' ? *pos - '0' : *pos - 'a' + 10);
    if (non_exec) {
      pos = internal_strchr(pos, '[');
      if (pos && !internal_strcmp(pos, "[stack]")) {
        info.stack_end = end;
        SAN_LOG("stack  %p-%p", reinterpret_cast<void*>(info.stack_start),
                reinterpret_cast<void*>(info.stack_end));
      }
      if (!info.stack_end)
        info.stack_start = end;
      continue;
    }
    if (!info.stack_end)
      info.stack_start = end;
    const char* file = internal_strchr(pos, '/');
    if (!file) {
      pos = internal_strchr(pos, '[');
      if (pos && !internal_strcmp(pos, "[vdso]")) {
        file = "[vdso]";
        info.vdso_start = start;
        info.vdso_end = end;
      } else {
        continue;
      }
    }

    if (own_addr >= start && own_addr < end &&
        !(main_addr >= start && main_addr < end)) {
      // We know our own address if the runtime is loaded as a DSO.
      info.own_start = start;
      info.own_end = end;
    }

    offset = start - offset;
    // Detect non-pie main executable as the first module mapped low enough.
    // PCs for symbolization must include the offset for such executables.
    if (!info.list && offset <= 0x00800000)
      offset = 0;
    const char* name = Basename(file);
    auto* mod = PersistentNew<internal::ModuleInfoNode>();
    mod->start_address = start;
    mod->end_address = end;
    mod->pc_offset = offset;
    mod->name = PersistentStrDup(name);
    mod->next = info.list;
    info.list = mod;
    SAN_LOG("module %p-%p/%p %s", reinterpret_cast<void*>(start),
            reinterpret_cast<void*>(end), reinterpret_cast<void*>(offset),
            mod->name);
  }
  return info;
}

}  // namespace internal

bool InitModuleList() {
  SAN_CHECK(!modules.list);
  // The constant comes from https://reviews.llvm.org/D112794.
  // We reserve a huge region and rely on OS lazy allocation,
  // this is much simpler and faster than multiple attempts
  // to read the file with increasing buffer sizes.
  constexpr uptr kBufferSize = 256 << 20;
  char* buffer = Mmap(kBufferSize);
  if (SAN_WARN(!buffer))
    return false;
  bool res = !!ReadFile("/proc/self/maps", {buffer, kBufferSize});
  if (res) {
    uptr me = reinterpret_cast<uptr>(InitModuleList);
    uptr exe = reinterpret_cast<uptr>(&main);
    modules = internal::ParseModuleList(buffer, me, exe);
  }
  Munmap(buffer, kBufferSize);
  return res;
}

bool IsVDSO(uptr pc) {
  return pc >= modules.vdso_start && pc < modules.vdso_end;
}

Optional<bool> IsRuntimeInDSO(uptr pc_or_addr) {
  if (!modules.own_start && !modules.own_end)
    return {};
  return pc_or_addr >= modules.own_start && pc_or_addr < modules.own_end;
}

Optional<Pair<uptr, uptr>> GetStackBounds() {
  if (!modules.stack_start || !modules.stack_end)
    return {};
  return Pair{modules.stack_start, modules.stack_end};
}

const ModuleInfo* FindModule(uptr pc) {
  for (const auto* mod = modules.list; mod; mod = mod->next) {
    if (pc >= mod->start_address && pc < mod->end_address)
      return mod;
  }
  return nullptr;
}

void ForEachModule(FunctionRef<void(const ModuleInfo&)> cb) {
  for (const auto* mod = modules.list; mod; mod = mod->next)
    cb(*mod);
}

}  // namespace gwpsan
