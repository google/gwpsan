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

#include "gwpsan/core/init.h"

#include <dlfcn.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/os.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/semantic_metadata.h"
#include "gwpsan/unified/unified.h"

SAN_WEAK_IMPORT extern "C" int __fork();
SAN_DECLARE_INTERCEPTOR(int, fork);

namespace gwpsan {
namespace {

constinit OptionalBase<UnifiedTool> unified;

bool GwpsanInit() {
  if (!Init())
    return false;
  if (GetFlags().dump) {
    if (!InitSemanticMetadata(kSemanticAll)) {
      Printf("failed to initialize semantic metadata\n");
      Die();
    }
    if (!internal_strcmp(GetFlags().dump, "metadata"))
      DumpSemanticMetadata();
    else if (!internal_strcmp(GetFlags().dump, "instructions"))
      DumpInstructions();
    else
      Printf("supported dump values: metadata, instructions\n");
    Die();
  }

  const auto cfg = UnifiedTool::GetBreakManagerConfig();
  return BreakManager::singleton().try_emplace(cfg) && unified.try_emplace();
}

SAN_PUSH_DIAG("-Wglobal-constructors");
SAN_CONSTRUCTOR void GwpsanInitCtor() {
  if (!GwpsanInit()) {
    SAN_LOG("failed to initialize");
    SAN_CHECK(!GetFlags().must_init);
    return;
  }
  SAN_LOG("started");
}
SAN_POP_DIAG();

auto* resolve_fork() {
  if (___interceptor_fork)
    return ___interceptor_fork;
  auto fn = reinterpret_cast<int (*)()>(dlsym(RTLD_NEXT, "fork"));
  if (fn)
    return fn;
  if (__fork)
    return __fork;
  SAN_BUG("dlsym(\"fork\") failed (%s)", dlerror());
}

}  // namespace

SAN_INTERFACE int __interceptor_fork() {
  static auto real_fork = resolve_fork();
  if (!unified || !GetFlags().sample_after_fork)
    return real_fork();

  SemanticMetadataScopedFork semantic_scoped_fork;

  BreakManager::CallbackDisableContext disable_ctx;
  BreakManager::singleton()->BeginFork(disable_ctx);

  const int pid = real_fork();

  BreakManager::singleton()->EndFork(pid, disable_ctx);
  unified->EndFork(pid);

  SAN_LOG("intercepted fork()=%d", pid);
  return pid;
}

// vfork() does not need to be intercepted, as stated in the man pages, what is
// allowed by the child after a vfork() is very limited:
//
//   "The vfork() function has the same effect as fork(2), except that the
//   behavior is undefined if the process created by vfork() either modifies any
//   data other than a variable of type pid_t used to store the return value
//   from vfork(), or returns from the function in which vfork() was called, or
//   calls any other function before successfully calling _exit(2) or one of the
//   exec(3) family of functions."
//
// Since the child "shares all memory with its parent, including the stack", it
// would be foolish to attempt to change any GWPSan state after a vfork().

}  // namespace gwpsan
