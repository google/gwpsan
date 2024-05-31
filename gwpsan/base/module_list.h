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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_MODULE_LIST_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_MODULE_LIST_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"

namespace gwpsan SAN_LOCAL {

struct ModuleInfo {
  const char* name;
  uptr start_address;
  uptr end_address;
  uptr pc_offset;  // what needs to be subtracted from PC to pass to addr2line
};

bool InitModuleList();
bool IsVDSO(uptr pc);

// Returns true if the address is part of the runtime which is loaded as a DSO.
// If no value can be returned, then the runtime is statically linked into the
// main binary.
Optional<bool> IsRuntimeInDSO(uptr pc_or_addr);

// Returns the main thread stack bounds.
// Note: the start address is conservative and is based on the end of
// the previous mapping (since the stack automatically grows down).
Optional<Pair<uptr, uptr>> GetStackBounds();
const ModuleInfo* FindModule(uptr pc);
void ForEachModule(FunctionRef<void(const ModuleInfo&)> cb);

namespace internal {

struct ModuleInfoNode : ModuleInfo {
  const ModuleInfoNode* next;
};

struct ModulesInfo {
  const ModuleInfoNode* list = nullptr;
  uptr stack_start = 0;
  uptr stack_end = 0;
  uptr vdso_start = 0;
  uptr vdso_end = 0;
  uptr own_start = 0;
  uptr own_end = 0;
};

ModulesInfo ParseModuleList(char* buffer, uptr own_addr, uptr main_addr);

}  // namespace internal
}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_MODULE_LIST_H_
