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

#ifndef GWPSAN_CORE_KNOWN_FUNCTIONS_H_
#define GWPSAN_CORE_KNOWN_FUNCTIONS_H_

#include "gwpsan/base/common.h"
#include "gwpsan/core/core_fwd.h"

namespace gwpsan SAN_LOCAL {

// Returns true if the current PC points to the beginning of a malloc-like
// function (malloc, calloc, new, etc). Returns the requested object size
// in 'size'; 'uninit' is set if the returned memory is uninitialized.
bool IsMallocPC(const CPUContext& ctx, uptr& size, bool& uninit);

// Returns true if the current PC points to the beginning of a free-like
// function (free, delete, etc). Returns the freed pointer in 'ptr'.
// If size of the object is known, it's returned in 'size';
// otherwise 'size' is set to 0.
bool IsFreePC(const CPUContext& ctx, uptr& ptr, uptr& size);

// Returns true if the current PC points to the beginning of a mem/str*
// function (memset, strcmp, etc). 'cb' is called for each access
// by the function memory range.
bool IsMemAccessFunc(const CPUContext& ctx,
                     const FunctionRef<void(const MemAccess&)>& cb);
bool IsMemAccessFunc(uptr pc);

template <typename Vec>
bool IsMemAccessFunc(const CPUContext& ctx, Vec& accesses) {
  return IsMemAccessFunc(ctx, [&](const MemAccess& a) {
    if (SAN_WARN(accesses.size() >= accesses.capacity()))
      return;
    accesses.emplace_back(a);
  });
}

// Assuming ctx points to a syscall instruction, returns the syscall number
// (SYS_*) and calls cb for every memory access done by the syscall.
uptr ExtractSyscallAccesses(const CPUContext& ctx,
                            const FunctionRef<void(const MemAccess&)>& cb);

template <typename Vec>
uptr ExtractSyscallAccesses(const CPUContext& ctx, Vec& accesses) {
  return ExtractSyscallAccesses(ctx, [&](const MemAccess& a) {
    if (SAN_WARN(accesses.size() >= accesses.capacity()))
      return;
    accesses.emplace_back(a);
  });
}

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_CORE_KNOWN_FUNCTIONS_H_
