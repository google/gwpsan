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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_SEMANTIC_METADATA_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_SEMANTIC_METADATA_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"

namespace gwpsan SAN_LOCAL {

using SemanticFlags = u32;

// Instruction was lowered from an atomic operation per C11/C++11 memory model.
inline constexpr SemanticFlags kSemanticAtomic = (1u << 0);

// Function is suitable for use-after-return checking.
inline constexpr SemanticFlags kSemanticUAR = (1u << 1);

inline constexpr SemanticFlags kSemanticAll = ~0;

// Prepares ``needed`` features for use.
// Must be called before any other semantic metadata functions.
bool InitSemanticMetadata(SemanticFlags needed);

// Return true if we have compiler-provided semantic metadata of all types
// specified in the ``mask``.
bool HasSemanticMetadata(SemanticFlags mask);

// Says if the pc is a start of a function (for which we have any metadata,
// which guarantees it's compiled by clang and is reasonably well-behaving).
bool IsFunctionStart(uptr pc);

// If the function is not covered with the semantic metadata,
// or if the metadata is not ready to be used, returns nothing.
// Otherwise return if the instruction at ``pc`` is atomic.
Optional<bool> IsAtomicPC(uptr pc);

// Returns the size of stack arguments of the function if ``pc`` is a start of a
// function suitable for use-after-return checking.
Optional<uptr> IsUARFunctionStart(uptr pc);

// Print detailed metadata info.
void DumpSemanticMetadata();

// To be initialized before fork().
class SemanticMetadataScopedFork {
 public:
  SemanticMetadataScopedFork();
  ~SemanticMetadataScopedFork();
};

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_CORE_SEMANTIC_METADATA_H_
