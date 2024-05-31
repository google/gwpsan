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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_WEAK_IMPORTS_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_WEAK_IMPORTS_H_

#include "absl/base/config.h"
#include "gwpsan/base/common.h"

// Declare absl functions manually as weak because we don't want to depend on
// nor link in absl library. We use them only if they are linked otherwise.
namespace absl {
ABSL_NAMESPACE_BEGIN
SAN_WEAK_IMPORT bool Symbolize(const void* pc, char* out, int out_size);
ABSL_NAMESPACE_END
}  // namespace absl

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_WEAK_IMPORTS_H_
