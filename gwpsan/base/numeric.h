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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_NUMERIC_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_NUMERIC_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"

namespace gwpsan SAN_LOCAL {

uptr ReverseBitsVal(uptr val);

// Convert string to integer.
Optional<s64> Atoi(const char* str);

// A simple thread-safe pseudo-random generator.
class Rand {
 public:
  Rand();

  // Returns true in 1 out of n calls on average.
  // REQUIRES: n != 0
  bool OneOf(uptr n);

  // Returns a random number in the range [0, n).
  // REQUIRES: n != 0
  uptr Index(uptr n);

 private:
  u32 state_;

  u32 Next();
};

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_NUMERIC_H_
