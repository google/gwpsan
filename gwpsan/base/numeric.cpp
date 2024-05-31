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

#include "gwpsan/base/numeric.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"

namespace gwpsan {

uptr ReverseBitsVal(uptr val) {
  uptr res = 0;
  for (uptr i = 0; i < kWordBits; i++)
    res |= ((val & (1ul << i)) >> i) << (kWordBits - i - 1);
  return res;
}

Optional<s64> Atoi(const char* str) {
  const char* c = str;
  // Skip leading spaces.
  for (; *c == ' '; ++c) {}
  // Compute sign.
  s64 sign = 1;
  for (; *c == '-'; ++c)
    sign *= -1;
  if (!*c)
    return {};
  // Convert string to number.
  s64 num = 0;
  for (; *c >= '0' && *c <= '9'; ++c) {
    num *= 10;
    num += *c - '0';
  }
  // Should have consumed whole string; allow spaces after number.
  if (*c && *c != ' ' && *c != '\n')
    return {};
  return sign * num;
}

Rand::Rand()
    : state_(GetTid()) {}

u32 Rand::Next() {
  // Numbers from:
  // https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use
  // Note: we intentionally don't use compare_exchange.
  // compare_exchange would be slower and we don't need strong and secure
  // random numbers for our sampling choices.
  u32 state = __atomic_load_n(&state_, __ATOMIC_RELAXED);
  state = (state + 12345) * 1103515245;
  __atomic_store_n(&state_, state, __ATOMIC_RELAXED);
  return state;
}

bool Rand::OneOf(uptr n) {
  // Don't crash in production due to division by 0.
  if (SAN_WARN(n == 0))
    return false;
  return (Next() % n) == 0;
}

uptr Rand::Index(uptr n) {
  // Don't crash in production due to division by 0.
  if (SAN_WARN(n == 0))
    return 0;
  return Next() % n;
}

}  // namespace gwpsan
