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

#include <string.h>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"

namespace gwpsan {
namespace {

TEST(String, Memset) {
  constexpr uptr kSize = 1024;
  char buf1[kSize + 2];
  char buf2[kSize + 2];
  for (uptr size = 0; size < kSize; size++) {
    memset(buf1, 1, sizeof(buf1));
    memset(buf2, 1, sizeof(buf2));
    internal_memset(buf1 + 1, 2, size);
    memset(buf2 + 1, 2, size);
    ASSERT_TRUE(!memcmp(buf1, buf2, sizeof(buf1)));
  }
}

TEST(String, Memcpy) {
  constexpr uptr kSize = 1024;
  char buf0[kSize + 2];
  char buf1[kSize + 2];
  char buf2[kSize + 2];
  for (uptr i = 0; i < sizeof(buf0); i++)
    buf0[i] = i + 42;
  for (uptr size = 0; size < kSize; size++) {
    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));
    internal_memcpy(buf1 + 1, buf0, size);
    memcpy(buf2 + 1, buf0, size);
    ASSERT_TRUE(!memcmp(buf1, buf2, sizeof(buf1)));
  }
}

}  // namespace
}  // namespace gwpsan
