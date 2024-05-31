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

#include <limits>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/printf.h"

namespace gwpsan {
namespace {
using u64_limits = std::numeric_limits<u64>;
using s64_limits = std::numeric_limits<s64>;

TEST(Numeric, Atoi) {
  EXPECT_FALSE(Atoi(""));
  EXPECT_FALSE(Atoi(" "));
  EXPECT_FALSE(Atoi("-"));
  EXPECT_FALSE(Atoi("foo"));
  EXPECT_FALSE(Atoi("-123-42"));
  EXPECT_FALSE(Atoi("123-42"));
  EXPECT_FALSE(Atoi("12342-"));
  EXPECT_FALSE(Atoi("123x42"));
  EXPECT_EQ(*Atoi("0"), 0);
  EXPECT_EQ(*Atoi("-0"), 0);
  EXPECT_EQ(*Atoi("--42"), 42);
  EXPECT_EQ(*Atoi("---42"), -42);
  EXPECT_EQ(*Atoi("42\n"), 42);

  Rand rand;
  for (int i = 0; i < 1000; i++) {
    const s64 val = rand.Index(u64_limits::max()) - s64_limits::max();
    char buf[32];
    SPrintf(buf, sizeof(buf), "%s%lld%s", rand.OneOf(2) ? " " : "", val,
            rand.OneOf(2) ? " " : "");
    EXPECT_EQ(val, *Atoi(buf));
  }
}

}  // namespace
}  // namespace gwpsan
