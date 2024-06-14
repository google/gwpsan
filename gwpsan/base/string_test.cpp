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

#include "gwpsan/base/string.h"

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

TEST(String, MatchStr) {
  EXPECT_TRUE(MatchStr("", ""));
  EXPECT_TRUE(MatchStr("foobar", ""));
  EXPECT_TRUE(MatchStr("foobar", "ooba"));
  EXPECT_TRUE(MatchStr("foobar", "foo"));
  EXPECT_TRUE(MatchStr("foobar", "bar"));
  EXPECT_TRUE(MatchStr("foobar", "foobar"));
  EXPECT_FALSE(MatchStr("", "foobar"));
  EXPECT_FALSE(MatchStr("foobar", "foobarr"));
  EXPECT_FALSE(MatchStr("foobar", "xyc"));
  EXPECT_FALSE(MatchStr("foobar", "abcdefgh"));

  // Or
  EXPECT_TRUE(MatchStr("", "|"));
  EXPECT_TRUE(MatchStr("foobar", "|"));
  EXPECT_TRUE(MatchStr("foobar", "||"));
  EXPECT_TRUE(MatchStr("foobar", "x|y|z|foo"));
  EXPECT_TRUE(MatchStr("foobar", "abc|"));
  EXPECT_TRUE(MatchStr("foobar", "|abc"));
  EXPECT_TRUE(MatchStr("foobar", "ooba|xyc"));
  EXPECT_TRUE(MatchStr("foobar", "ooba|"));
  EXPECT_TRUE(MatchStr("foobar", "abc|foo"));
  EXPECT_TRUE(MatchStr("foobar", "foo|bar"));
  EXPECT_FALSE(MatchStr("foobar", "abc|xyz"));
  EXPECT_FALSE(MatchStr("foobar", "foobarr|abc"));
  EXPECT_FALSE(MatchStr("foobar", "x|y|z|0"));

  // Match beginning
  EXPECT_TRUE(MatchStr("", "^"));
  EXPECT_TRUE(MatchStr("foobar", "^"));
  EXPECT_TRUE(MatchStr("foobar", "^f"));
  EXPECT_TRUE(MatchStr("foobar", "^foo"));
  EXPECT_TRUE(MatchStr("foobar", "^foo|abc"));
  EXPECT_TRUE(MatchStr("foobar", "abc|^foo"));
  EXPECT_TRUE(MatchStr("foo^", "foo^"));  // literal char if not at beginning
  EXPECT_FALSE(MatchStr("foobar", "^ooba"));
  EXPECT_FALSE(MatchStr("foobar", "^foobarr"));

  // Match end
  EXPECT_TRUE(MatchStr("", "$"));
  EXPECT_TRUE(MatchStr("foobar", "$"));
  EXPECT_TRUE(MatchStr("foobar", "r$"));
  EXPECT_TRUE(MatchStr("foobar", "bar$"));
  EXPECT_TRUE(MatchStr("foobar", "bar$|abc"));
  EXPECT_TRUE(MatchStr("foobar", "abc|bar$"));
  EXPECT_TRUE(MatchStr("$foo", "$foo"));  // literal char if not at end
  EXPECT_FALSE(MatchStr("foobar", "ooba$"));
  EXPECT_FALSE(MatchStr("foobar", "foobarr$"));

  // Combined match beginning + end
  EXPECT_TRUE(MatchStr("", "^$"));
  EXPECT_TRUE(MatchStr("^", "^^$"));
  EXPECT_TRUE(MatchStr("$", "^$$"));
  EXPECT_TRUE(MatchStr("foobar", "^foobar$"));
  EXPECT_TRUE(MatchStr("foobar", "^foo|abc$"));
  EXPECT_TRUE(MatchStr("foobar", "abc|^foobar$"));
  EXPECT_TRUE(MatchStr("foobar", "^foobar$|abc"));
  EXPECT_FALSE(MatchStr("foobar", "^$"));
  EXPECT_FALSE(MatchStr("foobar", "^ooba$"));
}

TEST(String, Basename) {
  EXPECT_STREQ(Basename(""), "");
  EXPECT_STREQ(Basename("foobar"), "foobar");
  EXPECT_STREQ(Basename("foo/bar"), "bar");
  EXPECT_STREQ(Basename("/foobar"), "foobar");
  EXPECT_STREQ(Basename("/a/b/c/d/e/f"), "f");
}

}  // namespace
}  // namespace gwpsan
