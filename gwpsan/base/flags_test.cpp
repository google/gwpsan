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

#include "gwpsan/base/flags.h"

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"

namespace gwpsan {
namespace {

TEST(Flags, Empty) {
  bool bf = true;
  const FlagDesc flags[] = {
      {&bf, "bf", "bf"},
  };
  char str[] = "";
  ASSERT_TRUE(ParseFlagsFromStr(str, flags));
  EXPECT_EQ(bf, true);
}

TEST(Flags, Bad) {
  {
    char str[] = "unknown=0";
    ASSERT_FALSE(ParseFlagsFromStr(str, {}));
  }
  {
    bool bf = true;
    const FlagDesc flags[] = {
        {&bf, "bf", "bf"},
    };
    char str[] = "bf=foo";
    ASSERT_FALSE(ParseFlagsFromStr(str, flags));
  }
  {
    uptr uf = 0;
    const FlagDesc flags[] = {
        {&uf, "uf", "uf"},
    };
    char str[] = "uf=foo";
    ASSERT_FALSE(ParseFlagsFromStr(str, flags));
  }
  {
    uptr intf = 0;
    const FlagDesc flags[] = {
        {&intf, "intf", "intf"},
    };
    char str[] = "intf=foo";
    ASSERT_FALSE(ParseFlagsFromStr(str, flags));
  }
  {
    uptr uf = 0;
    const FlagDesc flags[] = {
        {&uf, "uf", "uf"},
    };
    char str[] = "uf";
    ASSERT_FALSE(ParseFlagsFromStr(str, flags));
  }
  {
    int intf = 0;
    const FlagDesc flags[] = {
        {&intf, "intf", "intf"},
    };
    char str[] = "intf";
    ASSERT_FALSE(ParseFlagsFromStr(str, flags));
  }
}

TEST(Flags, Good) {
  bool bf0 = true, bf1 = true, bf2 = false, bf3 = false, bf4 = false,
       bf5 = false, bf6 = true;
  uptr uf0 = 0;
  int if0 = 0, if1 = 0;
  const char *sf0 = nullptr, *sf1 = nullptr, *sf2 = nullptr, *sf3 = nullptr,
             *sf4 = nullptr;
  const FlagDesc flags[] = {
      {&bf0, "bf0", "bf0"},
      {&bf1, "bf1", "bf1"},
      {&bf2, "bf2", "bf2"},
      {&bf3, "bf3", "bf3"},
      {&bf4, "bf4", "bf4"},
      {&bf5, "bf5", "bf5"},
      {&bf6, "bf6", "bf6"},
      {&uf0, "uf0", "uf0"},
      {&if0, "if0", "if0"},
      {&if1, "if1", "if1"},
      {&sf0, "sf0", "sf0"},
      {&sf1, "sf1", "sf1"},
      {&sf2, "sf2", "sf2"},
      {&sf3, "sf3", "sf3"},
      {&sf4, "sf4", "sf4"},
  };
  char str[] =
      "bf0=0:bf1=false:bf2=1:bf3=true:bf4:uf0=123:if0=42:if1=-22:sf0:sf1=:sf2="
      "foo:sf3=bar";
  ASSERT_TRUE(ParseFlagsFromStr(str, flags));
  EXPECT_EQ(bf0, false);
  EXPECT_EQ(bf1, false);
  EXPECT_EQ(bf2, true);
  EXPECT_EQ(bf3, true);
  EXPECT_EQ(bf4, true);
  EXPECT_EQ(bf5, false);
  EXPECT_EQ(bf6, true);
  EXPECT_EQ(uf0, 123);
  EXPECT_EQ(if0, 42);
  EXPECT_EQ(if1, -22);
  EXPECT_STREQ(sf0, "");
  EXPECT_STREQ(sf1, "");
  EXPECT_STREQ(sf2, "foo");
  EXPECT_STREQ(sf3, "bar");
  EXPECT_EQ(sf4, nullptr);
}

}  // namespace
}  // namespace gwpsan
