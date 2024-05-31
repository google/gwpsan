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

#include "gwpsan/core/regset.h"

#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/core/arch.h"

namespace gwpsan {
namespace {

std::vector<RegIdx> ToVec(const RegSet& set) {
  std::vector<RegIdx> res;
  for (auto reg : set)
    res.push_back(reg);
  return res;
}

TEST(RegSet, Basic) {
  RegSet set;
  EXPECT_FALSE(set);
  EXPECT_STREQ(&set.Dump(), "");
  EXPECT_EQ(ToVec(set), std::vector<RegIdx>());
  EXPECT_FALSE(set[kTEMP0]);

  set.AddRange(kTEMP0, kTEMP3);
  EXPECT_TRUE(set);
  EXPECT_STREQ(&set.Dump(), "TEMP0,TEMP1,TEMP2,TEMP3");
  EXPECT_EQ(ToVec(set), (std::vector<RegIdx>{kTEMP0, kTEMP1, kTEMP2, kTEMP3}));
  EXPECT_TRUE(set[kTEMP0]);
  EXPECT_TRUE(set[kTEMP1]);
  EXPECT_FALSE(set[kPC]);

  set.Remove(kTEMP1, kTEMP3);
  EXPECT_TRUE(set);
  EXPECT_STREQ(&set.Dump(), "TEMP0,TEMP2");
  EXPECT_EQ(ToVec(set), (std::vector<RegIdx>{kTEMP0, kTEMP2}));

  set.Remove(kTEMP0, kTEMP2);
  EXPECT_FALSE(set);
  EXPECT_STREQ(&set.Dump(), "");
  EXPECT_EQ(ToVec(set), std::vector<RegIdx>());
}

TEST(RegSet, NonEmpty) {
  RegSet set(kTEMP3, kTEMPFLAGS, kTEMP2);
  EXPECT_TRUE(set);
  EXPECT_STREQ(&set.Dump(), "TEMP2,TEMP3,TFLAGS");
  EXPECT_EQ(ToVec(set), (std::vector<RegIdx>{kTEMP2, kTEMP3, kTEMPFLAGS}));

  set |= RegSet(kTEMP2, kTEMP1);
  EXPECT_STREQ(&set.Dump(), "TEMP1,TEMP2,TEMP3,TFLAGS");
}

}  // namespace
}  // namespace gwpsan
