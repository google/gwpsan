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

#include "gwpsan/base/vector.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gwpsan/base/common.h"

namespace gwpsan {
namespace {

template <typename VectorT>
void TestImpl() {
  VectorT v;
  ASSERT_TRUE(v.empty());
  ASSERT_EQ(v.size(), 0);
  ASSERT_EQ(v.begin(), v.end());
  for (uptr i = 0; i < 10; ++i) {
    v.emplace_back(static_cast<typename VectorT::value_type>(i + 1));
    ASSERT_FALSE(v.empty());
    ASSERT_EQ(v.size(), i + 1);
    ASSERT_LE(v.size(), v.capacity());
    ASSERT_EQ(v.end() - v.begin(), i + 1);
    ASSERT_EQ(v.front(), 1);
    ASSERT_EQ(v.back(), i + 1);
    for (uptr j = 0; j <= i; ++j) {
      ASSERT_EQ(v[j], j + 1);
      ASSERT_EQ(v.at(j), j + 1);
      ASSERT_EQ(v.begin()[j], j + 1);
    }
  }
  EXPECT_DEATH(v.at(10), testing::HasSubstr("CHECK: n < size_ (10 < 10)"));
  for (uptr i = 0; i < 10; ++i) {
    ASSERT_EQ(v.pop_back(), 10 - i);
    ASSERT_EQ(v.size(), 10 - i - 1);
  }
  v.resize(10, 55);
  ASSERT_EQ(v.size(), 10);
  for (uptr i = 0; i < 10; ++i) {
    ASSERT_EQ(v.at(i), 55);
  }
  v.resize(0);
  ASSERT_EQ(v.size(), 0);
}

TEST(Vector, Basic) {
  TestImpl<ArrayVector<uptr, 10>>();
  TestImpl<ArrayVector<char, 10>>();
  TestImpl<MallocVector<uptr>>();
}

TEST(Vector, Move) {
  MallocVector<uptr> v;
  v.resize(10, 55);
  void* orig_data = v.data();
  MallocVector<uptr> v2(move(v));
  ASSERT_EQ(v.data(), nullptr);
  ASSERT_EQ(v.size(), 0);
  ASSERT_EQ(v2.data(), orig_data);
  ASSERT_EQ(v2.size(), 10);
  for (uptr i = 0; i < 10; ++i)
    ASSERT_EQ(v2.at(i), 55);
  MallocVector<uptr> v3;
  v3 = move(v2);
  ASSERT_EQ(v2.data(), nullptr);
  ASSERT_EQ(v2.size(), 0);
  ASSERT_EQ(v3.data(), orig_data);
  ASSERT_EQ(v3.size(), 10);
  for (uptr i = 0; i < 10; ++i)
    ASSERT_EQ(v3.at(i), 55);
}

TEST(Vector, ArrayOverflow) {
  ArrayVector<char, 2> v;
  ASSERT_EQ(v.capacity(), 2);
  v.emplace_back(char{1});
  v.emplace_back(char{2});
  ASSERT_DEATH(v.emplace_back(char{3}),
               testing::HasSubstr("BUG: ArrayStorage grow"));
}

}  // namespace
}  // namespace gwpsan
