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

#include "gwpsan/base/memory.h"

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"

namespace gwpsan {
namespace {

class TestObject {
 public:
  TestObject(int& ref)
      : ref_(ref) {
    ref++;
  }
  ~TestObject() {
    ref_--;
  }

 private:
  int& ref_;
};

TEST(Memory, UniquePtrReset) {
  int ref = 0;
  auto obj = MakeUniqueFreelist<TestObject>(ref);
  EXPECT_EQ(ref, 1);
  obj.reset();
  EXPECT_EQ(ref, 0);
}

TEST(Memory, UniquePtrMove) {
  int ref1 = 0;
  int ref2 = 0;
  auto obj1 = MakeUniqueFreelist<TestObject>(ref1);
  auto obj2 = MakeUniqueFreelist<TestObject>(ref2);
  TestObject* ptr1 = obj1.get();
  TestObject* ptr2 = obj2.get();
  EXPECT_NE(ptr1, ptr2);
  EXPECT_EQ(ref1, 1);
  EXPECT_EQ(ref2, 1);

  // move
  obj2 = move(obj1);
  EXPECT_EQ(obj1.get(), nullptr);
  EXPECT_EQ(obj2.get(), ptr1);
  EXPECT_EQ(ref1, 1);
  EXPECT_EQ(ref2, 0);

  obj2 = {};
  EXPECT_EQ(obj2.get(), nullptr);
  EXPECT_EQ(ref1, 0);
}

}  // namespace
}  // namespace gwpsan
