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

#include "gwpsan/base/common.h"

#include "gtest/gtest.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/syscall.h"

namespace gwpsan {
namespace {

int WithFunctionRef(FunctionRef<int()> fun) {
  return fun();
}

int Return42() {
  return 42;
}

TEST(Common, FunctionRef) {
  EXPECT_EQ(WithFunctionRef([] { return 123; }), 123);
  // Function pointer template type deduction works.
  EXPECT_EQ(FunctionRef(Return42)(), 42);
  // Test capturing lambda
  bool called = false;
  EXPECT_EQ(WithFunctionRef([&] {
              called = true;
              return 123;
            }),
            123);
  EXPECT_TRUE(called);
  // Test copy constructor.
  FunctionRef funref1(Return42);
  auto funref2 = funref1;
  EXPECT_EQ(funref1(), 42);
  EXPECT_EQ(funref2(), 42);
  auto funref3 = move(funref1);
  EXPECT_EQ(funref3(), 42);
}

TEST(Common, CleanupRef) {
  bool called = false;
  auto set_called = [&] { called = true; };
  {
    EXPECT_FALSE(called);
    CleanupRef cleanup(set_called);
    EXPECT_FALSE(called);
  }
  EXPECT_TRUE(called);
}

TEST(Common, Warn) {
#define SAN_INVALID_FD -1
  EXPECT_DEATH(({
                 if (SAN_WARN(!sys_close(SAN_INVALID_FD)) && !GWPSAN_DEBUG)
                   Die();
               }),
               "T[0-9]+ common_test.cpp:[0-9]+: WARN: "
               "\\(!sys_close\\(SAN_INVALID_FD\\)\\)");
  EXPECT_DEATH(
      ({
        if (SAN_WARN_IF_ERR(sys_close(SAN_INVALID_FD)) && !GWPSAN_DEBUG)
          Die();
      }),
      "T[0-9]+ common_test.cpp:[0-9]+: WARN: "
      "sys_close\\(SAN_INVALID_FD\\) failed \\(errno=9\\)");
  EXPECT_DEATH(
      ({
        if (SAN_WARN_IF_ERR(sys_close(SAN_INVALID_FD), "more info: %d", 1) &&
            !GWPSAN_DEBUG)
          Die();
      }),
      "T[0-9]+ common_test.cpp:[0-9]+: WARN: "
      "sys_close\\(SAN_INVALID_FD\\) failed \\(errno=9\\) more info: 1");

  EXPECT_DEATH(({ SAN_CHECK(SAN_INVALID_FD != -1, "more info %d", 1); }),
               "T[0-9]+ common_test.cpp:[0-9]+: CHECK: SAN_INVALID_FD != -1 "
               "\\(false\\) more info 1 in");
  EXPECT_DEATH(({ SAN_CHECK_NE(SAN_INVALID_FD, -1); }),
               "T[0-9]+ common_test.cpp:[0-9]+: CHECK: SAN_INVALID_FD != -1 "
               "\\(-1 != -1\\)");
  if (GWPSAN_DEBUG) {
    EXPECT_DEATH(({ SAN_DCHECK(SAN_INVALID_FD != -1, "more info %d", 1); }),
                 "T[0-9]+ common_test.cpp:[0-9]+: CHECK: SAN_INVALID_FD != -1 "
                 "\\(false\\) more info 1 in");
    EXPECT_DEATH(({ SAN_DCHECK_NE(SAN_INVALID_FD, -1); }),
                 "T[0-9]+ common_test.cpp:[0-9]+: CHECK: SAN_INVALID_FD != -1 "
                 "\\(-1 != -1\\)");
  }
#undef SAN_INVALID_FD
}

}  // namespace
}  // namespace gwpsan
