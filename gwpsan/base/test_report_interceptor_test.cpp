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

#include "gwpsan/base/test_report_interceptor.h"

#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"

namespace gwpsan {
namespace {

struct TestData {
  const char* re;
  const char* output;
};

using ReportInterceptorTest = testing::TestWithParam<TestData>;

TEST_P(ReportInterceptorTest, Test) {
  ReportInterceptor interceptor;
  // Print char-by-char to work-around Printf buffer size limit.
  for (const char* pos = GetParam().output; *pos; pos++)
    Printf("%c", *pos);
  interceptor.ExpectReport(GetParam().re);
  Printf("\n");
}

INSTANTIATE_TEST_SUITE_P(
    Test, ReportInterceptorTest,
    testing::ValuesIn(std::vector<TestData>{
  // clang-format off
{"[[MODULE]] A", "(3363dae9_020007+0x137) ./gwp_sanitizers/base/printf.h:42 A"},
{"[[MODULE]] A", "(3363dae9_020007+0x137) /bin/../include/c++/v1/__functional/invoke.h:394 A"},
  // clang-format on
}));

}  // namespace
}  // namespace gwpsan
