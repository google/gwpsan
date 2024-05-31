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

#include "gwpsan/base/printf.h"

#include <string>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/span.h"

namespace gwpsan {
namespace {

TEST(Printf, Base) {
  std::string res;
  const auto printf_callback = [&](const Span<const char>& str) {
    res.append(str.data(), str.size());
  };
  SetPrintfCallback({printf_callback});
  Printf("Hello, %s!\n", "world");
  EXPECT_EQ(res, "Hello, world!\n");
  res.clear();
  Printf("aaa %5d bbb\n", -123);
  EXPECT_EQ(res, "aaa  -123 bbb\n");
  res.clear();
  Printf("%p\n", reinterpret_cast<void*>(0x12345));
  EXPECT_EQ(res, "0x000000012345\n");
  res.clear();
  Printf("%08X\n", 0x1A2B3C);
  EXPECT_EQ(res, "001A2B3C\n");
  res.clear();
  SetPrintfCallback({});
}

}  // namespace
}  // namespace gwpsan
