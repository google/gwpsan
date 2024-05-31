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

#include <chrono>

#include "gtest/gtest.h"
#include "gwpsan/base/metric.h"

namespace gwpsan {

DECLARE_METRIC(timer_samples);
DECLARE_METRIC(gwpsan_tools);

namespace {

// Simple test that checks that if no tool is enabled we don't crash; also try
// to receive some signals by waiting a bit.
TEST(UnifiedTool, NoToolEnabled) {
  ASSERT_EQ(metric_gwpsan_tools.value(), 0);
  using std::chrono::high_resolution_clock;
  const auto start = high_resolution_clock::now();
  while (metric_timer_samples.value() < 2 &&
         high_resolution_clock::now() - start < std::chrono::seconds(10)) {}
  EXPECT_GE(metric_timer_samples.value(), 2);
}

}  // namespace
}  // namespace gwpsan
