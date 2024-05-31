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

#include "gwpsan/base/algorithm.h"

#include <stdlib.h>

#include <algorithm>
#include <vector>

#include "gtest/gtest.h"

namespace {

using Sorting = testing::TestWithParam<std::vector<int>>;

TEST_P(Sorting, Test) {
  const auto& data = GetParam();
  EXPECT_EQ(std::is_sorted(data.begin(), data.end()),
            gwpsan::is_sorted(data.begin(), data.end()));
  auto sorted = data;
  gwpsan::sort(sorted.begin(), sorted.end());
  auto sorted2 = data;
  std::sort(sorted2.begin(), sorted2.end());
  EXPECT_EQ(sorted, sorted2);
  EXPECT_TRUE(gwpsan::is_sorted(sorted.begin(), sorted.end()));
  auto augmented = sorted;
  augmented.emplace_back(0);
  if (!sorted.empty()) {
    augmented.emplace_back(sorted.front() - 1);
    augmented.emplace_back(sorted.back() + 1);
  }
  for (int v : augmented) {
    auto it = gwpsan::upper_bound(sorted.begin(), sorted.end(), v);
    auto it2 = std::upper_bound(sorted.begin(), sorted.end(), v);
    EXPECT_EQ(it, it2);
  }
}

std::vector<std::vector<int>> SortingTestCases() {
  std::vector<std::vector<int>> cases = {
      {},
      {0, 1, 2, 3},
      {3, 2, 1, 0},
      {2, 2, 1, 0, 3},
  };
  unsigned seed = 0;
  for (int i = 0; i < 10; i++) {
    std::vector<int> data;
    for (int i = rand_r(&seed) % 20; i >= 0; i--)
      data.push_back(rand_r(&seed));
    cases.push_back(data);
  }
  return cases;
}

INSTANTIATE_TEST_SUITE_P(Sorting, Sorting,
                         testing::ValuesIn(SortingTestCases()));

}  // namespace
