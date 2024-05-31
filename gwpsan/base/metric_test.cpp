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

#include "gwpsan/base/metric.h"

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/metric_collection.h"

namespace gwpsan {
namespace {

const char* IndexName(uptr idx) {
  return "test";
}

TEST(Metric, Ops) {
  Metric<1> metric(Metric<1>::InternalToken{}, "test_name", "description", -42);
  EXPECT_EQ(metric.name(), "test_name");
  EXPECT_EQ(metric.desc(), "description");
  EXPECT_EQ(metric.value(), -42);
  metric.Add(42);
  EXPECT_EQ(metric.value(), 0);
  metric.ExclusiveAdd(1);
  EXPECT_EQ(metric.value(), 1);
  metric.LossyAdd(1);
  EXPECT_EQ(metric.value(), 2);
  metric.Set(100);
  EXPECT_EQ(metric.value(), 100);
  EXPECT_EQ(metric.Sum(), 100);
}

TEST(Metric, ArrayOps) {
  Metric<3> metric(Metric<3>::InternalToken{}, "test_name", "description",
                   IndexName);
  EXPECT_EQ(metric.name(), "test_name");
  EXPECT_EQ(metric.desc(), "description");
  for (uptr i = 0; i < metric.size(); ++i) {
    EXPECT_EQ(metric.name(i), "test");
    EXPECT_EQ(metric.value(i), 0);
    metric.Add(i, 42);
    EXPECT_EQ(metric.value(i), 42);
    metric.ExclusiveAdd(i, 1);
    EXPECT_EQ(metric.value(i), 43);
    metric.LossyAdd(i, 1);
    EXPECT_EQ(metric.value(i), 44);
    metric.Set(i, 100);
    EXPECT_EQ(metric.value(i), 100);
  }
  EXPECT_EQ(metric.Sum(), 300);
}

DEFINE_METRIC(test1, 123, "desc1");
DEFINE_METRIC(test2, 231, "desc2");
DEFINE_METRIC_ARRAY(10, test3, "desc3", IndexName);

TEST(Metric, CollectMetrics) {
  int found = 0;
  CollectMetrics([&](const MetricRef& metric) {
    if (&metric == &metric_test1) {
      found += 1;
      EXPECT_EQ(metric.name(), "test1");
      EXPECT_EQ(metric.desc(), __FILE_NAME__ ": desc1");
      EXPECT_EQ(metric.value(0), 123);
    }
    if (&metric == &metric_test2) {
      found += 10;
      EXPECT_EQ(metric.name(), "test2");
      EXPECT_EQ(metric.desc(), __FILE_NAME__ ": desc2");
      EXPECT_EQ(metric.value(0), 231);
    }
    if (&metric == &metric_test3) {
      found += 100;
      EXPECT_EQ(metric.name(), "test3");
      EXPECT_EQ(metric.desc(), __FILE_NAME__ ": desc3");
      EXPECT_EQ(metric.size(), 10);
      for (uptr i = 0; i < metric.size(); ++i)
        EXPECT_EQ(metric.value(i), 0);
    }
  });
  EXPECT_EQ(found, 111);
}

// Check that gwpsan_collect_metrics copies metrics as expected.
TEST(Metric, gwpsan_collect_metrics) {
  int outer_idx = 0;
  gwpsan_collect_metrics(
      +[](const gwpsan_metric* outer_metric, void* arg) {
        int* outer_idx = reinterpret_cast<int*>(arg);
        int inner_idx = *outer_idx;
        CollectMetrics([&](const MetricRef& inner_metric) {
          if (inner_idx-- != 0)
            return;
          EXPECT_EQ(outer_metric->name, inner_metric.name());
          EXPECT_EQ(outer_metric->desc, inner_metric.desc());
          EXPECT_EQ(outer_metric->size, inner_metric.size());
          for (int i = 0; i < inner_metric.size(); ++i) {
            EXPECT_EQ(outer_metric->values[i].value, inner_metric.value(i));
            EXPECT_EQ(outer_metric->values[i].name, inner_metric.name(i));
          }
        });
        (*outer_idx)++;
      },
      &outer_idx);
}

// Test remaining macros.
DECLARE_METRIC(test1);
DECLARE_METRIC_ARRAY(10, test3);

}  // namespace
}  // namespace gwpsan
