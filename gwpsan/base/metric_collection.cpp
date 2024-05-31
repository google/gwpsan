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

#include "gwpsan/base/metric_collection.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/vector.h"

namespace gwpsan {

SAN_INTERFACE void gwpsan_collect_metrics(void (*callback)(const gwpsan_metric*,
                                                           void*),
                                          void* arg) {
  MallocVector<gwpsan_metric_value> values;
  // Copy metric data and call caller callback for every metric.
  CollectMetrics([&](const MetricRef& metric) {
    // Keep reusing the same values buffer for as long as we can.
    if (metric.size() > values.size())
      values.resize(metric.size());
    for (uptr i = 0; i < metric.size(); ++i) {
      values[i].value = metric.value(i);
      values[i].name = metric.name(i);
    }
    const gwpsan_metric export_metric = {.name = metric.name(),
                                         .desc = metric.desc(),
                                         .size = metric.size(),
                                         .values = values.data()};
    callback(&export_metric, arg);
  });
}

}  // namespace gwpsan
