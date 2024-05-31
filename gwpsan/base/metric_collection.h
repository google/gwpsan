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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_METRIC_COLLECTION_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_METRIC_COLLECTION_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/metric.h"

SAN_DECLARE_SECTION_VARS(const gwpsan::MetricRef* const, gwpsan_metrics);

namespace gwpsan SAN_LOCAL {

using MetricCallback = FunctionRef<void(const MetricRef&)>;

// Iterates through all metrics created via the DEFINE_METRIC*() macros.
//
// ENSURES: stable iteration order
inline void CollectMetrics(MetricCallback callback) {
  for (const MetricRef* const* metric = __start_gwpsan_metrics;
       metric < __stop_gwpsan_metrics; ++metric) {
    callback(**metric);
  }
}

}  // namespace gwpsan SAN_LOCAL

extern "C" {
// These structs are part of the gwpsan ABI, and should be representable in C as
// well as by common foreign language FFIs.
struct gwpsan_metric_value {
  gwpsan::s64 value;
  const char* name;
};
struct gwpsan_metric {
  const char* name;
  const char* desc;
  gwpsan::uptr size;
  gwpsan_metric_value* values;
};

// Helper to collect gwpsan metrics for external code. This is required where
// external code wants to export gwpsan's metrics, but using CollectMetrics()
// directly does not work for a variety of reasons:
//
//  1. The external code is in a shared library - in that case, it would not see
//     gwpsan's metric section.
//
//  2. The external code cannot depend on "external_interface".
//
//  3. The external code is just C code or some other language FFI.
//
// If it's possible to use CollectMetrics(), prefer that since it avoids
// additional memory allocations.
SAN_INTERFACE void gwpsan_collect_metrics(void (*callback)(const gwpsan_metric*,
                                                           void*),
                                          void* arg);
}  // extern "C"

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_METRIC_COLLECTION_H_
