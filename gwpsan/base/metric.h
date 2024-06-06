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

#ifndef GWPSAN_BASE_METRIC_H_
#define GWPSAN_BASE_METRIC_H_

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/span.h"

namespace gwpsan SAN_LOCAL {

// Metric counter reference. Thread-safety: thread-safe (with exceptions).
//
// The reference class is required to store template-type independent references
// in the list-of-metrics section.
class MetricRef {
 public:
  using IndexNameFunc = const char* (*)(uptr idx);

  struct InternalToken {};  // Do construct directly; use provided macros.
  explicit constexpr MetricRef(InternalToken, const char* name,
                               const char* desc, const Span<s64>& values,
                               IndexNameFunc index_name)
      : name_(name)
      , desc_(desc)
      , values_(values)
      , index_name_(index_name) {}

  // Set counter value to `val`. Thread-safe.
  void Set(uptr idx, s64 val) {
    __atomic_store_n(&values_.at(idx), val, __ATOMIC_RELAXED);
  }

  // Add `val` to counter value. Thread-safe.
  void Add(uptr idx, s64 val) {
    __atomic_fetch_add(&values_.at(idx), val, __ATOMIC_RELAXED);
  }

  // Add `val` to counter value, but addition is not guaranteed with concurrent
  // additions. Thread-safe.
  void LossyAdd(uptr idx, s64 val) {
    Set(idx, value(idx) + val);
  }

  // Add `val` to counter value, assume we have exclusive access with no
  // concurrent accesses. Not thread-safe.
  void ExclusiveAdd(uptr idx, s64 val) {
    values_.at(idx) += val;
  }

  const char* name() const {
    return name_;
  }

  const char* name(uptr idx) const {
    SAN_CHECK_LT(idx, values_.size());
    return index_name_(idx);
  }

  const char* desc() const {
    return desc_;
  }

  s64 value(uptr idx) const {
    return __atomic_load_n(&values_.at(idx), __ATOMIC_RELAXED);
  }

  uptr size() const {
    return values_.size();
  }

  s64 Sum() const {
    s64 sum = 0;
    for (s64 v : values_)
      sum += v;
    return sum;
  }

 private:
  const char* const name_;
  const char* const desc_;
  const Span<s64> values_;
  const IndexNameFunc index_name_;

  MetricRef(const MetricRef&) = delete;
  MetricRef& operator=(const MetricRef&) = delete;
};

// Metric counter array. See MetricRef.
template <uptr kNumCounters>
class Metric : public MetricRef {
  static_assert(kNumCounters > 0, "Must have at least 1 counter");

 public:
  explicit constexpr Metric(InternalToken, const char* name, const char* desc,
                            IndexNameFunc index_name)
      : MetricRef(InternalToken{}, name, desc, storage_, index_name) {}

 private:
  Array<s64, kNumCounters> storage_ = {};

  Metric(const Metric&) = delete;
  Metric& operator=(const Metric&) = delete;
};

// Single metric counter.
template <>
class Metric<1> : public MetricRef {
 public:
  explicit constexpr Metric(InternalToken, const char* name, const char* desc,
                            s64 start_val)
      : MetricRef(InternalToken{}, name, desc, {&storage_, 1}, IndexName)
      , storage_(start_val) {}

  void Set(s64 val) {
    MetricRef::Set(0, val);
  }
  void Add(s64 val) {
    MetricRef::Add(0, val);
  }
  void LossyAdd(s64 val) {
    MetricRef::LossyAdd(0, val);
  }
  void ExclusiveAdd(s64 val) {
    MetricRef::ExclusiveAdd(0, val);
  }
  s64 value() const {
    return MetricRef::value(0);
  }

 private:
  s64 storage_;

  static const char* IndexName(uptr idx) {
    return "-";
  }

  Metric(const Metric&) = delete;
  Metric& operator=(const Metric&) = delete;
};

#define DEFINE_METRIC(name, start_val, desc)                                   \
  constinit Metric<1> metric_##name(Metric<1>::InternalToken{}, #name,         \
                                    __FILE_NAME__ ": " desc, start_val);       \
  static MetricRef* metric_##name##_ptr SAN_SECTION(gwpsan_metrics) SAN_USED = \
      &metric_##name
#define DECLARE_METRIC(name) extern Metric<1> metric_##name

#define DEFINE_METRIC_ARRAY(num_counters, name, desc, index_name)              \
  constinit Metric<num_counters> metric_##name(                                \
      Metric<num_counters>::InternalToken{}, #name, __FILE_NAME__ ": " desc,   \
      index_name);                                                             \
  static MetricRef* metric_##name##_ptr SAN_SECTION(gwpsan_metrics) SAN_USED = \
      &metric_##name
#define DECLARE_METRIC_ARRAY(num_counters, name) \
  extern Metric<num_counters> metric_##name

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_METRIC_H_
