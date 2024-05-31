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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_REPORT_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_REPORT_H_

#include <signal.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/vector.h"

namespace gwpsan SAN_LOCAL {

class ReportPrinter {
 public:
  ReportPrinter(const char* type, MetricRef& metric,
                const ucontext_t* uctx = nullptr, uptr pc2 = 0);
  ~ReportPrinter();
  void CurrentStack();

 private:
  const ucontext_t* uctx_;
  ReportPrinter(const ReportPrinter&) = delete;
  ReportPrinter& operator=(const ReportPrinter&) = delete;
};

// Unwinds the current user stack for the signal context ``uctx``.
// The stack is stored in the ``storage`` and the actual stack size is returned.
[[nodiscard]] uptr UnwindStackSpan(Span<uptr> storage, const ucontext_t* uctx);

template <typename Storage>
SAN_ALWAYS_INLINE void UnwindStack(Vector<Storage>& vec,
                                   const ucontext_t* uctx) {
  vec.resize(vec.capacity());
  vec.resize(UnwindStackSpan(vec, uctx));
}

}  // namespace gwpsan SAN_LOCAL

#endif
