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

#include "gwpsan/core/report.h"

#include "gwpsan/base/bazel.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/unwind.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/known_functions.h"
#include "gwpsan/core/semantic_metadata.h"

namespace gwpsan {

DEFINE_METRIC(errors_detected, 0, "Total number of errors detected");

namespace {
inline constexpr char kReportMarker[] =
    "=================================================================\n";
}  // namespace

ReportPrinter::ReportPrinter(const char* type, MetricRef& metric,
                             const ucontext_t* uctx, uptr pc2)
    : uctx_(uctx) {
  metric_errors_detected.ExclusiveAdd(1);
  metric.ExclusiveAdd(0, 1);
  LogBuf summary;
  summary.Append("GWPSan: %s in ", type);
  if (uctx_)
    Symbolize(ExtractPC(*uctx_), summary.Remain().data(),
              summary.Remain().size(), false);
  if (pc2 && summary.Remain().size() > 8) {
    summary.Append(" / ");
    Symbolize(pc2, summary.Remain().data(), summary.Remain().size(), false);
  }
  BazelOnReport(&summary);
  Printf(kReportMarker);
  Printf("WARNING: %s (pid=%d)\n", &summary, GetPid());
}

ReportPrinter::~ReportPrinter() {
  Printf(kReportMarker);
  if (GetFlags().halt_on_error)
    Die();
}

void ReportPrinter::CurrentStack() {
  static OptionalBase<ArrayVector<uptr, 64>> stack;
  stack.emplace();
  UnwindStack(*stack, uctx_);
  PrintStackTrace(*stack, "    ");
}

uptr UnwindStackSpan(Span<uptr> storage, const ucontext_t* uctx) {
  SAN_CHECK(uctx);
  SAN_CHECK_GT(storage.size(), 2);
  uptr offset = 1;
  uptr pc = ExtractPC(*uctx);
  storage[0] = pc;
  // If we are on the first function PC, then we also need to add the caller PC
  // since the frame pointer does not yet point to it (it will be updated only
  // within next few instructions).
  // Note: we are not interested in all functions, only in the ones that we
  // check and that may appear in reports. Currently it's only UAR-checked
  // functions and memory access functions.
  if (IsFunctionStart(pc) || IsMemAccessFunc(pc))
    storage[offset++] = ReturnPC(*uctx);
  return offset + RawUnwindStack({&storage[offset], storage.size() - offset},
                                 reinterpret_cast<void*>(ExtractFP(*uctx)));
}

}  // namespace gwpsan
