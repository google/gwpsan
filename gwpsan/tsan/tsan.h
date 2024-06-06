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

#ifndef GWPSAN_TSAN_TSAN_H_
#define GWPSAN_TSAN_TSAN_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/numeric.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/unified/tool.h"

namespace gwpsan SAN_LOCAL {

class RaceDetector final : public Tool {
 public:
  RaceDetector(bool& ok);

 private:
  bool IsInteresting(const CPUContext& ctx, const MemAccess& access) override;
  bool Check(const CPUContext& ctx, const MemAccess& access) override;
  void OnRace(const CPUContext& ctx);
  static void PrintThread(const MemAccess& ma, int tid,
                          const Span<const uptr>& stack_trace);

  Rand rand_;
  uptr last_interesting_pc_ = 0;
  Addr last_interesting_addr_;
  Breakpoint* watched_ = nullptr;  // guarded by mgr().mtx_
  MemAccess sel_access_;           // guarded by mgr().mtx_
  MemAccess bp_access_;            // guarded by mgr().mtx_
  ArrayVector<uptr, 64> sel_stack_trace_;
  ArrayVector<uptr, 64> bp_stack_trace_;
  int bp_tid_ = -1;
};

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_TSAN_TSAN_H_
