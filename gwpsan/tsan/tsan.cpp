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

#include "gwpsan/tsan/tsan.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/sanitizer.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/report.h"
#include "gwpsan/core/semantic_metadata.h"
#include "gwpsan/unified/tool.h"

namespace gwpsan {

DEFINE_METRIC(tsan_stall_samples, 0, "Samples on stallable memory access");
DEFINE_METRIC(tsan_init_ok, 0, "Initialization succeeded");
DEFINE_METRIC(tsan_init_fail, 0, "Initialization failed");
DEFINE_METRIC(tsan_data_races, 0, "Detected data races");

constinit const ToolDesc kTsanTool = {
    .name = "tsan",
    .enabled = &Flags::tsan,
    .init_ok = metric_tsan_init_ok,
    .init_fail = metric_tsan_init_fail,
    .semantic_flags = kSemanticAtomic,
    .config =
        BreakManager::Config{
                             .mode = Breakpoint::kModeEnableKernel,
                             .max_breakpoints = 1,
                             },
    .make_unique = TryMakeUniqueGlobal<RaceDetector, Tool>,
};

SAN_WEAK_DEFAULT bool TestOnDataRace(const MemAccess& ma1,
                                     const MemAccess& ma2);

RaceDetector::RaceDetector(bool& ok)
    : Tool(kTsanTool.name) {}

bool RaceDetector::IsInteresting(const CPUContext& ctx,
                                 const MemAccess& access) {
  // TODO(elver, dvyukov): Figure out how we can catch races between 2 mem/str*
  // functions. We can catch a race between mem/str* and a normal instrumented
  // access if we observe entry to mem/str* and infer the access is non-atomic.
  // However, we can't catch a race between two mem/str* functions because
  // on a watchpoint we will land in the middle of mem/str* function and
  // won't be able to infer that it's doing a non-atomic access.
  // But note that some mem/str* functions (memchr/strchr/strlen)
  // do intentional out-of-bounds accesses, so we generally can't use raw
  // accesses done by these functions.

  // Skip some accesses starting with cheaper checks.

  // Skip local stack accesses because these are massively caused
  // by CALL/RET/PUSH/POP and spills, and stack accesses are less likely
  // to race overall. We still can catch races on stack if the first access
  // is done by remote thread.
  const uptr addr = Bytes(access.addr);
  const uptr sp = ctx.reg(kSP).val;
  constexpr uptr kSkipStackRange = 1024;
  if (addr > sp - kSkipStackRange && addr < sp + kSkipStackRange) {
    SAN_LOG("skipping local stack access");
    return false;
  }
  if (IsSanitizerShadow(addr)) {
    SAN_LOG("skipping sanitizer shadow access");
    return false;
  }
  auto is_atomic = access.is_atomic;
  if (!is_atomic)
    is_atomic = IsAtomicPC(access.pc);
  if (!is_atomic) {
    SAN_LOG("not covered with atomic metadata");
    return false;
  }
  if (!GetFlags().tsan_report_atomic_races && is_atomic.value()) {
    SAN_LOG("skipping atomic access");
    return false;
  }
  if (watched_ && ((!sel_access_.is_write && !access.is_write) ||
                   !DoRangesIntersect(sel_access_.addr, sel_access_.size,
                                      access.addr, access.size))) {
    // This can happen episodically in the following situation.
    // Unified tool OnEmulate loop in one thread returns non-0 next_pc,
    // break manager sets restraint, unlocks the mutex and lets another
    // timer emulate run in another thread, it sets a tsan watchpoint,
    // then the first thread continues emulation when next_pc restraint fires,
    // and we get a completely unrelated memory access here.
    SAN_LOG("non-conflicting accesses");
    return false;
  }

  // Skip some accesses because (1) for instructions that do more than one
  // access we want to be able to check all of them and (2) tsan checking
  // is expensive and can be applied frequently.
  // However, if we got a watchpoint (second racing access), or claimed that
  // this access is interesting during emulation, we should not skip.
  uptr pc = ctx.reg(kPC).val;
  if (!watched_ &&
      (pc != last_interesting_pc_ || access.addr != last_interesting_addr_) &&
      !rand_.OneOf(GetFlags().tsan_skip_watch + 1))
    return false;
  last_interesting_pc_ = pc;
  last_interesting_addr_ = access.addr;
  return true;
}

bool RaceDetector::Check(const CPUContext& ctx, const MemAccess& access)
    SAN_NO_THREAD_SAFETY_ANALYSIS {
  auto is_atomic = access.is_atomic;
  if (!is_atomic)
    is_atomic = IsAtomicPC(access.pc);
  // We already checked this in IsInteresting, but it still can fail
  // if the semantic metadata mutex TryLock fails.
  if (!is_atomic)
    return false;
  if (!watched_) {
    //
    // 1. This thread will stall the memory access, and watch for racy accesses.
    //
    sel_access_ = access;
    sel_access_.is_atomic = is_atomic;
    // Breakpoints want to be aligned; find aligned overlapping range.
    uptr aligned_size = sizeof(u64);
    for (; aligned_size > Bytes(sel_access_.size) ||
           !IsAligned(Bytes(sel_access_.addr), aligned_size);
         aligned_size >>= 1) {}
    const Breakpoint::Info bpinfo = {sel_access_.is_write
                                         ? Breakpoint::Type::kReadWrite
                                         : Breakpoint::Type::kWriteOnly,
                                     sel_access_.addr, ByteSize(aligned_size)};
    watched_ = mgr().Watch(bpinfo);
    if (SAN_WARN(!watched_))
      return false;

    bp_access_ = {};

    metric_tsan_stall_samples.ExclusiveAdd(1);
    SAN_LOG("stalling memory access");
    mgr().CallbackUnlock();
    Sleep(Microseconds(GetFlags().tsan_delay_usec));
    mgr().CallbackLock();

    mgr().Unwatch(watched_);
    watched_ = nullptr;
    if (bp_access_.addr != 0)
      OnRace(ctx);
    return true;
  } else {
    //
    // 2. A breakpoint fired in this thread and we detected a race.
    //
    bp_tid_ = GetTid();
    bp_access_ = access;
    bp_access_.is_atomic = is_atomic;
    UnwindStack(bp_stack_trace_, ctx.uctx());
    return false;
  }
}

void RaceDetector::OnRace(const CPUContext& ctx) {
  if (SAN_WARN(!DoRangesIntersect(sel_access_.addr, sel_access_.size,
                                  bp_access_.addr, bp_access_.size)))
    return;

  if (*sel_access_.is_atomic && *bp_access_.is_atomic) {
    SAN_LOG("detected a race between atomic operations");
    return;
  }

  SAN_LOG("detected a data race!");
  if (TestOnDataRace && TestOnDataRace(sel_access_, bp_access_))
    return;

  ReportPrinter printer("data-race", metric_tsan_data_races, ctx.uctx(),
                        bp_access_.pc);
  UnwindStack(sel_stack_trace_, ctx.uctx());
  PrintThread(sel_access_, GetTid(), sel_stack_trace_);
  Printf("\n");
  PrintThread(bp_access_, bp_tid_, bp_stack_trace_);
}

void RaceDetector::PrintThread(const MemAccess& ma, int tid,
                               const Span<const uptr>& stack_trace) {
  Printf("  %s of size %zu at 0x%zx by thread T%d:\n", ma.TypeAsString(),
         Bytes(ma.size), Bytes(ma.addr), tid);
  PrintStackTrace(stack_trace, "    ");
}

}  // namespace gwpsan
