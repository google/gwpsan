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

#include "gwpsan/core/breakmanager.h"

#include <limits.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <signal.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/linux.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/timer.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/unwind_instruction.h"

namespace gwpsan {

DEFINE_METRIC(watchpoints_hit, 0, "Number of watchpoint hit");
DEFINE_METRIC(watchpoints_set, 0, "Number of watchpoints set");
DEFINE_METRIC(watchpoints_no_capacity, 0,
              "Number of watchpoints that wasn't set due to capacity limit");
DEFINE_METRIC(timer_samples, 0, "Number of timers samples received");
DEFINE_METRIC_ARRAY(static_cast<uptr>(BreakManager::ResetReason::kCount),
                    global_resets, "Number of global state resets",
                    [](uptr idx) {
                      return BreakManager::ResetReasonString(
                          static_cast<BreakManager::ResetReason>(idx));
                    });

namespace {
struct ThreadContext {
  bool registered = false;  // registered for OnThreadExit callback
  bool exited = false;      // already called OnThreadExit
  bool trapping = false;    // currently in the signal handler
  // Per-thread breakpoint used for controlled restrained thread execution
  // (breaking on the next PC).
  OptionalBase<Breakpoint> restraint;
};

constinit pthread_key_t thread_dtor;
constinit SAN_THREAD_LOCAL ThreadContext thr;
}  // namespace

bool BreakManager::Init() {
  return !SAN_WARN(
      SAN_LIBCALL(pthread_key_create(&thread_dtor, ThreadDestructor)));
}

void BreakManager::ThreadDestructor(void* arg) {
  uptr iter = reinterpret_cast<uptr>(arg);
  if (iter > 1) {
    SAN_CHECK(
        !pthread_setspecific(thread_dtor, reinterpret_cast<void*>(iter - 1)));
    return;
  }
  __atomic_store_n(&thr.exited, true, __ATOMIC_SEQ_CST);
  thr.restraint.reset();

  // For in-production use we expect the BreakManager and Callback to never be
  // destroyed. For tests, we expect threads to be joined before test completion
  // or never exit at all.
  if (SAN_WARN(!singleton()))
    return;
  if (SAN_WARN(!singleton()->cb_))
    return;
  singleton()->cb_->OnThreadExit();
}

BreakManager::BreakManager(bool& ok, const Config& cfg)
    : breakpoint_mode_(cfg.mode)
    , timer_(ok) {
  SAN_CHECK(!(cfg.mode & Breakpoint::kModePerThread));
  SAN_CHECK_LE(cfg.max_breakpoints, kMaxBreakpoints);
  for (auto& bp : breaks_) {
    if (available_.size() == cfg.max_breakpoints)
      break;
    if (!bp.Init(cfg.mode))
      ok = false;
    available_.emplace_back(&bp);
  }

  // Since the kernel supports async SIGTRAP on perf events, we do not need
  // SA_NODEFER here, and we can filter any signals by checking the async bit.
  sigset_t sig_mask;
  SAN_LIBCALL(sigfillset)(&sig_mask);
  SAN_LIBCALL(sigdelset)(&sig_mask, SIGSEGV);
  SAN_LIBCALL(sigdelset)(&sig_mask, SIGBUS);
  SAN_LIBCALL(sigdelset)(&sig_mask, SIGABRT);
  if (!InstallSignalHandler(SA_RESTART, sig_mask))
    ok = false;
}

BreakManager::BreakManager(bool& ok, Breakpoint::Mode mode,
                           uptr max_breakpoints)
    : BreakManager(ok, Config{
                           .mode = mode,
                           .max_breakpoints = max_breakpoints,
                       }) {}

BreakManager::~BreakManager() {
  // The shutdown sequence is tricky because we can enter into dtor in
  // restrained execution/emulation mode.
  //
  // After SingletonSync::ResetBegin() we can still get signals, but they will
  // return early and won't access BreakManager. Once we reset timer and close
  // breakpoints, we stop receiving signals.

  CallbackDisableContext disable_ctx;
  CallbackDisable(disable_ctx);
  (void)Sample(0);
  for (auto& bp : breaks_)
    bp.Close();
  // Note: we may have restraints enabled in other threads as well.
  // Destroying restraint for the current thread is enough for tests,
  // which are either single-threaded or have threads that are test-scoped.
  // And for real uses it should not matter since BreakManager is not destroyed.
  thr.restraint.reset();
  pthread_setspecific(thread_dtor, nullptr);
  __atomic_store_n(&thr.registered, false, __ATOMIC_RELAXED);
  CallbackEnable(disable_ctx);
}

void BreakManager::Register(Callback* cb) {
  Lock lock(mtx_);
  SAN_CHECK_EQ(cb_, nullptr);
  cb_ = cb;
}

void BreakManager::Unregister(Callback* cb) {
  Lock lock(mtx_);
  SAN_CHECK_EQ(cb_, cb);
  cb_ = nullptr;
}

bool BreakManager::Sample(Duration period) {
  return timer_.SetDelay(period);
}

void BreakManager::CallbackLock() {
  // Need to set trapping before locking the mutex, so that we don't get
  // a recursive signal that will try to lock the mutex again (and deadlock).
  SAN_CHECK(!__atomic_exchange_n(&thr.trapping, true, __ATOMIC_SEQ_CST));
  mtx_.Lock();
}

void BreakManager::CallbackUnlock() {
  mtx_.Unlock();
  SAN_CHECK(__atomic_exchange_n(&thr.trapping, false, __ATOMIC_SEQ_CST));
}

void BreakManager::CheckCallbackLocked() {
  mtx_.CheckLocked();
}

void BreakManager::CallbackDisable(CallbackDisableContext& ctx) {
  // We need to disable delivery of our SIGTRAP signals.
  // Otherwise we may get into an infinite loop if we get a signal and then
  // another signal while delivering the first signal (when kernel
  // reads/writes siginfo). While we will return early from the signal handler
  // because thr.trapping is set, we will get another signal immediately
  // (because kernel touches siginfo_t area and triggers another signal),
  // and then one more and so on infinitely.
  // What we would need to do in such case is to disable the breakpoint that
  // triggers the infinite signal, but we can't do that because that would
  // require locking mtx_, which we already locked as part of CallbackDisable.
  // So a recursive lock with deadlock.
  // Delaying SIGTRAPs for the duration of CallbackDisable/Enable solves all
  // of the above problems.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  SAN_CHECK(!sigprocmask(SIG_BLOCK, &set, &ctx.oldset));
  CallbackLock();
}

void BreakManager::CallbackEnable(CallbackDisableContext& ctx) {
  CallbackUnlock();
  SAN_CHECK(!sigprocmask(SIG_SETMASK, &ctx.oldset, nullptr));
}

Breakpoint* BreakManager::Watch(Breakpoint::Info bpinfo) {
  if (available_.empty()) {
    metric_watchpoints_no_capacity.LossyAdd(1);
    return nullptr;
  }
  auto* bp = available_.pop_back();
  if (SAN_WARN_IF_ERR(bp->Enable(bpinfo), "type=%d addr=0x%zx size=%zu",
                      static_cast<int>(bpinfo.type), Bytes(bpinfo.addr),
                      Bytes(bpinfo.size))) {
    available_.emplace_back(bp);
    return nullptr;
  }
  metric_watchpoints_set.LossyAdd(1);
  return bp;
}

void BreakManager::Unwatch(Breakpoint* bp) {
  SAN_CHECK(bp);
  for (auto* bp1 : available_)
    SAN_CHECK_NE(bp, bp1);
  bp->Disable();
  available_.emplace_back(bp);
}

Breakpoint* BreakManager::FindBreakpoint(const Breakpoint::MatchInfo& minfo) {
  mtx_.CheckLocked();
  for (auto& bp : breaks_) {
    if (bp.Match(minfo))
      return &bp;
  }
  if (thr.restraint.and_then([&](auto& bp) { return bp.Match(minfo); }))
    return &*thr.restraint;
  // The breakpoint may have been already disabled and reused in another thread.
  return nullptr;
}

bool BreakManager::Reset(ResetReason reason, uptr pc) {
  mtx_.CheckLocked();
  SetDeferredReset(ResetReason::kNone);
  if (cb_->OnReset(reason))
    return true;
  SAN_LOG("global reset due to %s at %s", ResetReasonString(reason),
          &DumpInstr(pc, kDumpPC | kDumpModule));
  metric_global_resets.LossyAdd(static_cast<uptr>(reason), 1);
  thr.restraint.and_then([](auto& bp) { bp.Disable(); });
  return false;
}

bool BreakManager::OnSignal(int sig, siginfo_t* siginfo, void* uctxp) {
  void (BreakManager::*on_event)(const siginfo_t&, ucontext_t&) = nullptr;
  switch (timer_.IsSignal(*siginfo)) {
  case SampleTimer::EventType::kTransient:
    SetDeferredReset(ResetReason::kTransientTimer);
    return true;
  case SampleTimer::EventType::kSample:
    on_event = &BreakManager::OnTimer;
    break;
  case SampleTimer::EventType::kNone:
    if (siginfo->si_code == TRAP_PERF) {
      // Note: We assume that binaries enabling gwpsan will not want to set up
      // SIGTRAP perf events and we take full ownership of all TRAP_PERF
      // signals. Should this become a problem we need to add infrastructure to
      // register sig_data that we expect here, and forward all other signals.
      SAN_DCHECK_EQ(GetSigInfoPerf(*siginfo).type, PERF_TYPE_BREAKPOINT);
      on_event = &BreakManager::OnBreakpoint;
      break;
    }
    [[fallthrough]];
  default:
    // SIGTRAP is not real-time/queued. So if we got an alien signal, we could
    // have lost our signals and need to assume the worst and reset.
    SetDeferredReset(ResetReason::kAlienSignal);
    return false;
  }

  // Note: we don't even call cb_.OnWrite if thr.trapping because the assumption
  // is that we should not really work with user memory. We can hit a left-over
  // watchpoint for stack memory, but since it's left-over it's fine to keep it.
  // Or we can trigger a watchpoint while doing memory load emulating a memory
  // load instruction, but it's not a write. Potentially there may be a
  // performance issue if we have a left-over watchpoint for stack memory and we
  // always hit it (potentially multiple times per handler), but user code never
  // gets that deep and doesn't reset it.
  if (__atomic_exchange_n(&thr.trapping, true, __ATOMIC_SEQ_CST))
    return true;
  (this->*on_event)(*siginfo, *static_cast<ucontext_t*>(uctxp));
  __atomic_store_n(&thr.trapping, false, __ATOMIC_RELEASE);
  return true;
}

void BreakManager::OnBreakpoint(const siginfo_t& siginfo, ucontext_t& uctx)
    SAN_NO_THREAD_SAFETY_ANALYSIS {
  metric_watchpoints_hit.LossyAdd(1);
  const auto minfo = Breakpoint::ExtractMatchInfo(SIGTRAP, siginfo);
  if (!AsyncBreakpointFilter(minfo, uctx))
    return;
  mtx_.CheckLocked();
  // The breakpoint may have been already disabled and reused in another thread.
  // In such case presumably we don't need to do anything.
  if (auto bp = FindBreakpoint(minfo)) {
    // TODO(dvyukov): work-around for broken arm64 breakpoints.
    // If we don't disable the breakpoint before returning from the handler,
    // the process will hang. This is very wrong. But for now it allows us to
    // pass simple tests. Remove when arm64 breakpoints are fixed.
    // Disabling the breakpoint resets bpinfo, so we need to save it now.
    const auto bpinfo = bp->bpinfo();
    if (GWPSAN_ARM64)
      bp->Disable();
    DispatchCallback(siginfo, uctx, EventType::kBreakpoint, bp, &bpinfo);
  } else {
    SAN_LOG("no breakpoint for 0x%zx", minfo.addr());
  }
  mtx_.Unlock();
}

bool BreakManager::AsyncBreakpointFilter(const Breakpoint::MatchInfo& minfo,
                                         ucontext_t& uctx)
    SAN_NO_THREAD_SAFETY_ANALYSIS {
  // Note: it does not matter if this is a code breakpoint (thread restraint)
  // or not. We don't need to reset the state due to the code breakpoint itself,
  // but since we don't know if we missed any data watchpoints because of this,
  // we need to reset state anyway.
  if (mtx_.TryLock()) {
    // Locked the mutex and this is not a sync signal, good to emulate.
    if (!minfo.is_async())
      return true;
    // If this is an async signal (delayed either due to signals blocked
    // with sigprocmask, or a recursive SIGTRAP), reset the state since we
    // don't know what other signals we missed.
    Reset(ResetReason::kAsyncSignal, ExtractPC(uctx));
    mtx_.Unlock();
  } else {
    // We can't process the signal right now, so we have to reset the state
    // on next mutex lock.
    SAN_LOG("try lock failed in signal at PC %s",
            &DumpInstr(ExtractPC(uctx), kDumpPC | kDumpModule));
    SetDeferredReset(ResetReason::kTryLockFail);
    if (minfo.is_async()) {
      // If this is an async signal, we need to reset the breakpoint right now.
      // Otherwise we can get into an infinite loop receiving the same signal
      // again and again.
      Lock lock(mtx_);
      Reset(ResetReason::kTryLockFail, ExtractPC(uctx));
    }
  }
  return false;
}

void BreakManager::OnTimer(const siginfo_t& siginfo, ucontext_t& uctx) {
  metric_timer_samples.LossyAdd(1);
  if (__atomic_load_n(&thr.exited, __ATOMIC_RELAXED) || !mtx_.TryLock())
    return;
  DispatchCallback(siginfo, uctx, EventType::kTimer);
  mtx_.Unlock();
}

void BreakManager::DispatchCallback(const siginfo_t& siginfo, ucontext_t& uctx,
                                    EventType evt_type, const Breakpoint* bp,
                                    const Breakpoint::Info* bpinfo) {
  // Disable the restraint breakpoint early to prevent recursive breakpoint
  // hits when we execute the same code the restraint is set to.
  // The recursion is not happening in the production msan build because we
  // internalize all our code (see the objcopy trickery in msan/BUILD).
  // But it still can happen in msan tests and there does not seem to be
  // an easy way to do similar internalization for the test.
  // Potentially this may slightly slow down execution because instead of
  // a single breakpoint modification syscall at the end we now do 2 syscalls
  // when single-stepping (disable here + enable at the end). If this becomes
  // a problem, we can either find a way to do internalization for the test,
  // or handle restraint differently in the tests and production.
  const uptr restraint_pc =
      thr.restraint.and_then([](auto& bp) { return bp.Enabled(); })
          ? Bytes(thr.restraint->bpinfo().addr)
          : 0;
  thr.restraint.and_then([](auto& bp) { bp.Disable(); });
  if (!cb_)
    return;
  uptr pc = ExtractPC(uctx);
  if (__atomic_load_n(&thr.exited, __ATOMIC_RELAXED)) {
    Reset(ResetReason::kThreadExited, pc);
    return;
  }
  if (const auto reset = GetDeferredReset();
      reset != ResetReason::kNone && !Reset(reset, pc))
    return;
  RegisterCurrentThread();

  switch (evt_type) {
  case EventType::kBreakpoint: {
    SAN_DCHECK(bp);
    SAN_DCHECK(bpinfo);
    SAN_DCHECK(bpinfo->addr);
    if (bp != thr.restraint.ptr_or()) {
      SAN_LOG("hit breakpoint on 0x%zx/%zu at %s", Bytes(bpinfo->addr),
              Bytes(bpinfo->size), &DumpInstr(pc, kDumpPC | kDumpModule));
      if (!cb_->OnBreak(*bpinfo, bp->HitCount())) {
        Reset(ResetReason::kOnBreakFailed, pc);
        return;
      }

      if (GWPSAN_X64 && bpinfo->type != Breakpoint::Type::kCode) {
        auto prev = MakeUniqueFreelist<CPUContext>(uctx);
        if (restraint_pc && restraint_pc != pc) {
          // We have restraint enabled, but got a code breakpoint on
          // on an unexpected PC. Something went wrong (e.g. a signal).
          Reset(ResetReason::kRestraintMismatch, pc);
          return;
        }
        // Note: we need to do UnwindInstruction even if we don't execute
        // OnEmulate(prev) below. This is needed to avoid false positives
        // on syscalls. UnwindInstruction always fails on syscalls since it
        // doesn't predict that syscalls do any memory accesses. As the result
        // we reset state as needed.
        if (!UnwindInstruction(*prev, *bpinfo)) {
          Reset(ResetReason::kUnwindInstructionFailed, pc);
          return;
        }
        // If we have restraint enabled, we don't need to unwind/emulate
        // the previous instruction since we emulated it before.
        if (!restraint_pc) {
          uptr next_pc = cb_->OnEmulate(*prev);
          if (!next_pc) {
            SAN_LOG("resuming normal execution");
            return;
          }
          if (next_pc != pc) {
            SAN_LOG("mismatched next pc: expect %s, got %s",
                    &DumpInstr(pc, kDumpPC | kDumpModule),
                    &DumpInstr(next_pc, kDumpPC | kDumpModule));
            Reset(ResetReason::kUnwindEmulateMismatch, pc);
            return;
          }
        }
      }
    }
    break;
  }
  case EventType::kTimer:
    if (!cb_->OnTimer())
      return;
    break;
  default:
    SAN_BUG("should not get here!");
  }

  // We used to use GlobalPlacedObj here, but tsan needs to get two OnEmulate
  // callbacks at the same time.
  auto ctx = MakeUniqueFreelist<CPUContext>(uctx);
  uptr next_pc = cb_->OnEmulate(*ctx);
  if (next_pc) {
    if (!thr.restraint) {
      thr.restraint.emplace();
      if (SAN_WARN(!thr.restraint->Init(breakpoint_mode_ |
                                        Breakpoint::kModePerThread))) {
        // We can't proceed here, because calling Enable() on non-initialized
        // Breakpoint will CHECK-fail. It is possible that the tool will be in a
        // bad state if it receives an unexpected event from this point forward,
        // but should only result in more WARNs but no crashes.
        thr.restraint.reset();
        return;
      }
    }
    // Execute until next_pc.
    SAN_LOG("enabling restraint on PC %zx", next_pc);
    auto res = thr.restraint->Enable({Breakpoint::Type::kCode, Addr(next_pc)});
    if (!res) {
      // This is possible if we mispredicted the next address (because we
      // emulated multiple instructions in a row, or otherwise) and asked
      // for something wild. Generally the code should be prepared for
      // the restraint not firing because, again, we can mispredict,
      // or the timer can always fire before the restraint. The code should
      // recover from this on the next timer sample, so we ignore the error.
      SAN_LOG("failed to enable restraint: %d", res.err());
    }
  }
  // Resume normal execution.
  SAN_LOG("resuming normal execution");
}

void BreakManager::RegisterCurrentThread() {
  // Don't change the value if we already set it.
  // Otherwise we may clash with the destructor that is already running
  // and started counting the iterations.
  if (__atomic_load_n(&thr.registered, __ATOMIC_RELAXED) ||
      __atomic_exchange_n(&thr.registered, true, __ATOMIC_RELAXED))
    return;
  uptr iters = PTHREAD_DESTRUCTOR_ITERATIONS;
  // LSan may report false leaks for UAR Thread object if we use the max
  // number of iterations. LSan also uses the same max number of iterations
  // to remove threads from the thread registry. If leak checking runs
  // in between LSan forgets about the thread and our destructor runs,
  // LSan does not scan the thread and reports a false leak.
  if (GWPSAN_INSTRUMENTED_ASAN)
    iters--;
  pthread_setspecific(thread_dtor, reinterpret_cast<void*>(iters));
}

void BreakManager::BeginFork(CallbackDisableContext& disable_ctx)
    SAN_NO_THREAD_SAFETY_ANALYSIS {
  CallbackDisable(disable_ctx);
  timer_.BeginFork();
}

void BreakManager::EndFork(int pid, CallbackDisableContext& disable_ctx)
    SAN_NO_THREAD_SAFETY_ANALYSIS {
  if (!pid) {
    for (auto& bp : available_) {
      // Because all our breakpoints are initialized with "inherit_thread=1",
      // they will not be inherited by a regular fork() (which will no longer be
      // in the same thread group). Force reinitialization of the breakpoints.
      SAN_WARN(!bp->Init(breakpoint_mode_, /*force=*/true));
    }
  }

  timer_.EndFork();
  CallbackEnable(disable_ctx);
}

void BreakManager::SetDeferredReset(ResetReason reason) {
  __atomic_store_n(&deferred_reset_, static_cast<u32>(reason),
                   __ATOMIC_RELAXED);
}

BreakManager::ResetReason BreakManager::GetDeferredReset() const {
  return static_cast<ResetReason>(
      __atomic_load_n(&deferred_reset_, __ATOMIC_RELAXED));
}

const char* BreakManager::ResetReasonString(ResetReason reason) {
  switch (reason) {
  case ResetReason::kNone:
    return "none";
  case ResetReason::kAsyncSignal:
    return "async signal";
  case ResetReason::kTryLockFail:
    return "try lock failed";
  case ResetReason::kThreadExited:
    return "thread exited";
  case ResetReason::kAlienSignal:
    return "alien signal";
  case ResetReason::kOnBreakFailed:
    return "break callback failed";
  case ResetReason::kRestraintMismatch:
    return "restraint PC mismatch";
  case ResetReason::kUnwindInstructionFailed:
    return "unwind instruction failed";
  case ResetReason::kUnwindEmulateMismatch:
    return "emulate after unwind PC mismatch";
  case ResetReason::kTransientTimer:
    return "transient timer signal";
  default:
    SAN_WARN(true);
    return "unknown";
  }
}

}  // namespace gwpsan
