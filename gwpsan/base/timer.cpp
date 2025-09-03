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

#include "gwpsan/base/timer.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/linux.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/base/units.h"

#ifndef sigev_notify_thread_id
#define sigev_notify_thread_id _sigev_un._tid
#endif

namespace gwpsan {

DEFINE_METRIC(timer_freq_target, 0,
              "Sample timer is firing with target frequency");
DEFINE_METRIC(timer_freq_missed, 0,
              "Sample timer is firing fast/slow (adapted interval)");
DEFINE_METRIC(timer_signal_distributed, 0,
              "Sample timer signal delivered to different threads");
DEFINE_METRIC(timer_signal_same, 0,
              "Sample timer signal delivered to same thread as before");
DEFINE_METRIC(timer_sample_lost, 0, "Sample timer lost a sample");

Duration GetTime(clockid_t clockid) {
  kernel_timespec tp = {};
  SAN_WARN_IF_ERR(sys_clock_gettime(clockid, &tp));
  return Nanoseconds(tp.tv_nsec) + Seconds(tp.tv_sec);
}

PosixTimer::PosixTimer(bool& ok, int sig, clockid_t clockid, int tid)
    : sig_(sig)
    , clockid_(clockid)
    , tid_(tid) {
  if (!Init())
    ok = false;
}

PosixTimer::~PosixTimer() {
  if (timer_id_)
    sys_timer_delete(*timer_id_);
}

bool PosixTimer::Init() {
  struct sigevent sev = {};
  sev.sigev_notify = SIGEV_SIGNAL;
  if (tid_) {
    sev.sigev_notify |= SIGEV_THREAD_ID;
    sev.sigev_notify_thread_id = tid_;
  }
  sev.sigev_signo = sig_;
  sev.sigev_value.sival_ptr = const_cast<void*>(sival_ptr());
  timer_t timer_id = 0;
  if (!sys_timer_create(clockid_, &sev, &timer_id)) {
    // Creation for an invalid TID (not in this process) is expected to fail,
    // and is a supported usecase.
    SAN_WARN(!tid_, "timer creation failed");
    return false;
  }

  timer_id_ = timer_id;
  return true;
}

bool PosixTimer::SetDelay(Duration delay, bool periodic) {
  if (SAN_WARN(!timer_id_))
    return false;
  struct itimerspec its = {};
  its.it_value.tv_sec = *Seconds(delay, /*lossy=*/true);
  its.it_value.tv_nsec = Nanos(delay % Seconds(1));
  if (periodic)
    its.it_interval = its.it_value;
  if (!sys_timer_settime(*timer_id_, 0, &its, nullptr)) {
    // This may fail if the timer was deleted by the kernel, such as on fork().
    // Try recreating the timer and retry.
    if (!Init())
      return false;
    if (SAN_WARN_IF_ERR(sys_timer_settime(*timer_id_, 0, &its, nullptr)))
      return false;
  }
  return true;
}

bool PosixTimer::IsSignal(const siginfo_t& siginfo) {
  return timer_id_ && siginfo.si_code == SI_TIMER &&
         siginfo.si_value.sival_ptr == sival_ptr();
}

SampleTimer::SampleTimer(bool& ok, clockid_t clockid, Duration thread_work)
    : driving_timer_(ok, SIGTRAP, clockid) {
  SAN_DCHECK_NE(driving_timer_.sival_ptr(), sival_ptr());
}

bool SampleTimer::SetDelay(Duration delay) {
  Lock lock(adapt_mtx_);
  target_delay_ = real_delay_ = delay;
  last_sample_ = GetTime(CLOCK_MONOTONIC);

  return driving_timer_.SetDelay(delay, true);
}

SampleTimer::EventType SampleTimer::IsSignal(const siginfo_t& siginfo) {
  if (driving_timer_.IsSignal(siginfo)) {
    AdaptDelay();

    const int tid = GetTid();
    if (const int last_tid =
            __atomic_exchange_n(&driving_tid_, tid, __ATOMIC_RELAXED);
        last_tid != tid) {
      // POSIX timer seems to be distributing signals across threads; no need
      // for manual thread selection. With older kernels this is less likely to
      // be the case (but can still be observed)! Since Linux kernel 6.4, timer
      // signals should be better distributed by default - see Linux kernel
      // commit bcb7ee79029d ("posix-timers: Prefer delivery of signals to the
      // current thread").
      SAN_LOG("sampling this thread (last timer signal in T%d)", last_tid);
      metric_timer_signal_distributed.LossyAdd(1);
      return EventType::kSample;
    }

    TryLock lock(select_mtx_);
    if (!lock) {
      // Timer firing too rapidly; let's not walk the list of tasks concurrently
      // to avoid contention on internal kernel data structures.
      return EventType::kTransient;
    }

    // Need to select another thread that should be sampled.
    metric_timer_signal_same.LossyAdd(1);

    int first_tid = -1;
    // Note: ForEachTid() should iterate in sorted order.
    const bool iterated_tids = ForEachTid([&](int tid) {
      select_mtx_.CheckLocked();

      const auto state = GetThreadState(tid);
      if (state.value_or(ThreadState::kDead) != ThreadState::kRunning)
        return true;  // skip non-running threads

      if (first_tid == -1)
        first_tid = tid;
      if (tid > sample_tid_) {
        sample_tid_ = tid;
        first_tid = -1;
        return false;
      }

      return true;
    });
    if (SAN_WARN(!iterated_tids))
      return EventType::kSample;  // Fallback
    if (first_tid != -1)
      sample_tid_ = first_tid;  // wrap around
    if (sample_tid_ == tid) {
      SAN_LOG("sampling this thread");
      return EventType::kSample;
    }

    SAN_LOG("sampling thread T%d by sending signal", sample_tid_);
    siginfo_t queueinfo = {};
    queueinfo.si_value.sival_ptr = const_cast<void*>(sival_ptr());
    queueinfo.si_code = SI_TIMER;
    queueinfo.si_pid = tid;
    const int pid = GetPid();
    if (!sys_rt_tgsigqueueinfo(pid, sample_tid_, SIGTRAP, &queueinfo)) {
      // This may legitimately happen if the target thread exited and/or is no
      // longer in the same thread group. Better luck next time.
      SAN_LOG("rt_tgsigqueueinfo(%d, %d, SIGTRAP, ...) failed", pid,
              sample_tid_);
      metric_timer_sample_lost.LossyAdd(1);
    }
    return EventType::kTransient;
  } else if (siginfo.si_code == SI_TIMER &&
             siginfo.si_value.sival_ptr == sival_ptr()) {
    SAN_LOG("sampling this thread (received signal from T%d)", siginfo.si_pid);
    return EventType::kSample;
  }
  return EventType::kNone;
}

void SampleTimer::AdaptDelay() {
  // Anything below likely unachievable with today's OSes and CPUs.
  constexpr Microseconds kMinTargetDelay{10};

  // The lock primarly protects us from accidentally re-enabling the timer if it
  // was disabled via a concurrent SetDelay().
  TryLock lock(adapt_mtx_);
  if (!lock)
    return;  // Timer firing too rapidly or concurrent SetDelay().
  if (!target_delay_)
    return;  // SetDelay() concurrently disabled timer.
  if (target_delay_ <= kMinTargetDelay)
    return;  // ... unachievable with today's OSes and CPUs.

  const Duration now = GetTime(CLOCK_MONOTONIC);
  const Duration wall_delay = now - last_sample_;
  last_sample_ = now;

  // Check if monotonic time went backwards. Generally this should not happen
  // provided the kernel is not broken. However, it can happen in some process
  // migration cases if the migration procedure does not use time namespaces
  // to restore the monotonic clock.
  // On one hand, we want to warn about this, but on the other hand, we don't
  // want to warn too often, and don't want to warn in migration cases.
  // So we warn once if this happens twice in a row.
  static bool time_travel = false;
  if (wall_delay <= Duration()) {
    if (time_travel) {
      static bool warned = false;
      if (!warned) {
        warned = true;
        Printf("gwpsan: monotonic clock went backwards by %lld ns\n",
               *wall_delay);
      }
    }
    time_travel = true;
    return;
  }
  time_travel = false;

  // Let's avoid floating point calculations. Minimum is 1 to avoid div-by-0;
  // should that happen, we likely need more than 1 iteration to reach target.
  const auto percent =
      max<Duration::Type>((*wall_delay * 100) / *target_delay_, 1);

  // Wall delay within 100% to 200% of target delay is good.
  if (percent >= 100 && percent <= 200) {
    metric_timer_freq_target.LossyAdd(1);
    return;
  }

  // Aim for 125-175% of target - assumes scales proportionally.
  const s64 pct_target = 125 + rand_.Index(50);
  Duration new_real_delay{(*real_delay_ * pct_target) / percent};

  // Cap new real delay at some sane boundaries.
  const Duration real_delay_min = kMinTargetDelay;
  const Duration real_delay_max = Duration(2 * GetNumCPUs()) * target_delay_;
  SAN_DCHECK_GT(*real_delay_min, 0);
  SAN_DCHECK_GT(*real_delay_max, *real_delay_min);
  if (new_real_delay < real_delay_min)
    new_real_delay = real_delay_min;
  else if (new_real_delay > real_delay_max)
    new_real_delay = real_delay_max;

  SAN_LOG(
      "sample interval too %s (%lld.%lld milliseconds), "
      "adjusting to %lld.%lld milliseconds",
      new_real_delay > real_delay_ ? "low" : "high",
      *Milliseconds(wall_delay, /*lossy=*/true),
      Nanos(wall_delay % Milliseconds(1)),
      *Milliseconds(new_real_delay, /*lossy=*/true),
      Nanos(new_real_delay % Milliseconds(1)));

  if (driving_timer_.SetDelay(real_delay_, true))
    real_delay_ = new_real_delay;
  metric_timer_freq_missed.LossyAdd(1);
}

void SampleTimer::BeginFork() {
  adapt_mtx_.Lock();
  select_mtx_.Lock();
}

void SampleTimer::EndFork() {
  select_mtx_.Unlock();
  adapt_mtx_.Unlock();
}

}  // namespace gwpsan
