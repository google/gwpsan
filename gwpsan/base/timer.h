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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_TIMER_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_TIMER_H_

#include <signal.h>
#include <time.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/numeric.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/units.h"

namespace gwpsan SAN_LOCAL {

// Return the current time of `clockid`.
Duration GetTime(clockid_t clockid);

// Wrapper around POSIX per-process timer. Unlike other signal-based timers
// (e.g. setiitmer()), a POSIX timer can be identified via sival_ptr
// (requirement for accurately forwarding unhandled signals).
//
// There is no guarantee that the timer signal will fire in a specific thread,
// nor that repeated firing of the timer uniformly targets random threads (i.e.
// the timer signal cannot be used to sample random threads).
class PosixTimer {
 public:
  // Create a new POSIX timer that generates signals with number `sig`; the
  // timer will use clock `clockid` (see timer_create()). If `tid` is non-zero,
  // the signal is delivered to the thread with TID `tid`.
  explicit PosixTimer(bool& ok, int sig, clockid_t clockid, int tid = 0);
  ~PosixTimer();

  // If `periodic` is false, sets up a one-shot timer to fire after `delay`
  // duration; if `periodic` is true, sets up a repeating interval timer. A
  // `delay` of 0 disarms the timer.
  //
  // REQUIRES: ok
  [[nodiscard]] bool SetDelay(Duration delay, bool periodic);

  bool IsSignal(const siginfo_t& siginfo);

  const void* sival_ptr() const {
    return this;
  }

 private:
  bool Init();

  Optional<timer_t> timer_id_;
  const int sig_;
  const clockid_t clockid_;
  const int tid_;
};

// To be used to sample different threads relatively uniformly, addressing the
// shortcomings of PosixTimer (bad thread distribution).
class SampleTimer {
 public:
  enum EventType {
    kNone,       // Not a timer signal.
    kSample,     // A timer signal that can be used for sampling.
    kTransient,  // A transient timer signal not for sampling.
  };

  // The `clockid` is the type of POSIX timer used to drive the per-thread
  // timers. The duration `thread_work` specifies how much work (in CPU time) a
  // thread has to do (in aggregate) in between the driving timer firing and the
  // next perf timer firing.
  // If `require_distribution` is true, the timer is expected to distribute
  // signals across active threads; otherwise, signals are most likely skewed
  // towards the main thread.
  explicit SampleTimer(bool& ok, clockid_t clockid = CLOCK_PROCESS_CPUTIME_ID,
                       Duration thread_work = Milliseconds(10));

  // Sets up a periodic timer to fire after `delay` duration. A `delay` of 0
  // disarms the timer. The given `delay` is the desired target delay in real
  // wallclock time.
  //
  // REQUIRES: ok
  [[nodiscard]] bool SetDelay(Duration delay);

  // Check if the received signal was from this timer. See EventType.
  EventType IsSignal(const siginfo_t& siginfo);

  // To be called before fork().
  void BeginFork() SAN_ACQUIRE(select_mtx_, adapt_mtx_);

  // To be called after fork().
  void EndFork() SAN_RELEASE(select_mtx_, adapt_mtx_);

 private:
  // Adapts the driving timer's delay to roughly match the `target_delay_`.
  void AdaptDelay();

  const void* sival_ptr() const {
    return this;
  }

  // To check if the timer is distributing signals across threads.
  int driving_tid_ = -1;
  // Mutex guarding thread selection if POSIX timer is not distributing well.
  Mutex select_mtx_;
  // The last thread that was selected for a sample.
  int sample_tid_ SAN_GUARDED_BY(select_mtx_) = -1;

  PosixTimer driving_timer_;

  // Below is the state required for adapting the timer's delay.
  Mutex adapt_mtx_;
  Duration last_sample_ SAN_GUARDED_BY(adapt_mtx_);
  Duration target_delay_ SAN_GUARDED_BY(adapt_mtx_);
  Duration real_delay_ SAN_GUARDED_BY(adapt_mtx_);
  Rand rand_ SAN_GUARDED_BY(adapt_mtx_);
};

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_TIMER_H_
