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

#ifndef GWPSAN_UAR_UAR_H_
#define GWPSAN_UAR_UAR_H_

#include <pthread.h>
#include <signal.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/numeric.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/unified/tool.h"

namespace gwpsan SAN_LOCAL {

// Detect if UAR can rely on perf event support or not; if it can, returns the
// ideal precise_ip mode for the host.
Optional<int> UarDetectPerfEventSupport();

using ThreadRoutine = void* (*)(void*);

// UarDetector detects use-after-return (UAR) bugs.
//
// Operation outline:
//  - sample every uar_check_every_nth_thread (flag) thread
//  - allocate 2x as large stack for sampled threads
//  - the 2x stack is split into "main" stack and "second" stack
//  - every uar_sample_interval_usec (flag) arm perf event that samples
//    function entry
//  - when the perf event fires, adjust SP to switch from the main stack
//    to the second stack and arrange to call into our runtime when
//    the current function returns
//  - when the function returns, adjust SP back to the main stack and
//    protect the second stack
//  - if the code accesses any local variables in the second stack,
//    we get paging fault (which means an access to the frame of
//    the returned function)
class UarDetector final : public Tool,
                          public SynchronizedSingleton<UarDetector>,
                          public SignalListener<SIGSEGV, UarDetector> {
 public:
  bool ShouldSampleThread(const pthread_attr_t* attr);
  bool ModifyThread(pthread_attr_t* attr, ThreadRoutine* routine, void** arg);
  static bool GetStackLimits(uptr* lo, uptr* hi);
  static void SwitchBack();

 private:
  static constexpr uptr kStackTraceSize = 64;

  class Thread {
   public:
    Thread(UarDetector* detector, ThreadRoutine routine, void* arg,
           uptr stack_size, uptr guard_size);
    ~Thread();

    Thread(const Thread&) = delete;
    Thread& operator=(const Thread&) = delete;

    bool Prepare(uptr stack_addr);
    bool ProtectSecondStack();
    bool UnprotectSecondStack();
    void NameSecondStack(bool name);

    uptr MainStackBegin() const;
    uptr MainStackEnd() const;
    uptr SecondStackBegin() const;
    uptr SecondStackEnd() const;

    UarDetector* const detector_;
    // Original user thread routine/arg.
    ThreadRoutine const routine_;
    void* const arg_;
    // The thread stack is organized as follows:
    //
    // ╔═════════════╦═══════════════╦═════════════╦═══════════════╗
    // ║   guard     ║ second stack  ║   guard     ║  main stack   ║
    // ║(guard_size_)║ (stack_size_) ║(guard_size_)║ (stack_size_) ║
    // ╚═════════════╩═══════════════╩═════════════╩═══════════════╝
    //               ^
    //  stack_addr_══╝
    //
    const uptr stack_size_;
    uptr guard_size_;
    uptr stack_addr_ = 0;
    int tid_ = 0;
    bool initialized_ = false;
    bool stack_protected_ = false;
    bool stack_named_ = false;
    bool switched_ = false;
    // Stack trace where we last switched stack (for bug reporting).
    ArrayVector<uptr, kStackTraceSize> switch_stack_;
  };

  static SAN_THREAD_LOCAL Thread* current_;

  Rand rand_;
  // prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME) is supported.
  const bool set_vma_name_supported_;
  ArrayVector<uptr, kStackTraceSize> current_stack_;

  UarDetector(bool& ok);
  bool OnSignal(int signo, siginfo_t* siginfo, void* uctxp);
  void SampleMainThread();
  bool PrepareThread(Thread* thr);
  void SwitchBack(Thread* thr);
  static void* ThreadWrapper(void* arg);
  void PrintStackInfo(Thread* thr, const ucontext_t& uctx, uptr addr);

  // Tool interface:
  bool IsInteresting(const CPUContext& ctx) override;
  bool Check(CPUContext& ctx) override;
  void OnThreadExit() override;

  friend bool IsOnTheSecondStack();
  friend Singleton;
  friend SignalListener;
};

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_UAR_UAR_H_
