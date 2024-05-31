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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_BREAKMANAGER_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_BREAKMANAGER_H_

#include <signal.h>

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/timer.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"

namespace gwpsan SAN_LOCAL {

// BreakManager manages and distributes a set of breakpoints.
// It allows to watch/unwatch addresses, to execute a thread in a controlled
// manner stopping it at given PCs and to sample execution with a timer.
//
// Only one BreakManager can exist at any given time (signal handlers, timers
// and breakpoints are global resources); this is made explicit by requiring
// construction and use via Optional returned from BreakManager::singleton().
class BreakManager : public SynchronizedSingleton<BreakManager>,
                     public SignalListener<SIGTRAP, BreakManager> {
 public:
  // Arguments for constructor.
  struct Config {
    Breakpoint::Mode mode;
    // Specifies number of breakpoints that BreakManager will initialize
    // and make available for future Watch calls;
    // must be between 0 and kMaxBreakpoints.
    uptr max_breakpoints;
  };

  struct Callback;
  // Reasons why we do global state reset.
  // These are exported via METRIC_ARRAY and should not be deleted/reordered.
  enum class ResetReason : u32 {
    kNone,
    kAsyncSignal,
    kTryLockFail,
    kThreadExited,
    kAlienSignal,
    kOnBreakFailed,
    kRestraintMismatch,
    kUnwindInstructionFailed,
    kUnwindEmulateMismatch,
    kTransientTimer,
    kCount,
  };

  // REQUIRES: no existing callback registered
  void Register(Callback* cb);
  // REQUIRES: current registered callback is `cb`
  void Unregister(Callback* cb);

  // Enables execution sampling, users will get OnTimer and OnEmulate callbacks.
  // Must be called once after the constructor, but not combined with
  // the constructor because most likely users need to do some additional
  // setup before they are ready to receive sampling callbacks.
  [[nodiscard]] bool Sample(Duration period);

  // Enable a blobal breakpoint for all threads, users will get OnBreak and
  // OnEmulate callbacks.
  // Returns nullptr if out of breakpoints.
  Breakpoint* Watch(Breakpoint::Info bpinfo);
  // Disable a breakpoint returned by Watch.
  void Unwatch(Breakpoint* bp);

  // Maximum number of breakpoints that can be enabled with Watch.
  static constexpr uptr kMaxBreakpoints = 3;

  // Lock/unlock BreakManager mutex that is used to protect callbacks.
  // Should be used from user callbacks to give up the lock during long
  // computations or stalls that do *not* use any data shared with callbacks.
  void CallbackLock() SAN_ACQUIRE(mtx_);
  void CallbackUnlock() SAN_RELEASE(mtx_);
  // Check that the callback mutex is locked by the current thread.
  void CheckCallbackLocked() SAN_CHECK_LOCKED(mtx_);

  class CallbackDisableContext {
    friend class BreakManager;
    sigset_t oldset;
  };

  // Lock/unlock BreakManager mutex that is used to protect callbacks.
  // Should be used by code that shares data with the callbacks.
  void CallbackDisable(CallbackDisableContext& ctx) SAN_ACQUIRE(mtx_);
  void CallbackEnable(CallbackDisableContext& ctx) SAN_RELEASE(mtx_);

  // Ensures that OnThreadExit callback will be called for the current thread.
  void RegisterCurrentThread();

  // To be called before fork().
  void BeginFork(CallbackDisableContext& disable_ctx) SAN_ACQUIRE(mtx_);
  // Reinitialize state after fork().
  void EndFork(int pid, CallbackDisableContext& disable_ctx) SAN_RELEASE(mtx_);

  static bool Init();
  static const char* ResetReasonString(ResetReason reason);

 private:
  enum class EventType {
    kUnknown,
    kBreakpoint,
    kTimer,
  };

  Mutex mtx_;
  Callback* cb_ = nullptr;
  const Breakpoint::Mode breakpoint_mode_;
  Array<Breakpoint, kMaxBreakpoints> breaks_;
  ArrayVector<Breakpoint*, kMaxBreakpoints> available_;
  SampleTimer timer_;
  // If set to anything other than ResetReason::kNone, something went wrong
  // and we need to reset all state on the next event. The flag allows us
  // to avoid blocking on the mutex in some contexts.
  u32 deferred_reset_ = static_cast<u32>(ResetReason::kNone);

  explicit BreakManager(bool& ok, const Config& cfg);
  explicit BreakManager(bool& ok, Breakpoint::Mode mode = 0,
                        uptr max_breakpoints = kMaxBreakpoints);
  ~BreakManager();

  bool OnSignal(int sig, siginfo_t* siginfo, void* uctxp);
  void OnBreakpoint(const siginfo_t& siginfo, ucontext_t& uctx);
  void OnTimer(const siginfo_t& siginfo, ucontext_t& uctx);
  void DispatchCallback(const siginfo_t& siginfo, ucontext_t& uctx,
                        EventType evt_type, const Breakpoint* bp = nullptr,
                        const Breakpoint::Info* bpinfo = nullptr);
  Breakpoint* FindBreakpoint(const Breakpoint::MatchInfo& minfo);
  bool AsyncBreakpointFilter(const Breakpoint::MatchInfo& minfo,
                             ucontext_t& uctx);
  bool Reset(ResetReason reason, uptr pc);
  void Disable();
  void Enable();
  void SetDeferredReset(ResetReason reason);
  ResetReason GetDeferredReset() const;

  static void ThreadDestructor(void* arg);

  BreakManager(const BreakManager&) = delete;
  BreakManager& operator=(const BreakManager&) = delete;
  friend Singleton;
  friend SignalListener;
};

class BreakManager::Callback {
 public:
  // Callback self-registers with the BreakManager singleton.
  // REQUIRES: if registration==true, BreakManager::singleton() is initialized
  explicit Callback(bool registration = true)
      : registration_(registration) {
    if (registration)
      mgr()->Register(this);
  }
  // Self-unregisters with BreakManager if registered on construction.
  virtual ~Callback() {
    // If derived class has members used in callbacks, should be called by
    // derived class's destructor.
    BeginDestructor();
  }

  // Called on timer sample if sampling is enabled. Return true if the
  // interrupted instruction should be emulated, false otherwise.
  virtual bool OnTimer() {
    return false;
  }

  // Called when a breakpoint fires. Return true if the interrupted instruction
  // should be emulated, otherwise state will be reset and OnReset called.
  // hit_count is the number of times this breakpoint was triggered since
  // it was enabled.
  virtual bool OnBreak(const Breakpoint::Info& bpinfo, uptr hit_count) {
    return true;
  }

  // Called after OnTimer and OnBreak, allows users to observe and emulate
  // precise CPU context and to do restrained execution by returning the next
  // PC to stop. When the current thread reaches the returned PC, OnEmulate
  // is called again. If the callback returns 0, normal execution is resumed.
  virtual uptr OnEmulate(const CPUContext& ctx) {
    return 0;
  }

  // OnReset is called when global state might be imprecise, and analysis that
  // relies on precise analysis should be aborted. If the callback returns true,
  // emulation may proceed at best-effort, however, is not guaranteed; returning
  // false will immediately abort emulation.
  virtual bool OnReset(BreakManager::ResetReason reason) {
    return true;
  }

  // Called on thread exit if the thread has called
  // BreakManager::RegisterCurrentThread (otherwise may be called or not).
  virtual void OnThreadExit() {}

 protected:
  // Should be called by Callback implementations' destructors, to ensure
  // BreakManager cannot call Callback functions with members being destroyed.
  void BeginDestructor() {
    if (registration_ && mgr().has_value()) {
      mgr()->Unregister(this);
      registration_ = false;
    }
  }

  // Convenience accessor for derived classes to BreakManager.
  static auto mgr() -> decltype(BreakManager::singleton()) {
    return BreakManager::singleton();
  }

 private:
  bool registration_;
};

// RAII helper to initialize and destroy the singleton BreakManager.
//
// If T is derived from ScopedBreakManager and BreakManager::Callback,
// ResetBreakManager() may be used to re-initialize BreakManager.
template <typename T = void>
class ScopedBreakManagerSingleton {
 public:
  // REQUIRES: BreakManager::singleton() not yet initialized
  template <typename... Args>
  explicit ScopedBreakManagerSingleton(bool& ok, Args&&... args) {
    // While try_emplace() would implicitly reset(), disallow nested or
    // redundant use of ScopedBreakManager.
    SAN_CHECK(!BreakManager::singleton().has_value());
    if (!BreakManager::singleton().try_emplace(forward<Args>(args)...))
      ok = false;
  }

  ~ScopedBreakManagerSingleton() {
    BreakManager::singleton().reset();
  }

  // Re-initializes BreakManager and re-registers the derived class as Callback.
  template <typename... Args>
  [[nodiscard]] bool ResetBreakManager(Args&&... args) {
    if (BreakManager::singleton().try_emplace(forward<Args>(args)...)) {
      auto* derived_with_callback = static_cast<T*>(this);
      BreakManager::singleton()->Register(derived_with_callback);
      return true;
    }
    return false;
  }

  BreakManager* operator->() {
    return &*BreakManager::singleton();
  }
};

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_CORE_BREAKMANAGER_H_
