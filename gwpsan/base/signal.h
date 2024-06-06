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

#ifndef GWPSAN_BASE_SIGNAL_H_
#define GWPSAN_BASE_SIGNAL_H_

#include <signal.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/units.h"

namespace gwpsan SAN_LOCAL {

typedef int (*sigaction_t)(int sig, const struct sigaction* act,
                           struct sigaction* old);

Result<int> Sigaction(int sig, const struct sigaction* act,
                      struct sigaction* oldact);

template <int kSig>
class SignalListenerBase {
  static_assert(kSig == SIGTRAP || kSig == SIGILL || kSig == SIGSEGV ||
                    kSig == SIGBUS,
                "Update InSignalHandler()");

 public:
  static bool SigactionInterceptor(const struct sigaction* act,
                                   struct sigaction* old);

  static bool InSignalHandler() {
    return __atomic_load_n(&handler_running_, __ATOMIC_RELAXED);
  }

  // Restores the initial state, if we already installed a handler.
  static void TestOnlyUninstall() SAN_NO_THREAD_SAFETY_ANALYSIS {
    if (state_ != State::kUninstalled) {
      const auto chain_act = chain_act_.Read();
      SAN_WARN_IF_ERR(Sigaction(kSig, &*chain_act, nullptr));
      state_ = State::kUninstalled;
    }
  }

 protected:
  using OnSignal = void (*)(int, siginfo_t*, void*);

  ~SignalListenerBase() {
    // If the SignalListener singleton is destroyed, it becomes weak to allow
    // recreation of the same or different SignalListener instance.
    Lock l(mu_);
    state_ = State::kWeakInstalled;
  }

  struct ScopedHandlerRunning {
    ScopedHandlerRunning() {
      __atomic_fetch_add(&handler_running_, 1, __ATOMIC_RELAXED);
    }
    ~ScopedHandlerRunning() {
      __atomic_fetch_sub(&handler_running_, 1, __ATOMIC_RELAXED);
    }
  };

  // Install a new handler with `on_signal`; overrides any previously installed
  // SignalListener handler.
  static bool Install(uptr flags, sigset_t mask, OnSignal on_signal, bool weak);

  static void Forward(int sig, siginfo_t* info, void* uctx);

 private:
  enum class State {
    kUninstalled,
    kWeakInstalled,
    kInstalled,
  };

  // This is shared between all classes.
  static Mutex mu_;
  static State state_ SAN_GUARDED_BY(mu_);
  static SeqLock<struct sigaction> chain_act_;
  static SAN_THREAD_LOCAL int handler_running_;
  friend class ScopedHandlerRunning;
};

template <int kSig>
constinit Mutex SignalListenerBase<kSig>::mu_;
template <int kSig>
constinit SignalListenerBase<kSig>::State SignalListenerBase<kSig>::state_ =
    SignalListenerBase<kSig>::State::kUninstalled;
template <int kSig>
constinit SeqLock<struct sigaction> SignalListenerBase<kSig>::chain_act_{mu_};
template <int kSig>
constinit SAN_THREAD_LOCAL int SignalListenerBase<kSig>::handler_running_ = 0;

// Helper to install signal handlers, and properly forward them. There may only
// be one SignalListener per kSig. If a SignalListener may be overridden by
// another later installed SignalListener, set kWeak to true.
template <int kSig, typename Derived, bool kWeak = false>
class SignalListener : public SignalListenerBase<kSig> {
 protected:
  explicit SignalListener(uptr flags = 0, sigset_t mask = {},
                          bool install_handler = false) {
    if (install_handler)
      InstallSignalHandler(flags, mask);
  }

  // Note: On destruction we should leave our signal handler installed, so
  // that latent signals do not cause termination; in production we should not
  // uninstall signal handler, and this should only affect tests (which can
  // revert to an initial state with TestOnlyUninstall() if needed).

  static bool InstallSignalHandler(uptr flags = 0, sigset_t mask = {}) {
    return Base::Install(flags, mask, OnSignal, kWeak);
  }

 private:
  using Base = SignalListenerBase<kSig>;
  using typename SignalListenerBase<kSig>::ScopedHandlerRunning;

  // Return true if we expect spurious/async signals with kSig, and it is not
  // safe to unconditionally forward unhandled signals if Derived::singleton()
  // is not instantiated.
  static constexpr bool ExpectAsyncSignals() {
    switch (kSig) {
    case SIGTRAP:
      // Timers, or Perf async SIGTRAP.
      return true;
    default:
      return false;
    }
  }

  static void OnSignal(int sig, siginfo_t* info, void* uctx) {
    SAN_CHECK_EQ(sig, kSig);
    {
      ScopedHandlerRunning scoped_running;
      if (HandleNonFailingAccess(sig, uctx))
        return;
      bool signal_handled = ExpectAsyncSignals();
      // Derived::singleton() should return a class that provides
      // and_then_sync(); in most cases, this should just be a
      // SynchronizedSingleton<Derived>.
      Derived::singleton().and_then_sync([&](auto& derived) {
        signal_handled = derived.OnSignal(sig, info, uctx);
      });
      if (signal_handled)
        return;
    }
    // Note: It is possible that derived.OnSignal() was not called if the
    // singleton has been destroyed. The only problem might be that we fail to
    // forward a signal (if ExpectAsyncSignals()); however, this may only be a
    // problem in tests, and if some test generates a signal not destined for
    // us. In production the singletons should never be destroyed.
    Base::Forward(sig, info, uctx);
  }
};

// Makes InSignalHandler() return true in debug mode for testing purposes.
// This will make SAN_DCHECK_NOT_SIGNAL_HANDLER fail.
struct ScopedAsyncSignalSafe {
#if GWPSAN_DEBUG
  ScopedAsyncSignalSafe();
  ~ScopedAsyncSignalSafe();
#else
  ScopedAsyncSignalSafe() {}  // To prevent unused variable warnings.
#endif
};

inline uptr& ExtractPC(ucontext_t& uctx) {
#if GWPSAN_X64
  return reinterpret_cast<uptr&>(uctx.uc_mcontext.gregs[REG_RIP]);
#elif GWPSAN_ARM64
  return reinterpret_cast<uptr&>(uctx.uc_mcontext.pc);
#else
#error "unsupported arch"
#endif
}

inline uptr ExtractPC(const ucontext_t& uctx) {
  return ExtractPC(const_cast<ucontext_t&>(uctx));
}

inline uptr& ExtractSP(ucontext_t& uctx) {
#if GWPSAN_X64
  return reinterpret_cast<uptr&>(uctx.uc_mcontext.gregs[REG_RSP]);
#elif GWPSAN_ARM64
  return reinterpret_cast<uptr&>(uctx.uc_mcontext.sp);
#else
#error "unsupported arch"
#endif
}

inline uptr ExtractSP(const ucontext_t& uctx) {
  return ExtractSP(const_cast<ucontext_t&>(uctx));
}

inline uptr& ExtractFP(ucontext_t& uctx) {
#if GWPSAN_X64
  return reinterpret_cast<uptr&>(uctx.uc_mcontext.gregs[REG_RBP]);
#elif GWPSAN_ARM64
  return reinterpret_cast<uptr&>(uctx.uc_mcontext.regs[29]);
#else
#error "unsupported arch"
#endif
}

inline uptr ExtractFP(const ucontext_t& uctx) {
  return ExtractFP(const_cast<ucontext_t&>(uctx));
}

inline uptr ReturnPC(const ucontext_t& uctx) {
#if GWPSAN_X64
  uptr res = 0;
  NonFailingLoad(Addr(uctx.uc_mcontext.gregs[REG_RSP]), Sizeof(res), &res);
  return res;
#elif GWPSAN_ARM64
  return uctx.uc_mcontext.regs[30];
#else
#error "unsupported arch"
#endif
}

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_SIGNAL_H_
