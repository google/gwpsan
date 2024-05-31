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

#include "gwpsan/base/signal.h"

#include <dlfcn.h>
#include <errno.h>
#include <signal.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/syscall.h"

SAN_DECLARE_INTERCEPTOR(int, sigaction, int sig, const struct sigaction* act,
                        struct sigaction* old);
SAN_DECLARE_INTERCEPTOR(sighandler_t, signal, int sig, sighandler_t handler);

SAN_WEAK_IMPORT extern "C" int __sigaction(int sig, const struct sigaction* act,
                                           struct sigaction* old);

namespace gwpsan {
namespace {
#if GWPSAN_DEBUG
SAN_THREAD_LOCAL int test_in_signal_handler;
#endif

sigaction_t ResolveLibcSigaction() {
  // Then the normal libc function.
  auto fn = reinterpret_cast<sigaction_t>(dlsym(RTLD_NEXT, "sigaction"));
  if (fn)
    return fn;
  // In case we statically linked with libc, try one of its aliases.
  if (__sigaction)
    return __sigaction;
  SAN_BUG("dlsym(\"sigaction\") failed (%s)", dlerror());
}

sigaction_t resolve_sigaction() {
  // First try sanitizer interceptor.
  if (___interceptor_sigaction)
    return ___interceptor_sigaction;
  return ResolveLibcSigaction();
}

int real_sigaction(int sig, const struct sigaction* act,
                   struct sigaction* old) {
  static auto real = resolve_sigaction();
  return real(sig, act, old);
}

}  // namespace

Result<int> Sigaction(int sig, const struct sigaction* act,
                      struct sigaction* oldact) {
  if (real_sigaction(sig, act, oldact))
    return Result<int>{-static_cast<uptr>(errno)};
  return Result<int>{0};
}

template <int kSig>
void SignalListenerBase<kSig>::Forward(int sig, siginfo_t* info, void* uctx) {
  const auto chain_act = chain_act_.Read();
  if (chain_act->sa_handler == SIG_IGN) {
    // Ignore.
  } else if (chain_act->sa_handler == SIG_DFL) {
    // Should only forward default handler for fatal signals.
    SAN_WARN(sig != SIGHUP && sig != SIGINT && sig != SIGQUIT &&
             sig != SIGILL && sig != SIGTRAP && sig != SIGABRT &&
             sig != SIGBUS && sig != SIGFPE && sig != SIGKILL &&
             sig != SIGUSR1 && sig != SIGSEGV && sig != SIGUSR2 &&
             sig != SIGPIPE && sig != SIGALRM && sig != SIGTERM &&
             sig != SIGXCPU && sig != SIGXFSZ && sig != SIGVTALRM &&
             sig != SIGPROF && sig != SIGPOLL && sig != SIGSYS);
    auto fatal_fallback = [sig] {
      // If we could not invoke the kernel's default handler, terminate!
      SAN_BUG("Program received signal %d", sig);
    };
    CleanupRef fatal_fallback_cleanup(fatal_fallback);
    // We want to trigger the kernel's default handler, because it might trigger
    // policies (e.g. coredump) we cannot replicate by just termining with exit.
    //
    // Note: There is a chance that if we set the handler back to the default
    // handler, we might receive a signal we could normally handle (e.g. timer),
    // but would then crash in the other thread. There is no good solution for
    // this, but it seems acceptable if we assume this happens rarely.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    if (SAN_WARN_IF_ERR(
            sys_rt_sigprocmask(SIG_UNBLOCK, &set, nullptr, sizeof(uptr))))
      return;
    if (SAN_WARN_IF_ERR(Sigaction(sig, &*chain_act, nullptr)))
      return;
    SAN_WARN_IF_ERR(sys_rt_tgsigqueueinfo(GetPid(), GetTid(), sig, info));
  } else if (chain_act->sa_flags & SA_SIGINFO) {
    chain_act->sa_sigaction(sig, info, uctx);
  } else {
    chain_act->sa_handler(sig);
  }
}

template <int kSig>
bool SignalListenerBase<kSig>::SigactionInterceptor(const struct sigaction* act,
                                                    struct sigaction* old) {
  Lock l(mu_);
  if (state_ == State::kUninstalled)
    return false;
  // We let the external sigaction believe we do not exist, and return the
  // initially installed handler.
  if (old)
    *old = *chain_act_.ReadExclusive();
  // If the external sigaction installed a new handler, it is now the new "root"
  // of the external chain, and we have to update the tail (initial) chain_act_
  // of one of our SignalListener instances.
  if (act)
    chain_act_.Write(SeqValue{*act});
  return true;
}

template <int kSig>
bool SignalListenerBase<kSig>::Install(uptr flags, sigset_t mask,
                                       OnSignal on_signal, bool weak) {
  Lock l(mu_);
  struct sigaction act = {};
  act.sa_sigaction = on_signal;
  act.sa_flags = flags | SA_SIGINFO;
  act.sa_mask = mask;
  SeqValue<struct sigaction> oldact;
  if (SAN_WARN_IF_ERR(Sigaction(kSig, &act, &*oldact)))
    return false;

  // If we already installed a handler before, `chain_act_` is the "root" of the
  // external sigaction chain.
  if (state_ == State::kUninstalled)
    chain_act_.Write(oldact);

  // Sanitizers can prevent installation of external signal handlers,
  // but they pretend the installation has succeeded.
  // Query the handler again to understand if that happened or not.
  // If yes, then try to install our handler using libc sigaction.
  // But only for asan, because for msan we do need it to wrap our handler
  // to prevent false reports, so there is no way out.
  if (SAN_WARN_IF_ERR(Sigaction(kSig, nullptr, &*oldact)))
    return false;
  if (oldact->sa_sigaction != on_signal) {
    const bool kFallbackLibc =
        GWPSAN_INSTRUMENTED_ASAN && ___interceptor_sigaction;
    if (kFallbackLibc && !ResolveLibcSigaction()(kSig, &act, &*oldact)) {
      chain_act_.Write(oldact);
    } else {
      SAN_LOG("cannot install signal handler (sig=%d)", kSig);
      return false;
    }
  }

  SAN_LOG("installed signal handler (sig=%d)", kSig);

  // Disallow overriding non-weakly installed SignalListener.
  SAN_DCHECK_NE(state_, State::kInstalled);
  if (weak)
    state_ = State::kWeakInstalled;
  else
    state_ = State::kInstalled;
  return true;
}

template class SignalListenerBase<SIGTRAP>;
template class SignalListenerBase<SIGILL>;
template class SignalListenerBase<SIGSEGV>;
template class SignalListenerBase<SIGBUS>;

#if GWPSAN_DEBUG
ScopedAsyncSignalSafe::ScopedAsyncSignalSafe() {
  test_in_signal_handler++;
}

ScopedAsyncSignalSafe::~ScopedAsyncSignalSafe() {
  SAN_CHECK_GE(--test_in_signal_handler, 0);
}
#endif

int InSignalHandler() {
  // List all the signals used by our tools here.
  if (SignalListenerBase<SIGTRAP>::InSignalHandler())
    return SIGTRAP;
  if (SignalListenerBase<SIGILL>::InSignalHandler())
    return SIGILL;
  if (SignalListenerBase<SIGSEGV>::InSignalHandler())
    return SIGSEGV;
  if (SignalListenerBase<SIGBUS>::InSignalHandler())
    return SIGBUS;
#if GWPSAN_DEBUG
  if (test_in_signal_handler)
    return 123;
#endif
  return 0;
}

}  // namespace gwpsan

SAN_INTERFACE int __interceptor_sigaction(int sig, const struct sigaction* act,
                                          struct sigaction* old) {
  if (sig == SIGTRAP &&
      gwpsan::SignalListenerBase<SIGTRAP>::SigactionInterceptor(act, old))
    return 0;
  if (sig == SIGILL &&
      gwpsan::SignalListenerBase<SIGILL>::SigactionInterceptor(act, old))
    return 0;
  if (sig == SIGSEGV &&
      gwpsan::SignalListenerBase<SIGSEGV>::SigactionInterceptor(act, old))
    return 0;
  if (sig == SIGBUS &&
      gwpsan::SignalListenerBase<SIGBUS>::SigactionInterceptor(act, old))
    return 0;
  return gwpsan::real_sigaction(sig, act, old);
}

SAN_INTERFACE sighandler_t __interceptor_signal(int sig, sighandler_t handler) {
  // Not checking ___interceptor_signal, because implementing signal() in terms
  // of sigaction() is sufficient.
  struct sigaction act = {};
  act.sa_handler = handler;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, sig);
  act.sa_flags = SA_RESTART;
  struct sigaction old;
  if (__interceptor_sigaction(sig, &act, &old))
    return SIG_ERR;
  return old.sa_handler;
}
