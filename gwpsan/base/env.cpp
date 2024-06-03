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

#include "gwpsan/base/env.h"

#include <signal.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/sanitizer.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/synchronization.h"

namespace gwpsan {
namespace {
constinit SAN_THREAD_LOCAL uptr fail_restore_pc;

// We can install this handler as "weak", since it does not actually handle
// signals directly. We only need it to ensure that the signal handler is set up
// in case no other SignalListener<kSig, ..> is ever installed.
template <int kSig>
class SignalHandler final
    : public SignalListener<kSig, SignalHandler<kSig>, true>,
      public SynchronizedSingleton<SignalHandler<kSig>> {
 public:
  bool OnSignal(int signo, siginfo_t* siginfo, void* uctxp) {
    // This fake signal handler is only needed to install our SignalListener
    // handler. SignalListener will always call HandleNonFailingAccess
    // regardless of the actual handler, so we don't need to do anything here.
    return false;
  }

 private:
  explicit SignalHandler(bool& ok) {
    ok = this->InstallSignalHandler(SA_ONSTACK | SA_NODEFER);
  }

  friend SynchronizedSingleton<SignalHandler<kSig>>::Singleton;
};

// We must not trigger SIGSEGV/SIGBUS when emulate user accesses because
// we may mis-calcualte the address due to a bug in our code, or a race,
// or something else, and crash the process.
//
// We used to use process_vm_readv/writev to implement this function.
// It's probably the safest option, but it turned out to be quite slow.
// It may also cause issues with sandboxes (however if perf_event_open
// is not permitted, then it does not matter).
//
// LMSan may need a NonFailingMemcpy() that does not trigger our breakpoints.
// But somehow it's not a problem so far. If this becomes a problem,
// we can either handle such breakpoints specially in the BreakManager,
// or switch breakpoints to write-only while handling signals
// (though, this may be expensive), or switch back to process_vm_readv/writev.
//
// Note: we need to disable sanitizer instrumentation because the function
// must not do calls and because sanitizer instrumentation will try to access
// shadow of shadow while we are emulating sanitizer shadow accesses.
SAN_NOINSTR_BRITTLE bool NonFailingMemcpyImpl(void* dst, const void* src,
                                              uptr size) {
  // Tread carefully: If a signal is raised, the handler will set PC to the
  // fail_restore label's address. This means we must not call any functions
  // since SP would be restored to the wrong frame.
  fail_restore_pc = reinterpret_cast<uptr>(&&fail_restore);
  SAN_BARRIER();
  for (uptr i = 0; i < size; i++) {
    const u8 v = static_cast<const u8*>(src)[i];  // access may fault
    // "Invisible goto" so that compiler approximately knows that we may jump to
    // fail_restore from this location. Implies compiler barrier that also
    // prevents it from emitting a memcpy().
    SAN_INVISIBLE_GOTO(fail_restore);
    static_cast<u8*>(dst)[i] = v;
  }
  SAN_BARRIER();
  fail_restore_pc = 0;
  return true;

fail_restore:
  SAN_BARRIER();
  return false;
}
}  // namespace

bool NonFailingMemcpy(void* dst, const void* src, uptr size) {
  if (!NonFailingMemcpyImpl(dst, src, size))
    return false;
  MSAN_UNPOISON_MEMORY_REGION(dst, size);
  return true;
}

bool InitNonFailing() {
  return !!SignalHandler<SIGSEGV>::singleton().try_emplace();
}

bool HandleNonFailingAccess(int sig, void* uctx) {
  if ((sig != SIGSEGV && sig != SIGBUS) || !fail_restore_pc)
    return false;
  SAN_LOG("got signal %d copying user data - restoring PC to %p", sig,
          reinterpret_cast<void*>(fail_restore_pc));
  ExtractPC(*static_cast<ucontext_t*>(uctx)) = fail_restore_pc;
  fail_restore_pc = 0;
  return true;
}

}  // namespace gwpsan
