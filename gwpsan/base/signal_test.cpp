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

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <functional>

#include "gwpsan/base/common.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/base/vector.h"

extern "C" sighandler_t bsd_signal(int, sighandler_t);

namespace gwpsan {
namespace {

class SignalTester : public SynchronizedSingleton<SignalTester>,
                     public SignalListener<SIGTRAP, SignalTester> {
 public:
  ~SignalTester() {
    SAN_CHECK(!expect_signal_);
    SAN_CHECK(!expect_ext_signal_);
    SAN_CHECK(!expect_ext_sigaction_);
  }

  using Handler = void (*)(int);

  void CheckCurrentHandler(Handler expected) {
    struct sigaction old = {};
    SAN_CHECK(!sigaction(SIGTRAP, nullptr, &old));
    CheckHandler(old, expected);
  }

  void InstallHandler() {
    InstallSignalHandler();
  }

  void InstallExtHandler(Handler handler, Handler expected,
                         sighandler_t (*installer)(int,
                                                   sighandler_t) = signal) {
    CheckCurrentHandler(expected);
    SAN_CHECK_EQ(installer(SIGTRAP, handler), expected);
  }

  void InstallExtHandler(void (*handler)(int sig, siginfo_t* info, void* uctx),
                         Handler expected) {
    CheckCurrentHandler(expected);
    struct sigaction act = {};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = handler;
    struct sigaction old = {};
    SAN_CHECK(!sigaction(SIGTRAP, &act, &old));
    CheckHandler(old, expected);
  }

  void SendSignal() {
    siginfo_t info = {};
    info.si_code = SI_USER;
    info.si_pid = GetTid();
    SAN_CHECK(!!sys_rt_tgsigqueueinfo(GetPid(), GetTid(), SIGTRAP, &info));
  }

  void ExpectSignal(bool res) {
    SAN_CHECK(!expect_signal_);
    expect_signal_ = true;
    signal_result_ = res;
  }

  void ExpectExtSignal() {
    SAN_CHECK(!expect_ext_signal_);
    expect_ext_signal_ = true;
  }

  void ExpectExtSigaction() {
    SAN_CHECK(!expect_ext_sigaction_);
    expect_ext_sigaction_ = true;
  }

  void ExpectJmpSignal(jmp_buf* buf) {
    SAN_CHECK(!expect_jmp_signal_);
    expect_jmp_signal_ = buf;
  }

  bool OnSignal(int sig, siginfo_t* info, void* uctx) {
    SAN_CHECK(expect_signal_);
    expect_signal_ = false;
    return signal_result_;
  }

  static void SignalThunk(int sig) {
    singleton().and_then_sync([=](auto& self) {
      SAN_CHECK(self.expect_ext_signal_);
      self.expect_ext_signal_ = false;
    });
  }

  static void SigactionThunk(int sig, siginfo_t* info, void* uctx) {
    singleton().and_then_sync([=](auto& self) {
      SAN_CHECK(self.expect_ext_sigaction_);
      self.expect_ext_sigaction_ = false;
    });
  }

  static void LongjmpThunk(int sig) {
    singleton().and_then_sync([=](auto& self) {
      auto buf = self.expect_jmp_signal_;
      self.expect_jmp_signal_ = nullptr;
      SAN_CHECK_NE(buf, nullptr);
      longjmp(*buf, 1);
    });
  }

 private:
  bool expect_signal_ = false;
  bool signal_result_ = false;
  bool expect_ext_signal_ = false;
  bool expect_ext_sigaction_ = false;
  jmp_buf* expect_jmp_signal_ = nullptr;

  void CheckHandler(const struct sigaction& old, Handler expected) {
    auto handler = old.sa_handler;
    if (old.sa_flags & SA_SIGINFO)
      handler = reinterpret_cast<Handler>(old.sa_sigaction);
    SAN_CHECK_EQ(handler, expected);
  }
};

void ExpectDeath(const std::function<void()>& fn) {
  int pid = fork();
  SAN_CHECK_GE(pid, 0);
  if (!pid) {
    fn();
    exit(0);
  }
  int status = 0;
  while (pid != waitpid(pid, &status, 0)) {}
  SAN_CHECK(WIFSIGNALED(status));
  SAN_CHECK_EQ(WTERMSIG(status), SIGTRAP);
}

int RealMain() {
  auto& test = SignalTester::singleton().emplace();
  const auto SignalHandler = SignalTester::SignalThunk;
  const auto SigactionHandler =
      reinterpret_cast<SignalTester::Handler>(SignalTester::SigactionThunk);
  test.CheckCurrentHandler(SIG_DFL);
  ExpectDeath([&] { test.SendSignal(); });
  test.InstallExtHandler(SIG_DFL, SIG_DFL);
  ExpectDeath([&] { test.SendSignal(); });
  test.InstallExtHandler(SIG_IGN, SIG_DFL);
  test.SendSignal();
  test.InstallExtHandler(SignalHandler, SIG_IGN);
  test.ExpectExtSignal();
  test.SendSignal();
  // MSan has own bsd_signal interceptor which breaks the test.
  if (!GWPSAN_INSTRUMENTED_MSAN && !GWPSAN_INSTRUMENTED_TSAN) {
    test.InstallExtHandler(SIG_IGN, SignalHandler, ssignal);
    test.SendSignal();
    test.InstallExtHandler(SignalHandler, SIG_IGN, bsd_signal);
    test.ExpectExtSignal();
    test.SendSignal();
  }
  test.InstallExtHandler(SigactionHandler, SignalHandler);
  test.ExpectExtSigaction();
  test.SendSignal();
  test.InstallExtHandler(SIG_DFL, SigactionHandler);

  for (int iter = 0; iter < 4; iter++) {
    Printf("test #%d\n", iter);
    int pid = fork();
    SAN_CHECK_GE(pid, 0);
    if (pid) {
      int status = 0;
      while (pid != waitpid(pid, &status, 0)) {}
      SAN_CHECK_EQ(status, 0);
      continue;
    }
    if (iter == 0)
      test.InstallExtHandler(SIG_DFL, SIG_DFL);
    else if (iter == 1)
      test.InstallExtHandler(SIG_IGN, SIG_DFL);
    else if (iter == 2)
      test.InstallExtHandler(SignalHandler, SIG_DFL);
    else
      test.InstallExtHandler(SigactionHandler, SIG_DFL);
    // Now install own handler:
    test.InstallHandler();
    // If we handle the signal ourselves, it does not matter what user handler
    // is installed.
    test.ExpectSignal(true);
    test.SendSignal();
    // If we don't handle the behavior is different.
    if (iter == 0) {
      ExpectDeath([&] {
        test.ExpectSignal(false);
        test.SendSignal();
      });
    } else if (iter == 1) {
      test.ExpectSignal(false);
      test.SendSignal();
      test.InstallExtHandler(SIG_DFL, SIG_IGN);
    } else if (iter == 2) {
      test.ExpectSignal(false);
      test.ExpectExtSignal();
      test.SendSignal();
      test.InstallExtHandler(SIG_DFL, SignalHandler);
    } else {
      test.ExpectSignal(false);
      test.ExpectExtSigaction();
      test.SendSignal();
      test.InstallExtHandler(SIG_DFL, SigactionHandler);
    }
    // Now we have our handler installed and SIG_DFL as user handler.
    ExpectDeath([&] {
      test.ExpectSignal(false);
      test.SendSignal();
    });
    test.InstallExtHandler(SigactionHandler, SIG_DFL);
    test.ExpectSignal(false);
    test.ExpectExtSigaction();
    test.SendSignal();
    exit(0);
  }

  test.InstallHandler();
  test.InstallExtHandler(SignalTester::LongjmpThunk, SIG_DFL);
  jmp_buf buf;
  if (!setjmp(buf)) {
    test.ExpectSignal(false);
    test.ExpectJmpSignal(&buf);
    test.SendSignal();
  }
  {
    // Regression test for calling malloc/free after longjmp'ing
    // from a user signal handler.
    MallocVector<int> vec;
    vec.reserve(10);
  }

  return 0;
}

}  // namespace
}  // namespace gwpsan

int main() { return gwpsan::RealMain(); }
