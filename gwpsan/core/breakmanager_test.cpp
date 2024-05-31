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

#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <queue>
#include <thread>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"

namespace gwpsan {
namespace {

class BreakManagerTest : public testing::Test,
                         public ScopedBreakManagerSingleton<BreakManagerTest>,
                         public BreakManager::Callback {
 protected:
  BreakManagerTest()
      : ScopedBreakManagerSingleton(ok_) {}

  enum class Method {
    kOnTimer,
    kOnBreak,
    kOnEmulate,
    kOnReset,
    kOnThreadExit,
  };

  struct Expectation {
    Method method;
    Breakpoint::Info bpinfo;
    uptr hit_count;
    bool on_break_res;
    // If non-0, the value is added to the current context PC and returned from
    // OnEmulate.
    uptr on_emulate_pc_off;
    // If on_emulate_pc_off is 0, this value is returned from OnEmulate as is.
    uptr on_emulate_res;
    // For OnReset:
    BreakManager::ResetReason reason;
    Breakpoint* unwatch[BreakManager::kMaxBreakpoints];
    // For OnThreadExit:
    int tid;
  };

  void Expect(Expectation exp) {
    expects_.push(exp);
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
  }

  void ExpectAccess(Breakpoint::Info bpinfo, uptr hit_count) {
    Expect({
        .method = Method::kOnBreak,
        .bpinfo = bpinfo,
        .hit_count = hit_count,
        .on_break_res = true,
    });
    Expect({
        .method = Method::kOnEmulate,
        .on_emulate_res = 0,
    });
  }

 private:
  bool ok_ = true;
  std::queue<Expectation> expects_;

  void SetUp() override {
    ASSERT_TRUE(ok_);
  }

  void TearDown() override {
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    if (!expects_.empty())
      FAIL() << "unused expect " << static_cast<int>(expects_.front().method);
  }

  bool OnTimer() override {
    return false;
  }

  bool OnBreak(const Breakpoint::Info& bpinfo, uptr hit_count) override {
    auto exp = CheckMethod(Method::kOnBreak);
    EXPECT_EQ(bpinfo, exp.bpinfo);
    EXPECT_EQ(hit_count, exp.hit_count);
    return exp.on_break_res;
  }

  uptr OnEmulate(const CPUContext& ctx) override {
    auto exp = CheckMethod(Method::kOnEmulate);
    std::cout << "context: " << &ctx.Dump() << std::endl;
    if (exp.on_emulate_pc_off)
      return ctx.reg(kPC).val + exp.on_emulate_pc_off;
    return exp.on_emulate_res;
  }

  bool OnReset(BreakManager::ResetReason reason) override {
    if (reason == BreakManager::ResetReason::kTransientTimer)
      return true;  // impossible to predict these
    auto exp = CheckMethod(Method::kOnReset);
    EXPECT_EQ(exp.reason, reason);
    for (auto* bp : exp.unwatch) {
      if (bp)
        mgr()->Unwatch(bp);
    }
    return false;
  }

  void OnThreadExit() override {
    auto exp = CheckMethod(Method::kOnThreadExit);
    EXPECT_EQ(exp.tid, GetTid());
  }

  Expectation CheckMethod(Method method) {
    std::cout << "got method call " << static_cast<int>(method) << std::endl;
    EXPECT_FALSE(expects_.empty());
    auto exp = expects_.front();
    expects_.pop();
    EXPECT_EQ(exp.method, method);
    if (exp.tid)
      EXPECT_EQ(exp.tid, GetTid());
    return exp;
  }
};

TEST(BreakManager, ChainSignalDefault) {
  SignalListenerBase<SIGTRAP>::TestOnlyUninstall();
  bool ok = true;
  ScopedBreakManagerSingleton<> mgr(ok, 0, 0);
  ASSERT_TRUE(ok);
  EXPECT_DEATH(raise(SIGTRAP), ".*");
}

int old_handler_calls = -1;
void OldHandler(int sig) {
  SAN_CHECK_NE(old_handler_calls, -1);
  old_handler_calls++;
}

TEST(BreakManager, ChainSignalCustom) {
  SignalListenerBase<SIGTRAP>::TestOnlyUninstall();
  struct sigaction act = {};
  struct sigaction oldact = {};
  act.sa_handler = OldHandler;
  ASSERT_NE(sigaction(SIGTRAP, &act, &oldact), -1);

  // Test normal delivery.
  old_handler_calls = 0;
  raise(SIGTRAP);
  ASSERT_EQ(old_handler_calls, 1);

  // Via BreakManager chaining.
  bool ok = true;
  ScopedBreakManagerSingleton<> mgr(ok, 0, 0);
  ASSERT_TRUE(ok);
  for (int i = 0; i < 10; ++i)
    raise(SIGTRAP);
  EXPECT_EQ(old_handler_calls, 11);
  old_handler_calls = -1;  // Fail if called again by BreakManager.
  // Restore old handler (overriding BreakManager handler).
  ASSERT_NE(sigaction(SIGTRAP, &oldact, nullptr), -1);
}

int old_handler_siginfo_calls = -1;
void OldHandlerSiginfo(int sig, siginfo_t* info, void* uctx) {
  SAN_CHECK_NE(old_handler_siginfo_calls, -1);
  old_handler_siginfo_calls++;
}

TEST(BreakManager, ChainSignalCustomSiginfo) {
  SignalListenerBase<SIGTRAP>::TestOnlyUninstall();
  // Install custom handler.
  struct sigaction act = {};
  struct sigaction oldact = {};
  act.sa_sigaction = OldHandlerSiginfo;
  act.sa_flags |= SA_SIGINFO;
  ASSERT_NE(sigaction(SIGTRAP, &act, &oldact), -1);

  // Test normal delivery.
  old_handler_siginfo_calls = 0;
  raise(SIGTRAP);
  ASSERT_EQ(old_handler_siginfo_calls, 1);

  // Via BreakManager chaining.
  bool ok = true;
  ScopedBreakManagerSingleton<> mgr(ok, 0, 0);
  ASSERT_TRUE(ok);
  for (int i = 0; i < 10; ++i)
    raise(SIGTRAP);
  EXPECT_EQ(old_handler_siginfo_calls, 11);
  old_handler_siginfo_calls = -1;
  ASSERT_NE(sigaction(SIGTRAP, &oldact, nullptr), -1);
}

TEST(BreakManager, NumBreakpoints) {
  for (uptr bps = 0; bps < BreakManager::kMaxBreakpoints; bps++) {
    bool ok = true;
    ScopedBreakManagerSingleton<> mgr(ok, 0, bps);
    ASSERT_TRUE(ok);
    BreakManager::Callback cb;
    int data = 0;
    for (uptr i = 0; i < BreakManager::kMaxBreakpoints + 1; i++) {
      auto* bp =
          mgr->Watch({Breakpoint::Type::kReadWrite, &data, Sizeof(data)});
      if (i < bps)
        ASSERT_NE(bp, nullptr);
      else
        ASSERT_EQ(bp, nullptr);
    }
  }
}

TEST_F(BreakManagerTest, OnEmulateFails) {
  volatile int data = 0;

  Expect({
      .method = Method::kOnBreak,
      .bpinfo = {Breakpoint::Type::kReadWrite, &data, Sizeof(data)},
      .hit_count = 1,
      .on_break_res = true,
  });
  Expect({
      .method = Method::kOnEmulate,
      .on_emulate_res = 0,
  });

  auto* bp = mgr()->Watch({Breakpoint::Type::kReadWrite, &data, Sizeof(data)});
  data = 1;
  mgr()->Unwatch(bp);
}

TEST_F(BreakManagerTest, Unwatch) {
  volatile int data = 0;
  auto* bp = mgr()->Watch({Breakpoint::Type::kReadWrite, &data, Sizeof(data)});
  mgr()->Unwatch(bp);
  data = 1;
}

TEST_F(BreakManagerTest, UnwindInstructionFails) {
  if (!GWPSAN_X64)
    GTEST_SKIP() << "test does not make sense on !x86";
  if (!ResetBreakManager(Breakpoint::kModeRequireKernel))
    GTEST_SKIP() << "kernel breakpoints are not supported";
  struct timespec tp;
  auto* bp = mgr()->Watch({Breakpoint::Type::kReadWrite, &tp, ByteSize(1)});

  Expect({
      .method = Method::kOnBreak,
      .bpinfo = {Breakpoint::Type::kReadWrite, &tp, ByteSize(1)},
      .hit_count = 1,
      .on_break_res = true,
  });
  Expect({
      .method = Method::kOnReset,
      .reason = BreakManager::ResetReason::kUnwindInstructionFailed,
      .unwatch = {bp},
  });

  // UnwindInstruction fails on syscall accesses.
  // Use raw syscall to avoid accesses in sanitizer interceptors.
  syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &tp);
}

SAN_NOINLINE extern "C" void EmptyFunc() {
  __atomic_signal_fence(__ATOMIC_SEQ_CST);
}

TEST_F(BreakManagerTest, SingleStep) {
  volatile int data = 0;

  Expect({
      .method = Method::kOnBreak,
      .bpinfo = {Breakpoint::Type::kReadWrite, &data, Sizeof(data)},
      .hit_count = 1,
      .on_break_res = true,
  });
  Expect({
      .method = Method::kOnEmulate,
      // Size of the movl/strb instructions below.
      .on_emulate_pc_off = GWPSAN_X64 ? 6 : 4,
  });
  Expect({
      .method = Method::kOnEmulate,
      .on_emulate_res = reinterpret_cast<uptr>(EmptyFunc),  // next PC to stop
  });
  Expect({
      .method = Method::kOnEmulate,
      .on_emulate_res = 0,
  });

  auto* bp = mgr()->Watch({Breakpoint::Type::kReadWrite, &data, Sizeof(data)});
  // Assembly because we need to know size of the instruction that triggers
  // the breakpoint and need to prevent the compiler from inserting any code
  // between the store and the call.
#if GWPSAN_X64
  asm volatile(
      "movl $1, (%0);\n"
      "callq EmptyFunc;\n" ::"a"(&data));
#elif GWPSAN_ARM64
  asm volatile(
      "strb w0, %0;\n"
      "bl EmptyFunc;\n" ::"m"(data));
#else
#error "unknown arch"
#endif
  mgr()->Unwatch(bp);
}

TEST_F(BreakManagerTest, Reset) {
  volatile int data = 0;

  mgr()->Watch({Breakpoint::Type::kReadWrite, &data, Sizeof(data)});
  BreakManager::singleton().reset();
  data = 1;
}

TEST_F(BreakManagerTest, HitCount) {
  if (GWPSAN_ARM64)
    GTEST_SKIP() << "arm64 does not support multiple hits for a breakpoint";
  volatile int data1 = 0;
  volatile int data2 = 0;
  auto* bp1 =
      mgr()->Watch({Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)});
  auto* bp2 =
      mgr()->Watch({Breakpoint::Type::kReadWrite, &data2, Sizeof(data2)});
  ExpectAccess({Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)}, 1);
  data1 = 1;
  ExpectAccess({Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)}, 2);
  data1 = 1;
  ExpectAccess({Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)}, 3);
  data1 = 1;
  ExpectAccess({Breakpoint::Type::kReadWrite, &data2, Sizeof(data2)}, 1);
  data2 = 1;
  ExpectAccess({Breakpoint::Type::kReadWrite, &data2, Sizeof(data2)}, 2);
  data2 = 1;
  ExpectAccess({Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)}, 4);
  data1 = 1;
  mgr()->Unwatch(bp1);
  mgr()->Unwatch(bp2);
}

TEST_F(BreakManagerTest, OnBreakFails) {
  volatile int data = 0;
  for (uptr i = 0; i < 3; i++) {
    auto* bp =
        mgr()->Watch({Breakpoint::Type::kReadWrite, &data, Sizeof(data)});
    Expect({
        .method = Method::kOnBreak,
        .bpinfo = {Breakpoint::Type::kReadWrite, &data, Sizeof(data)},
        .hit_count = 1,
        .on_break_res = false,
    });
    Expect({
        .method = Method::kOnReset,
        .reason = BreakManager::ResetReason::kOnBreakFailed,
        .unwatch = {bp},
    });
    data = 1;
  }
}

TEST_F(BreakManagerTest, OnThreadExit) {
  ASSERT_TRUE(mgr()->Sample(Milliseconds(1)));
  for (int i = 0; i < 100; i++) {
    std::thread th([&] {
      mgr()->RegisterCurrentThread();
      Expect({
          .method = Method::kOnThreadExit,
          .tid = GetTid(),
      });
    });
    th.join();
  }
}

TEST_F(BreakManagerTest, ThreadOutlivesManager) {
  std::thread th([&] {
    mgr()->RegisterCurrentThread();
    BreakManager::singleton().reset();
  });
  th.join();
}

}  // namespace
}  // namespace gwpsan
