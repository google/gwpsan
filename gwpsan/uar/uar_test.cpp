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

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

#include <chrono>
#include <functional>
#include <thread>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/test_report_interceptor.h"
#include "gwpsan/base/unwind.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/semantic_metadata.h"

extern "C" bool gwpsan_get_stack_limits(uintptr_t* lo, uintptr_t* hi);

namespace gwpsan {

DECLARE_METRIC(gwpsan_tools);

bool IsOnTheSecondStack();

const char* DefaultFlags() {
  return "uar";
}

namespace {

SAN_NOINLINE void Escape(const volatile void* ptr) {
  static SAN_UNUSED const volatile void* volatile sink;
  sink = ptr;
}

SAN_NOINLINE bool SwitchingFunction(std::function<void()> const& body) {
  int escaping = 0;
  Escape(&escaping);
  if (!IsOnTheSecondStack())
    return false;
  body();
  return true;
}

SAN_NOINLINE void OnTheSecondStack(std::function<void()> const& body) {
  while (!SwitchingFunction(body)) {}
}

bool HasSigAltStack() {
  stack_t ss = {};
  if (SAN_WARN(sigaltstack(nullptr, &ss)))
    return false;
  return !(ss.ss_flags & SS_DISABLE);
}

void SetupSigAltStack() {
  if (HasSigAltStack())
    return;

  static thread_local char stack[64 << 10];
  stack_t ss = {
      .ss_sp = stack,
      .ss_size = sizeof(stack),
  };
  ASSERT_EQ(0, sigaltstack(&ss, nullptr));
}

SAN_NOINLINE SAN_NOINSTR int* BasicStackLeak() {
  int x = 0;
  int* volatile p = &x;
  return p;
}

SAN_NOINLINE SAN_NOINSTR void BasicUse() {
  int* p = BasicStackLeak();
  *p = 1;
}

TEST(UAR, SingleTool) {
  // Check that for this test suite only UAR is enabled.
  ASSERT_EQ(metric_gwpsan_tools.value(), 1);
}

TEST(UAR, SwitchingFunction) {
  // Ensure that SwitchingFunction is indeed switching,
  // otherwise subsequent tests will hang trying to switch in it.
  // It's better to hang here.
  // Note: IsUARFunctionStart can fail spuriously, so need to loop.
  while (!IsUARFunctionStart(reinterpret_cast<uptr>(SwitchingFunction))) {}
}

SAN_NOINLINE SAN_NOINSTR void Infinite() {
  static volatile bool yes = true;
  if (yes)
    Infinite();
  SAN_BARRIER();
}

auto stack_overflow_matcher =
    AllOf(testing::HasSubstr("GWPSan: access to the stack guard page"),
          Not(testing::HasSubstr("GWPSan: use-after-return")));

TEST(UAR, StackOverflow) {
  EXPECT_DEATH(({
                 SetupSigAltStack();
                 Infinite();
               }),
               stack_overflow_matcher);
}

TEST(UAR, StackOverflowOnTheSecondStack) {
  EXPECT_DEATH(({
                 SetupSigAltStack();
                 OnTheSecondStack(Infinite);
               }),
               stack_overflow_matcher);
}

TEST(UAR, StackOverflowInThread) {
  EXPECT_DEATH(({
                 std::thread th([]() {
                   SetupSigAltStack();
                   Infinite();
                 });
                 th.join();
               }),
               stack_overflow_matcher);
}

TEST(UAR, StackOverflowInThreadOnTheSecondStack) {
  EXPECT_DEATH(({
                 std::thread th([]() {
                   SetupSigAltStack();
                   OnTheSecondStack(Infinite);
                 });
                 th.join();
               }),
               stack_overflow_matcher);
}

TEST(UAR, Basic) {
  ExpectReport(BasicUse, R"([[MARKER]]
WARNING: GWPSan: use-after-return in gwpsan::(anonymous namespace)::BasicUse() (pid=[[NUM]])
    #0: [[MODULE]] gwpsan::(anonymous namespace)::BasicUse()
    [[SKIP-LINES]]
    #[[NUM]]: [[MODULE]] main

The variable was allocated within:
    #0: [[MODULE]] gwpsan::(anonymous namespace)::BasicStackLeak()
    [[SKIP-LINES]]
    #[[NUM]]: [[MODULE]] main

Access address:  [[ADDR]]
Current SP:      [[ADDR]]
Main stack:      [[ADDR]]-[[ADDR]]
Second stack:    [[ADDR]]-[[ADDR]]
[[MARKER]])");
}

SAN_NOINLINE SAN_NOINSTR int* TailStackLeak() {
  SAN_BARRIER();
  SAN_MUSTTAIL return BasicStackLeak();
}

SAN_NOINLINE SAN_NOINSTR void TailUse() {
  int* p = TailStackLeak();
  *p = 1;
}

TEST(UAR, TailCall) {
  ExpectReport(
      TailUse,
      R"(WARNING: GWPSan: use-after-return in gwpsan::(anonymous namespace)::TailUse())");
}

SAN_NOINLINE void BasicThread() {
  BasicUse();
  SAN_BARRIER();
}

TEST(UAR, NonMainThread) {
  ReportInterceptor report_interceptor;
  std::thread th([&report_interceptor]() {
    using clock = std::chrono::high_resolution_clock;
    const auto start = clock::now();
    while (report_interceptor.Empty() &&
           clock::now() - start < std::chrono::seconds{100}) {
      for (int i = 0; i < 10; i++)
        BasicThread();
    }
  });
  th.join();
  report_interceptor.ExpectPartial(R"([[MARKER]]
WARNING: GWPSan: use-after-return in gwpsan::(anonymous namespace)::BasicUse() (pid=[[NUM]])
    #0: [[MODULE]] gwpsan::(anonymous namespace)::BasicUse()
    #1: [[MODULE]] gwpsan::(anonymous namespace)::BasicThread()
[[SKIP-LINES]]
The variable was allocated within:
    #0: [[MODULE]] gwpsan::(anonymous namespace)::BasicStackLeak()
    #1: [[MODULE]] gwpsan::(anonymous namespace)::BasicUse()
    #2: [[MODULE]] gwpsan::(anonymous namespace)::BasicThread()
[[SKIP-LINES]]
Access address:  [[ADDR]]
Current SP:      [[ADDR]]
Main stack:      [[ADDR]]-[[ADDR]]
Second stack:    [[ADDR]]-[[ADDR]]
[[MARKER]])");
}

TEST(UAR, ThreadReuse) {
  // Pthread can reuse a bit larger stack of a finished thread for a new
  // thread that asked for a bit smaller stack. Ensure that we handle this.
  ReportInterceptor report_interceptor;
  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setstacksize(&attr, 256 << 10));
  pthread_t th;
  const auto empty_func = +[](void*) -> void* { return nullptr; };
  ASSERT_EQ(0, pthread_create(&th, &attr, empty_func, nullptr));
  ASSERT_EQ(0, pthread_join(th, nullptr));
  ASSERT_EQ(0, pthread_attr_setstacksize(&attr, 224 << 10));
  const auto thread_func = +[](void* arg) -> void* {
    using clock = std::chrono::high_resolution_clock;
    const auto start = clock::now();
    auto& report_interceptor = *static_cast<ReportInterceptor*>(arg);
    while (report_interceptor.Empty() &&
           clock::now() - start < std::chrono::seconds{100}) {
      for (int i = 0; i < 10; i++)
        BasicThread();
    }
    return nullptr;
  };
  ASSERT_EQ(0, pthread_create(&th, &attr, thread_func, &report_interceptor));
  ASSERT_EQ(0, pthread_join(th, nullptr));
  ASSERT_EQ(0, pthread_attr_destroy(&attr));
  report_interceptor.ExpectPartial(
      "GWPSan: use-after-return in gwpsan::(anonymous "
      "namespace)::BasicUse()");
}

SAN_NOINLINE void CallUnwind(ArrayVector<uptr, 32>& stack) {
  stack.resize(stack.capacity());
  stack.resize(RawUnwindStack(stack).size());
  SAN_BARRIER();
}

TEST(UAR, Unwind) {
  ArrayVector<uptr, 32> stack;
  OnTheSecondStack([&]() { CallUnwind(stack); });
  ReportInterceptor interceptor;
  PrintStackTrace(stack);
  interceptor.ExpectPartial(
      R"([[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan::(anonymous namespace)::CallUnwind()
[[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan::(anonymous namespace)::SwitchingFunction()
[[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan_uar_switch_stack
[[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan::(anonymous namespace)::OnTheSecondStack()
[[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan::(anonymous namespace)::UAR_Unwind_Test::TestBody()
)");
  interceptor.ExpectPartial("[[MODULE]] main");
}

TEST(UAR, UnwindInThread) {
  ArrayVector<uptr, 32> stack;
  std::thread th([&]() { OnTheSecondStack([&]() { CallUnwind(stack); }); });
  th.join();
  ReportInterceptor interceptor;
  PrintStackTrace(stack);
  interceptor.ExpectPartial(
      R"([[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan::(anonymous namespace)::CallUnwind()
[[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan::(anonymous namespace)::SwitchingFunction()
[[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan_uar_switch_stack
[[SKIP-LINES]]#[[NUM]]: [[MODULE]] gwpsan::(anonymous namespace)::OnTheSecondStack()
)");
}

void CheckStackLimits(size_t expect_lo, size_t expect_hi) {
  uintptr_t stack_lo, stack_hi;
  SAN_CHECK(gwpsan_get_stack_limits(&stack_lo, &stack_hi));
  size_t stack_size = stack_hi - stack_lo;
  uptr sp = SAN_CURRENT_FRAME();
  fprintf(stderr, "stack: 0x%zx-0x%zx (0x%zx) sp:0x%zx\n", stack_lo, stack_hi,
          stack_size, sp);
  SAN_CHECK_GT(sp, stack_lo);
  SAN_CHECK_LT(sp, stack_hi);
  SAN_CHECK_GE(stack_size, expect_lo);
  SAN_CHECK_LE(stack_size, expect_hi);
  if (!IsOnTheSecondStack())
    OnTheSecondStack([=]() { CheckStackLimits(expect_lo, expect_hi); });
}

void CheckUnchecked() {
  uintptr_t stack_lo, stack_hi;
  SAN_CHECK(!gwpsan_get_stack_limits(&stack_lo, &stack_hi));
}

constexpr uptr kGoodStackSize = 1 << 20;

int StackLimitsSubprocess(bool checked) {
  if (checked)
    CheckStackLimits(kGoodStackSize, kGoodStackSize);
  else
    CheckUnchecked();
  fprintf(stderr, "%s\n", __func__);
  return 0;
}

TEST(UAR, StackLimits) {
  // Use odd stack size that is smaller and larger than the default.
  // Pthread may reuse stacks and these sizes may give different effects.
  const uptr stack_sizes[] = {kGoodStackSize, 387451, 15577311};
  for (auto stack_size : stack_sizes) {
    const bool checked = stack_size == kGoodStackSize;
    struct rlimit rl;
    ASSERT_EQ(getrlimit(RLIMIT_STACK, &rl), 0);
    struct rlimit rl_new = rl;
    rl_new.rlim_cur = stack_size;
    ASSERT_EQ(setrlimit(RLIMIT_STACK, &rl_new), 0);
    // We need to exec() to apply the new stack limits.
    EXPECT_EXIT(execl("/proc/self/exe", "uar_test",
                      checked ? "StackLimits_checked" : "StackLimits_unchecked",
                      nullptr),
                testing::ExitedWithCode(0), "StackLimitsSubprocess")
        << "stack_size=" << stack_size;
    ASSERT_EQ(setrlimit(RLIMIT_STACK, &rl), 0);

    pthread_attr_t attr;
    ASSERT_EQ(pthread_attr_init(&attr), 0);
    ASSERT_EQ(pthread_attr_setstacksize(&attr, stack_size), 0);
    pthread_t th;
    // Threads are unchecked when an odd stack size is used.
    auto fn = checked ? +[](void* arg) -> void* {
      CheckStackLimits(kGoodStackSize, kGoodStackSize);
      return nullptr;
    }
    : +[](void* arg) -> void* {
        CheckUnchecked();
        return nullptr;
      };
    ASSERT_EQ(pthread_create(&th, &attr, fn, nullptr), 0);
    ASSERT_EQ(pthread_join(th, nullptr), 0);
    ASSERT_EQ(pthread_attr_destroy(&attr), 0);
  }

  // Test the default stack size.
  CheckStackLimits(16 << 10, 16 << 20);
}

TEST(UAR, LotsOfThreads) {
  // A stress test that creates lots of threads. In particular this tests our
  // handling of thread creation in presence of (our own) signals.
  std::vector<std::thread> threads;
  for (int i = 0; i < 10; i++) {
    threads.emplace_back([]() {
      for (int i = 0; i < 5000; i++) {
        std::thread th([]() {});
        th.join();
      }
    });
  }
  for (auto& th : threads)
    th.join();
}

}  // namespace
}  // namespace gwpsan

int main(int argc, char** argv) {
  if (argc == 2) {
    if (!strcmp(argv[1], "StackLimits_checked"))
      return gwpsan::StackLimitsSubprocess(true);
    else if (!strcmp(argv[1], "StackLimits_unchecked"))
      return gwpsan::StackLimitsSubprocess(false);
  }

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
