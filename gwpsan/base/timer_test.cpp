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

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/test_signal_listener.h"
#include "gwpsan/base/units.h"

namespace gwpsan {
namespace {

TEST(Timer, GetTime) {
  EXPECT_NE(GetTime(CLOCK_MONOTONIC), Duration());
}

class TimerTest : public ::testing::Test, public TestSignalListener<SIGTRAP> {
 protected:
  static void SleepMillis(int millis) {
    std::this_thread::sleep_for(std::chrono::milliseconds(millis));
  }
};

TEST_F(TimerTest, PosixTimerFiresOnce) {
  bool ok = true;
  PosixTimer timer(ok, SIGTRAP, CLOCK_MONOTONIC);
  ASSERT_TRUE(ok);
  std::atomic<int> fired = 0;
  auto scoped_handler = set_on_signal([&](const siginfo_t& siginfo) {
    if (timer.IsSignal(siginfo))
      fired++;
  });
  ASSERT_TRUE(timer.SetDelay(Milliseconds(1), false));
  while (!fired) {}
  SleepMillis(5);  // Fires again?
  EXPECT_EQ(fired.load(), 1);
}

TEST_F(TimerTest, PosixTimerFiresMultiple) {
  bool ok = true;
  PosixTimer timer(ok, SIGTRAP, CLOCK_MONOTONIC);
  ASSERT_TRUE(ok);
  std::atomic<int> fired = 0;
  auto scoped_handler = set_on_signal([&](const siginfo_t& siginfo) {
    if (timer.IsSignal(siginfo))
      fired++;
  });
  ASSERT_TRUE(timer.SetDelay(Milliseconds(1), true));
  while (fired < 5) {}  // Test will time out on bug.
  EXPECT_GE(fired.load(), 5);
  ASSERT_TRUE(timer.SetDelay(0, false));  // Stop!
  const int exact_fired = fired;
  SleepMillis(5);  // Fires again?
  EXPECT_EQ(exact_fired, fired.load());
}

TEST_F(TimerTest, PosixTimerFork) {
  Optional<PosixTimer> timer;
  ASSERT_TRUE(timer.try_emplace(SIGTRAP, CLOCK_MONOTONIC));
  std::atomic<int> fired = 0;
  auto scoped_handler = set_on_signal([&](const siginfo_t& siginfo) {
    if (timer->IsSignal(siginfo))
      fired++;
  });
  // First try to send signals to child after fork, to test that anything we do
  // after fork() doesn't destroy the parent timer.
  int pid = fork();
  if (!pid) {
    SAN_CHECK_EQ(fired.load(), 0);
    SAN_CHECK(timer->SetDelay(Milliseconds(1), false));
    while (!fired) {}
    exit(0);
  }
  int status = -1;
  waitpid(pid, &status, 0);
  EXPECT_EQ(status, 0);
  EXPECT_EQ(fired.load(), 0);

  // Check that the parent timer still works.
  ASSERT_TRUE(timer->SetDelay(Milliseconds(1), false));
  while (!fired) {}
  EXPECT_EQ(fired.load(), 1);
}

TEST_F(TimerTest, PosixTimerTargetsThread) {
  std::atomic<bool> stop = false;
  std::atomic<int> tid = 0;
  std::thread t([&] {
    tid = GetTid();
    while (!stop)
      std::this_thread::yield();
  });
  while (!tid)
    std::this_thread::yield();

  bool ok = true;
  PosixTimer timer(ok, SIGTRAP, CLOCK_MONOTONIC, tid);
  ASSERT_TRUE(ok);
  std::atomic<int> fired_in = 0;
  auto scoped_handler = set_on_signal([&](const siginfo_t& siginfo) {
    if (timer.IsSignal(siginfo))
      fired_in += GetTid();
  });
  ASSERT_TRUE(timer.SetDelay(Milliseconds(1), true));
  while (!fired_in)
    SleepMillis(1);
  EXPECT_EQ(fired_in.load() % tid, 0);

  stop = true;
  t.join();
}

TEST_F(TimerTest, PosixTimerTargetsNonExistentThread) {
  std::atomic<int> tid = 0;
  std::thread t([&] { tid = GetTid(); });
  while (!tid)
    std::this_thread::yield();
  t.join();
  while (GetThreadState(tid).has_value()) {
    // Wait for kernel to clean it up.
    SleepMillis(1);
  }
  bool ok = true;
  PosixTimer timer(ok, SIGTRAP, CLOCK_MONOTONIC, tid);
  ASSERT_FALSE(ok);
}

TEST_F(TimerTest, PosixTimerTargetsDeadThread) {
  std::atomic<bool> stop = false;
  std::atomic<int> tid = 0;
  std::thread t([&] {
    tid = GetTid();
    while (!stop)
      std::this_thread::yield();
  });
  while (!tid)
    std::this_thread::yield();

  bool ok = true;
  PosixTimer timer(ok, SIGTRAP, CLOCK_MONOTONIC, tid);
  ASSERT_TRUE(ok);
  std::atomic<int> fired = 0;
  auto scoped_handler = set_on_signal([&](const siginfo_t& siginfo) {
    if (timer.IsSignal(siginfo))
      fired++;
  });
  ASSERT_TRUE(timer.SetDelay(Milliseconds(1), false));
  while (!fired) {}
  stop = true;
  t.join();
  while (GetThreadState(tid).has_value()) {
    // Wait for kernel to clean it up.
    SleepMillis(1);
  }
  fired = 0;
  ASSERT_TRUE(timer.SetDelay(Milliseconds(1), true));
  SleepMillis(5);
  // On Linux at least, a POSIX timer will stop firing if its thread exits, i.e.
  // there's no fallback thread.
  EXPECT_EQ(fired.load(), 0);
}

TEST_F(TimerTest, SampleTimerFiresMultiple) {
  bool ok = true;
  SampleTimer timer(ok);
  ASSERT_TRUE(ok);
  std::atomic<int> fired = 0;
  auto scoped_handler = set_on_signal([&](const siginfo_t& siginfo) {
    if (timer.IsSignal(siginfo) == SampleTimer::EventType::kSample)
      fired++;
  });
  ASSERT_TRUE(timer.SetDelay(Milliseconds(1)));
  while (fired < 5) {}  // Test will time out on bug.
  EXPECT_GE(fired.load(), 5);
}

TEST_F(TimerTest, SampleTimerThreadDistribution) {
  thread_local int thread_index = -1;
  constexpr int kNumThreads = 100;
  bool ok = true;
  SampleTimer timer(ok);
  ASSERT_TRUE(ok);

  std::deque<std::atomic<int>> thread_fired;
  std::vector<std::thread> threads;
  thread_fired.resize(kNumThreads);
  threads.reserve(kNumThreads);
  std::atomic<int> total_done = 0;
  for (int t = 0; t < kNumThreads; ++t) {
    threads.emplace_back([&, idx = t] {
      thread_index = idx;
      std::atomic_signal_fence(std::memory_order_seq_cst);
      while (thread_fired.at(idx) < 3) {}
      total_done++;
      // Keep busy spinning to collect samples.
      while (total_done != kNumThreads) {}
    });
  }
  auto scoped_handler = set_on_signal([&](const siginfo_t& siginfo) {
    if (timer.IsSignal(siginfo) != SampleTimer::EventType::kSample)
      return;
    if (thread_index == -1)
      return;
    thread_fired.at(thread_index)++;
  });
  ASSERT_TRUE(timer.SetDelay(Milliseconds(1)));
  for (auto& t : threads)
    t.join();
}

// Test that an idle process is not woken up unnecessarily.
TEST_F(TimerTest, SampleTimerIdle) {
  bool ok = true;
  SampleTimer timer(ok);
  ASSERT_TRUE(ok);

  std::atomic<int> fired = 0;
  auto scoped_handler = set_on_signal([&](const siginfo_t& siginfo) {
    if (timer.IsSignal(siginfo) != SampleTimer::EventType::kNone)
      fired++;
  });
  ASSERT_TRUE(timer.SetDelay(Milliseconds(1)));
  for (int i = 0; i < 500; ++i)
    SleepMillis(1);
  // Should fire rarely, and if it does, much much less than sleep/interval.
  EXPECT_LT(fired, 30);
}

}  // namespace
}  // namespace gwpsan
