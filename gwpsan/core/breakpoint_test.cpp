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

#include "gwpsan/core/breakpoint.h"

#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <thread>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/base/test_signal_listener.h"
#include "gwpsan/base/units.h"

namespace gwpsan {
namespace {

class BreakpointTest : public testing::Test,
                       public TestSignalListener<SIGTRAP> {
 protected:
  std::array<Breakpoint, 2> bps_;

  void Expect(Breakpoint* bp, Breakpoint::Info bpinfo) {
    // Without this the compiler does not expect that OnSignal can reset
    // expected_bp_ and falsely fails below.
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    EXPECT_EQ(expected_bp_, nullptr);
    expected_bp_ = bp;
    expected_ = bpinfo;
  }

  void IgnoreAllBreakpoints() {
    ignore_all_ = true;
  }

 private:
  Breakpoint* expected_bp_ = nullptr;
  Breakpoint::Info expected_;
  bool ignore_all_ = false;

  // Constructed last and destroyed first.
  ScopedSignalHandler scoped_handler =
      set_on_signal([this](const siginfo_t& siginfo) {
        if (ignore_all_)
          return;
        EXPECT_NE(expected_bp_, nullptr);
        const auto minfo = Breakpoint::ExtractMatchInfo(SIGTRAP, siginfo);
        EXPECT_TRUE(expected_bp_->Match(minfo));
        EXPECT_EQ(expected_bp_->bpinfo(), expected_);
        for (auto& bp : bps_) {
          if (&bp != expected_bp_)
            EXPECT_FALSE(bp.Match(minfo));
        }
        // TODO(dvyukov): work-around for broken arm64 breakpoints.
        // If we don't disable the breakpoint before returning from the handler,
        // the process will hang. Remove when arm64 breakpoints are fixed.
        if (GWPSAN_ARM64)
          expected_bp_->Disable();
        expected_bp_ = nullptr;
      });

  void SetUp() override {
    EXPECT_EQ(expected_bp_, nullptr);
  }

  void TearDown() override {
    EXPECT_EQ(expected_bp_, nullptr);
  }
};

namespace {
template <int i>
SAN_NOINLINE int EmptyFunc() {
  __atomic_signal_fence(__ATOMIC_SEQ_CST);
  return i;
}
}  // namespace

// Test for async SIGTRAP support regression.
TEST(Breakpoint, AsyncSigtrap) {
  pid_t pid = fork();
  ASSERT_GE(pid, 0);

  if (pid == 0) {
    struct sigaction act = {};
    act.sa_handler = SIG_IGN;
    if (!Sigaction(SIGTRAP, &act, nullptr))
      sys_exit_group(1);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTRAP);
    if (sigprocmask(SIG_BLOCK, &set, nullptr))
      sys_exit_group(2);
    Breakpoint bp;
    if (!bp.Init(0))
      sys_exit_group(3);
    volatile int trap;
    if (!bp.Enable(Breakpoint::Info{Breakpoint::Type::kReadWrite, &trap,
                                    Sizeof(trap)}))
      sys_exit_group(4);
    trap = 1;
    bp.Disable();
    sys_exit_group(0);
  }

  int wstatus = 0;
  while (sys_wait4(pid, &wstatus, 0, nullptr).val_or(0) != pid) {}
  if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0)
    FAIL() << "async SIGTRAP not detected - kernel bug?";
}

TEST_F(BreakpointTest, Basic) {
  if (GWPSAN_ARM64)
    GTEST_SKIP() << "broken on arm64";
  volatile u16 data1 = 0;
  volatile char data2 = 0;
  EXPECT_FALSE(bps_[0].Inited());
  EXPECT_TRUE(bps_[0].Init(0));
  EXPECT_TRUE(bps_[0].Inited());
  EXPECT_TRUE(bps_[1].Init(0));
  EXPECT_FALSE(bps_[0].Enabled());
  ASSERT_TRUE(
      !!bps_[0].Enable({Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)}));
  EXPECT_TRUE(bps_[0].Enabled());
  ASSERT_TRUE(
      !!bps_[1].Enable({Breakpoint::Type::kReadWrite, &data2, Sizeof(data2)}));
  Expect(&bps_[0], {Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)});
  data1 = 1;
  Expect(&bps_[0], {Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)});
  data1 = 1;
  bps_[0].Disable();
  data1 = 1;
  data1 = 1;
  bps_[1].Disable();
  data2 = 1;
  ASSERT_TRUE(
      !!bps_[0].Enable({Breakpoint::Type::kWriteOnly, &data2, Sizeof(data2)}));
  Expect(&bps_[0], {Breakpoint::Type::kWriteOnly, &data2, Sizeof(data2)});
  data1 = 1;
  data2 = 1;
  bps_[0].Disable();
  data1 = 1;
  data2 = 1;
  ASSERT_TRUE(
      !!bps_[0].Enable({Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)}));
  ASSERT_FALSE(bps_[0].Enable(
      {Breakpoint::Type::kReadWrite, Addr(0x8080808012345678ul), ByteSize(1)}));
  data1 = 1;
  ASSERT_TRUE(
      !!bps_[0].Enable({Breakpoint::Type::kReadWrite, &data1, Sizeof(data1)}));
#if GWPSAN_DEBUG
  bps_[0].Disable();
  ASSERT_DEATH((void)bps_[0].Enable(
                   {Breakpoint::Type::kReadWrite, &data1, ByteSize(~0ul)}),
               "bad breakpoint size");
#else
  ASSERT_FALSE(
      !!bps_[0].Enable({Breakpoint::Type::kReadWrite, &data1, ByteSize(~0ul)}));
#endif
  data1 = 1;
}

TEST_F(BreakpointTest, Code) {
  ASSERT_TRUE(bps_[0].Init(0));
  ASSERT_TRUE(!!bps_[0].Enable({Breakpoint::Type::kCode, &EmptyFunc<0>}));
  Expect(&bps_[0], {Breakpoint::Type::kCode, &EmptyFunc<0>});
  EmptyFunc<0>();
}

TEST_F(BreakpointTest, NoKernel) {
  ASSERT_TRUE(bps_[0].Init(0));
  struct stat buf;
  ASSERT_TRUE(!!bps_[0].Enable(
      {Breakpoint::Type::kReadWrite, &buf.st_mode, Sizeof(buf.st_mode)}));
  ASSERT_EQ(0, stat("/dev/null", &buf));
  bps_[0].Close();
}

TEST_F(BreakpointTest, Kernel) {
  if (GWPSAN_ARM64)
    GTEST_SKIP() << "broken on arm64";
  if (!bps_[1].Init(Breakpoint::kModeRequireKernel))
    GTEST_SKIP() << "perf_event_open does not support kernel";
  struct stat buf;
  ASSERT_TRUE(!!bps_[1].Enable(
      {Breakpoint::Type::kReadWrite, &buf.st_mode, Sizeof(buf.st_mode)}));
  Expect(&bps_[1],
         {Breakpoint::Type::kReadWrite, &buf.st_mode, Sizeof(buf.st_mode)});
  ASSERT_EQ(0, stat("/dev/null", &buf));
  bps_[1].Close();
}

TEST_F(BreakpointTest, PerThread) {
  ASSERT_TRUE(bps_[0].Init(Breakpoint::kModePerThread));
  volatile int data = 0;
  ASSERT_TRUE(
      !!bps_[0].Enable({Breakpoint::Type::kReadWrite, &data, Sizeof(data)}));
  std::thread th([&]() { data = 1; });
  th.join();
  bps_[0].Close();
}

TEST_F(BreakpointTest, Threads) {
  if (!bps_[0].Init(0))
    GTEST_SKIP() << "perf_event_open does not support threads/sigtrap";
  volatile int data = 0;
  ASSERT_TRUE(
      !!bps_[0].Enable({Breakpoint::Type::kReadWrite, &data, Sizeof(data)}));
  Expect(&bps_[0], {Breakpoint::Type::kReadWrite, &data, Sizeof(data)});
  std::thread th([&]() { data = 1; });
  th.join();
  bps_[0].Close();
}

TEST_F(BreakpointTest, Overlapping) {
  ASSERT_TRUE(bps_[0].Init(0));
  volatile char data[24];
  ASSERT_TRUE(
      !!bps_[0].Enable({Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)}));
  // Just in case: these must not fire.
  reinterpret_cast<volatile u64&>(data[0]) = 1;
  reinterpret_cast<volatile u32&>(data[4]) = 1;
  reinterpret_cast<volatile u8&>(data[7]) = 1;
  reinterpret_cast<volatile u8&>(data[12]) = 1;
  reinterpret_cast<volatile u32&>(data[12]) = 1;
  for (uptr i = 1; i < 12; i++) {
    // Note: need to re-enable on every iteration because of arm64
    // resetting breakpoints after first trigger.
    ASSERT_TRUE(!!bps_[0].Enable(
        {Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)}));
    Expect(&bps_[0], {Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)});
    reinterpret_cast<volatile u64&>(data[i]) = 1;
  }
  for (uptr i = 5; i < 12; i++) {
    ASSERT_TRUE(!!bps_[0].Enable(
        {Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)}));
    Expect(&bps_[0], {Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)});
    reinterpret_cast<volatile u32&>(data[i]) = 1;
  }
  for (uptr i = 7; i < 12; i++) {
    ASSERT_TRUE(!!bps_[0].Enable(
        {Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)}));
    Expect(&bps_[0], {Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)});
    reinterpret_cast<volatile u16&>(data[i]) = 1;
  }
  for (uptr i = 8; i < 12; i++) {
    ASSERT_TRUE(!!bps_[0].Enable(
        {Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)}));
    Expect(&bps_[0], {Breakpoint::Type::kReadWrite, &data[8], ByteSize(4)});
    reinterpret_cast<volatile u8&>(data[i]) = 1;
  }
  bps_[0].Close();
}

TEST_F(BreakpointTest, Spawn) {
  // The test tests that async SIGTRAP works with spawn. sigprocmask(SIG_BLOCK)
  // is in posix_spawn and in a number of other similar implementations.
  IgnoreAllBreakpoints();
  if (!bps_[0].Init(0))
    GTEST_SKIP() << "perf_event_open does not support "
                    "attr.inherit_thread/remove_on_exec";
  for (uptr offset = 0; offset < 1024; offset++) {
    ASSERT_TRUE(!!bps_[0].Enable(
        {Breakpoint::Type::kReadWrite, &offset - offset, Sizeof(offset)}));
    pid_t pid;
    char* const argv[] = {const_cast<char*>("true"), nullptr};
    char* const envp[] = {nullptr};
    ASSERT_TRUE(!posix_spawnp(&pid, argv[0], nullptr, nullptr, argv, envp));
    int wstatus;
    while (pid != waitpid(pid, &wstatus, 0)) {}
    ASSERT_TRUE(WIFEXITED(wstatus));
    ASSERT_EQ(WEXITSTATUS(wstatus), 0);
  }
}

}  // namespace
}  // namespace gwpsan
