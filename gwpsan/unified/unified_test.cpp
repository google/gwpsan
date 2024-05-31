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

// Test that the unified tool finds each bug class with _all_ tools enabled.
// More rigorous tests for each tool are separate, to keep test time acceptable.

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <chrono>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/test_report_interceptor.h"

extern "C" void gwpsan_early_log() {}

namespace gwpsan {

DECLARE_METRIC(tsan_data_races);

// Enable all tools at once.
const char* DefaultFlags() {
  return "check_malloc:peek_instructions=100:tsan:lmsan:uar";
}

namespace {
alignas(64) volatile u64 test_data;

template <typename Arg>
SAN_NOINLINE SAN_OPTNONE void TestSink(Arg v) {
  SAN_BARRIER();
}

SAN_NOINLINE void TestAccessWrite() {
  test_data = 42;
}

void WriteWriteRace() {
  ReportInterceptor report_interceptor;

  auto thread = [old_data_races = metric_tsan_data_races.value()] {
    using std::chrono::high_resolution_clock;
    const auto start = high_resolution_clock::now();
    // It can take longer to find the data race with all tools enabled.
    while (metric_tsan_data_races.value() == old_data_races &&
           high_resolution_clock::now() - start < std::chrono::seconds(100)) {
      for (unsigned i = 0; i < 10000; i++)
        TestAccessWrite();
    }
  };

  std::vector<std::thread> threads;
  threads.reserve(10);
  for (int i = 0; i < 10; ++i)
    threads.emplace_back(thread);
  for (auto& t : threads)
    t.join();

  report_interceptor.ExpectReport(R"([[MARKER]]
WARNING: GWPSan: data-race in gwpsan::(anonymous namespace)::TestAccessWrite() / gwpsan::(anonymous namespace)::TestAccessWrite() (pid=[[NUM]])
  Write of size 8 at [[ADDR]] by thread T[[NUM]]:
    #0: [[MODULE]] gwpsan::(anonymous namespace)::TestAccessWrite()
[[SKIP-LINES]]
  Write of size 8 at [[ADDR]] by thread T[[NUM]]:
    #0: [[MODULE]] gwpsan::(anonymous namespace)::TestAccessWrite()
[[SKIP-LINES]][[MARKER]]
)");
}

TEST(UnifiedTool, WriteWriteRace) {
  WriteWriteRace();
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

TEST(UnifiedTool, UAR) {
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

TEST(UnifiedTool, Seccomp) {
  auto seccomp_and_exec = [] {
    EXPECT_TRUE(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    struct sock_filter filter[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = 1,
        .filter = filter,
    };
    EXPECT_TRUE(!syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog));
    execl("/proc/self/exe", "unified_test", "notests", nullptr);
  };

  EXPECT_DEATH(seccomp_and_exec(),
               "detected incompatible binary: seccomp filter is enabled");
}

SAN_NOINLINE SAN_OPTNONE void UseOfHeapUninit() {
  constexpr uptr kSize = 64;
  volatile void* volatile p = malloc(kSize);
  TestSink(memchr(const_cast<void*>(p), 0xe1, kSize));
  free(const_cast<void*>(p));
}

TEST(UnifiedTool, LMSanHeap) {
  if (GWPSAN_INSTRUMENTED_MSAN)
    GTEST_SKIP() << "MSan will detect uninits ahead of us";
  // Note: memchr symbol may look like __memchr_avx2/sse2, or due to other
  // trickery may not even be symbolizable.
  ExpectReport(UseOfHeapUninit, R"([[MARKER]]
WARNING: GWPSan: use-of-uninit in [[ANY]] (pid=[[NUM]])
    #0: [[MODULE]] [[ANY]]
    [[SKIP-LINES]]
    #[[NUM]]: [[MODULE]] main
[[MARKER]])");
}

SAN_NOINLINE void UseOfStackUninit() {
  constexpr uptr kSize = 64;
  volatile char buf[kSize];
  (void)write(-1, const_cast<char*>(buf), sizeof(buf));
}

TEST(UnifiedTool, LMSanStack) {
  if (GWPSAN_INSTRUMENTED_MSAN)
    GTEST_SKIP() << "MSan will detect uninits ahead of us";
  if (GWPSAN_INSTRUMENTED_ASAN)
    GTEST_SKIP() << "ASan uses fake stack which we won't spray";
  ExpectReport(UseOfStackUninit, R"([[MARKER]]
WARNING: GWPSan: use-of-uninit in write (pid=[[NUM]])
    #0: [[MODULE]] write
    [[SKIP-LINES]]
    #[[NUM]]: [[MODULE]] main
[[MARKER]])");
}

TEST(UnifiedTool, ForkAndRace) {
  const auto fork_and_race = [] {
    const int pid = fork();
    if (!pid) {
      WriteWriteRace();
      _exit(0);
    }
    int wstatus;
    while (pid != waitpid(pid, &wstatus, 0)) {}
    _exit(1);
  };
  EXPECT_DEATH(fork_and_race(), "WARNING: GWPSan: data-race in");
}

}  // namespace
}  // namespace gwpsan

int main(int argc, char** argv) {
  if (argc == 2 && !strcmp(argv[1], "notests"))
    return 1;

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
