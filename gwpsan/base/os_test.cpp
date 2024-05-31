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

#include "gwpsan/base/os.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/base/timer.h"
#include "gwpsan/base/units.h"

namespace gwpsan {
namespace {

const std::string& GetTmpdir() {
  static auto ret = []() -> std::string {
    // If running under Bazel, use provided temp directory.
    const char* tmpdir = getenv("TEST_TMPDIR");
    return tmpdir ? tmpdir : "/tmp";
  }();
  return ret;
}

TEST(OS, ReadFile) {
  // Write a temp file and then read it back with ReadFile.
  const auto filename = GetTmpdir() + "/file";
  auto fd = sys_openat(AT_FDCWD, filename.c_str(), O_CREAT | O_WRONLY, 0600);
  ASSERT_TRUE(!!fd);
  std::string data = "some data";
  auto wres = sys_write(fd.val(), data.c_str(), data.size());
  ASSERT_TRUE(!!wres);
  ASSERT_EQ(wres.val(), data.size());
  auto cres = sys_close(fd.val());
  ASSERT_TRUE(!!cres);

  // Read the whole file.
  char buf[128];
  auto rres = ReadFile(filename.c_str(), {buf, data.size() + 1});
  ASSERT_TRUE(!!rres);
  ASSERT_EQ(rres.val(), data.size());
  ASSERT_TRUE(std::string(buf, rres.val()) == data);

  // Read part of the file.
  rres = ReadFile(filename.c_str(), {buf, data.size()});
  ASSERT_TRUE(!!rres);
  ASSERT_EQ(rres.val(), data.size() - 1);
  ASSERT_TRUE(std::string(buf, rres.val()) == data.substr(0, rres.val()));
  ASSERT_EQ(buf[rres.val()], 0);

  rres = ReadFile(filename.c_str(), {buf, 1});
  ASSERT_TRUE(!!rres);
  ASSERT_EQ(rres.val(), 0);
  ASSERT_EQ(buf[0], 0);
}

TEST(OS, GetEnv) {
  char buf[512];
  int found = 0;
  int not_found = 0;

  auto check_getenv = [&](const char* var) {
    const char* expect = getenv(var);
    memset(buf, 1, sizeof(buf));
    if (expect) {
      found++;
      EXPECT_TRUE(GetEnv(var, buf)) << var;
      EXPECT_STREQ(expect, buf) << var;
    } else {
      not_found++;
      EXPECT_FALSE(GetEnv(var, buf)) << var;
      // Returns empty string if var does not exist.
      EXPECT_EQ(buf[0], 0) << var;
    }
  };

  check_getenv("GWPSAN_DOES_NOT_EXIST");
  check_getenv("GWPSAN_GETENV_TEST_EMPTY");
  check_getenv("GWPSAN_GETENV_TEST_NONEMPTY");
  check_getenv("HISTCONTROL");  // usually empty
  check_getenv("HOME");
  check_getenv("LANG");
  check_getenv("SHELL");
  check_getenv("TERM");
  check_getenv("USER");
  check_getenv("_");

  // Check that we covered both existing and non-existing vars.
  EXPECT_NE(found, 0);
  EXPECT_NE(not_found, 0);
}

TEST(OS, ReadProcessName) {
  char process[1024];
  ASSERT_TRUE(ReadProcessName(process));
  EXPECT_TRUE(internal_strstr(process, "base_test"));
}

TEST(OS, GetThreadState) {
  // Just check that it does not fail for this thread. The state is not
  // guaranteed to be running if we read from the /proc file.
  EXPECT_TRUE(GetThreadState(GetTid()));
}

TEST(OS, GetNumCPUs) {
  // Our implementation should match the "online CPUs" sysconf.
  EXPECT_EQ(GetNumCPUs(), sysconf(_SC_NPROCESSORS_ONLN));

  const auto readfile_fail_mock = [](const char*, Span<char>) {
    return Result<uptr>(-ENOENT);
  };
  SetReadFileMock({readfile_fail_mock});
  EXPECT_EQ(GetNumCPUs(), 1);

  const char* online_cpus;
  const auto readfile_mock = [&](const char* path, Span<char> buf) {
    SAN_CHECK(!internal_strcmp(path, "/sys/devices/system/cpu/online"));
    internal_strncpy(buf.data(), online_cpus, buf.size());
    return Result<uptr>(internal_strlen(online_cpus) + 1);
  };
  SetReadFileMock({readfile_mock});

  online_cpus = "";
  EXPECT_EQ(GetNumCPUs(), 1);
  online_cpus = "0";
  EXPECT_EQ(GetNumCPUs(), 1);
  online_cpus = "0-0";
  EXPECT_EQ(GetNumCPUs(), 1);
  online_cpus = "0-1";
  EXPECT_EQ(GetNumCPUs(), 2);
  online_cpus = "1-1";
  EXPECT_EQ(GetNumCPUs(), 1);
  online_cpus = "1-5";
  EXPECT_EQ(GetNumCPUs(), 5);
  online_cpus = "1,2,3,4,5";
  EXPECT_EQ(GetNumCPUs(), 5);
  online_cpus = "0-6,8-9,11,13-15";
  EXPECT_EQ(GetNumCPUs(), 13);
  online_cpus = "0-1234";
  EXPECT_EQ(GetNumCPUs(), 1235);

  SetReadFileMock({});
  EXPECT_EQ(GetNumCPUs(), 1235);  // Cached result.
}

TEST(OS, Sleep) {
  const auto start = GetTime(CLOCK_MONOTONIC);
  Sleep(Seconds(1));
  const auto elapsed = GetTime(CLOCK_MONOTONIC) - start;
  ASSERT_GE(elapsed, Seconds(1));
  ASSERT_LT(elapsed, Seconds(10));
}

TEST(OS, ForEachTid) {
  constexpr unsigned kThreads = 256;
  std::atomic<unsigned> barrier = 0;
  // Check that a thread finds itself in the thread list.
  auto check_thread = [&] {
    // Need a stable snapshot of threads, otherwise /proc/self/task might change
    // under us while we iterate it.
    for (++barrier; barrier < kThreads;)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));

    bool found_self = false;
    bool last_tid = 0;
    EXPECT_TRUE(ForEachTid([&](int tid) {
      // Verify that the TIDs are ordered sequentially.
      EXPECT_GT(tid, last_tid);
      last_tid = tid;

      if (tid == GetTid()) {
        found_self = true;
        return false;
      }
      return true;
    }));
    EXPECT_TRUE(found_self);

    for (++barrier; barrier < 2 * kThreads;)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
  };

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (unsigned i = 0; i < kThreads; ++i)
    threads.emplace_back(check_thread);
  for (auto& t : threads)
    t.join();
}

}  // namespace
}  // namespace gwpsan
