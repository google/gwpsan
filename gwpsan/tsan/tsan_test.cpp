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

#include <string.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/meta.h"

namespace gwpsan {
std::atomic<int> data_races;
std::vector<std::pair<MemAccess, MemAccess>> data_race_accesses;

bool TestOnDataRace(const MemAccess& ma1, const MemAccess& ma2) {
  data_races++;
  data_race_accesses.emplace_back(ma1, ma2);
  return true;
}

const char* DefaultFlags() {
  return "tsan";
}

namespace {
// Compares fields that we care about in the test.
constexpr bool MemAccessEquals(const MemAccess& ma1, const MemAccess& ma2) {
  bool ret = ma1.addr == ma2.addr && ma1.size == ma2.size &&
             ma1.is_read == ma2.is_read && ma1.is_write == ma2.is_write &&
             ma1.is_atomic == ma2.is_atomic;
  // PC checking is optional. It's hard to get the precise instruction address,
  // so we only check that the expected PC is close to the real one.
  if (GWPSAN_X64 && ma1.pc && ma2.pc)
    ret &= (ma1.pc <= ma2.pc ? ma2.pc - ma1.pc : ma1.pc - ma2.pc) < 32;
  return ret;
}

class RaceDetectorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    data_races = 0;
    data_race_accesses.clear();
    data_race_accesses.reserve(100);
  }

  void RunThreads(const std::vector<std::function<void()>>& funs) {
    constexpr unsigned kIterBeforeTimeout = 10000;

    auto thread = [this](const std::function<void()>& f) {
      using std::chrono::high_resolution_clock;
      const auto start = high_resolution_clock::now();
      while (!data_races && high_resolution_clock::now() - start < timeout_) {
        // high_resolution_clock::now() likely uses proportionally more cycles
        // than f(), so we're unlikely to stall in f() - spin in f() a bit more
        // before re-checking the timeout.
        for (unsigned i = 0; i < kIterBeforeTimeout; i++)
          f();
      }
    };

    std::vector<std::thread> threads;
    threads.reserve(funs.size());
    for (const auto& f : funs)
      threads.emplace_back([&] { thread(f); });
    for (auto& t : threads)
      t.join();
  }

  // Check that at all data race match the specified accesses.
  void ExpectAllDataRaces(const MemAccess& exp_ma1, const MemAccess& exp_ma2) {
    EXPECT_GT(data_races, 0);
    EXPECT_EQ(data_race_accesses.size(), data_races);
    for (const auto& [ma1, ma2] : data_race_accesses) {
      ValidateDataRace(ma1, ma2);
      if ((MemAccessEquals(ma1, exp_ma1) && MemAccessEquals(ma2, exp_ma2)) ||
          (MemAccessEquals(ma1, exp_ma2) && MemAccessEquals(ma2, exp_ma1)))
        continue;
      GTEST_FAIL() << "expected " << &exp_ma1.ToString() << " vs "
                   << &exp_ma2.ToString() << "\ngot      " << &ma1.ToString()
                   << " vs " << &ma2.ToString();
    }
  }

  void SetNoRaceTimeout() {
    timeout_ /= 20;
  }

 private:
  // Note: Only need this large timeout in unoptimized debug builds when running
  // in a VM. On bare metal or in optimized builds, there don't appear to be any
  // timeout issues.
  std::chrono::seconds timeout_{50};

  // Generic data race validation.
  void ValidateDataRace(const MemAccess& ma1, const MemAccess& ma2) {
    EXPECT_TRUE(ma1.pc);
    EXPECT_TRUE(ma2.pc);
    if (GetFlags().tsan_report_atomic_races)
      EXPECT_TRUE(!*ma1.is_atomic || !*ma2.is_atomic);
    else
      EXPECT_TRUE(!*ma1.is_atomic && !*ma2.is_atomic);
    // Check that we have either read or write.
    EXPECT_TRUE(ma1.is_read || ma1.is_write);
    EXPECT_TRUE(ma2.is_read || ma2.is_write);
    // At least one write.
    EXPECT_TRUE(ma1.is_write || ma2.is_write);
  }
};

constinit struct {
  volatile long dummy = 0;
  union {
    volatile long var;
    char buf[sizeof(long)];
  };
  char tmp[sizeof(long)] = {};
} test_data;

SAN_NOINLINE void TestSink(long v) {
  SAN_BARRIER();
}

template <int n = 20>
SAN_ALWAYS_INLINE void Pause() {
  if constexpr (n)
    Pause<n - 1>();
#if GWPSAN_X64
  asm volatile("pause");
#else
  asm volatile("yield");
#endif
}

SAN_NOINLINE void TestAccessRead() {
  TestSink(test_data.var);
}

SAN_NOINLINE void TestAccessPartialRead() {
  TestSink(*(reinterpret_cast<volatile short*>(&test_data.var) + 1));
}

SAN_NOINLINE void TestAccessUnalignedRead() {
  TestSink(*reinterpret_cast<volatile short*>(
      (reinterpret_cast<volatile char*>(&test_data.var) + 1)));
}

SAN_NOINLINE void TestAccessWrite() {
  test_data.var = 42;
}

SAN_NOINLINE void TestAccessWriteWithDummyRead() {
  test_data.var = 42;
  // Not all CPUs support L1 write miss detection, so let's add a dummy read;
  // without precise_ip there'll be some skid, so we likely hit the write
  // eventually.
  TestSink(test_data.dummy);
}

SAN_NOINLINE void TestAccessAtomicRead() {
  // Use builtin atomics, because compiler may outline the std::atomic wrappers.
  TestSink(__atomic_load_n(&test_data.var, __ATOMIC_RELAXED));
}

SAN_NOINLINE void TestAccessAtomicWrite() {
  __atomic_store_n(&test_data.var, 42, __ATOMIC_RELAXED);
}

SAN_NOINLINE void TestAccessAtomicRMW() {
  __atomic_fetch_add(&test_data.var, 1, __ATOMIC_RELAXED);
}

SAN_NOINLINE void TestAccessMemcpyWrite() {
  volatile int size = 1;
  memcpy(&test_data.buf[1], test_data.tmp, size);
}

SAN_NOINLINE void TestAccessMemcpyRead() {
  volatile int size = 2;
  memcpy(test_data.tmp, &test_data.buf[2], size);
}

SAN_NOINLINE void TestAccessSyscall() {
  // A stride of PAUSE instructions helps to land a timer signal before
  // SYSCALL instruction when we use our manual timer signal distribution
  // (with proper kernel timer signal distribution this will be hopefully
  // not needed).
  // What happens with our manual signal distribution: main thread first
  // set "signal pending" bit for this thread and then sends an IPI to this
  // CPU. Hovever, if the period between syscalls in this thread is smaller
  // than IPI latency (time between signal pending bit is set and IPI is
  // delivered), then syscall return path notices signal pending bit and
  // delivers the signal after the SYSCALL instruction (always!).
  // The stride of PAUSE increases the time between syscalls.
  // Note: we cannot use a loop because our emulation stops on loops.
  Pause();
  (void)read(-1, const_cast<long*>(&test_data.var), sizeof(test_data.var));
}

TEST_F(RaceDetectorTest, ReadWriteRace) {
  RunThreads({TestAccessWrite, TestAccessRead, TestAccessRead, TestAccessRead});
  MemAccess exp_read;
  exp_read.addr = &test_data.var;
  exp_read.size = Sizeof(test_data.var);
  exp_read.is_atomic = false;
  auto exp_write = exp_read;
  exp_read.is_read = true;
  exp_write.is_write = true;
  exp_read.pc = reinterpret_cast<uptr>(&TestAccessRead);
  exp_write.pc = reinterpret_cast<uptr>(&TestAccessWrite);
  ExpectAllDataRaces(exp_read, exp_write);
}

TEST_F(RaceDetectorTest, OverlappingReadWriteRace) {
  RunThreads({TestAccessWrite, TestAccessPartialRead, TestAccessPartialRead,
              TestAccessPartialRead});
  MemAccess exp_read;
  exp_read.addr = Addr(&test_data.var) + Sizeof<short>();
  exp_read.size = Sizeof<short>();
  exp_read.is_read = true;
  exp_read.is_atomic = false;
  MemAccess exp_write;
  exp_write.addr = &test_data.var;
  exp_write.size = Sizeof(test_data.var);
  exp_write.is_write = true;
  exp_write.is_atomic = false;
  exp_read.pc = reinterpret_cast<uptr>(&TestAccessPartialRead);
  exp_write.pc = reinterpret_cast<uptr>(&TestAccessWrite);
  ExpectAllDataRaces(exp_read, exp_write);
}

TEST_F(RaceDetectorTest, UnalignedReadWriteRace) {
  RunThreads({TestAccessWrite, TestAccessUnalignedRead, TestAccessUnalignedRead,
              TestAccessUnalignedRead});
  MemAccess exp_read;
  exp_read.addr = Addr(&test_data.var) + ByteSize(1);
  exp_read.size = Sizeof<short>();
  EXPECT_FALSE(IsAligned(*exp_read.addr, *exp_read.size));
  exp_read.is_read = true;
  exp_read.is_atomic = false;
  MemAccess exp_write;
  exp_write.addr = &test_data.var;
  exp_write.size = Sizeof(test_data.var);
  exp_write.is_write = true;
  exp_write.is_atomic = false;
  exp_read.pc = reinterpret_cast<uptr>(&TestAccessUnalignedRead);
  exp_write.pc = reinterpret_cast<uptr>(&TestAccessWrite);
  ExpectAllDataRaces(exp_read, exp_write);
}

// Stress test with low delay to catch internal races; this test may take much
// longer than the others.
TEST_F(RaceDetectorTest, LowDelayReadWriteRace) {
  ScopedTestFlagMutator flags;
  flags.SetSampleInterval(Microseconds(1));
  RunThreads({TestAccessWrite, TestAccessRead, TestAccessRead, TestAccessRead});
  MemAccess exp_read;
  exp_read.addr = &test_data.var;
  exp_read.size = Sizeof(test_data.var);
  exp_read.is_atomic = false;
  auto exp_write = exp_read;
  exp_read.is_read = true;
  exp_write.is_write = true;
  exp_read.pc = reinterpret_cast<uptr>(&TestAccessRead);
  exp_write.pc = reinterpret_cast<uptr>(&TestAccessWrite);
  ExpectAllDataRaces(exp_read, exp_write);
}

TEST_F(RaceDetectorTest, WriteWriteRace) {
  RunThreads({TestAccessWrite, TestAccessWriteWithDummyRead});
  MemAccess exp_write1;
  exp_write1.addr = &test_data.var;
  exp_write1.size = Sizeof(test_data.var);
  exp_write1.is_write = true;
  exp_write1.is_atomic = false;
  auto exp_write2 = exp_write1;
  exp_write1.pc = reinterpret_cast<uptr>(&TestAccessWrite);
  exp_write2.pc = reinterpret_cast<uptr>(&TestAccessWriteWithDummyRead);
  ExpectAllDataRaces(exp_write1, exp_write2);
}

TEST_F(RaceDetectorTest, ReadReadNoRace) {
  SetNoRaceTimeout();
  RunThreads({TestAccessRead, TestAccessRead, TestAccessRead});
  EXPECT_EQ(data_races, 0);
}

TEST_F(RaceDetectorTest, AtomicReadWriteNoRace) {
  SetNoRaceTimeout();
  RunThreads(
      {TestAccessAtomicWrite, TestAccessAtomicRead, TestAccessAtomicRead});
  EXPECT_EQ(data_races, 0);
}

TEST_F(RaceDetectorTest, AtomicWriteWriteNoRace) {
  SetNoRaceTimeout();
  RunThreads(
      {TestAccessAtomicWrite, TestAccessAtomicWrite, TestAccessAtomicWrite});
  EXPECT_EQ(data_races, 0);
}

TEST_F(RaceDetectorTest, AtomicRMWNoRace) {
  SetNoRaceTimeout();
  RunThreads({TestAccessAtomicRMW, TestAccessAtomicRead, TestAccessAtomicRead});
  EXPECT_EQ(data_races, 0);
}

TEST_F(RaceDetectorTest, AtomicWriteNonAtomicReadNoRace) {
  ScopedTestFlagMutator flags;
  flags->tsan_report_atomic_races = false;
  SetNoRaceTimeout();
  RunThreads({TestAccessAtomicWrite, TestAccessRead, TestAccessRead});
  EXPECT_EQ(data_races, 0);
}

TEST_F(RaceDetectorTest, AtomicWriteNonAtomicReadRace) {
  ScopedTestFlagMutator flags;
  flags->tsan_report_atomic_races = true;
  RunThreads({TestAccessAtomicWrite, TestAccessRead, TestAccessRead});
  MemAccess exp_read;
  exp_read.addr = &test_data.var;
  exp_read.size = Sizeof(test_data.var);
  exp_read.is_atomic = false;
  auto exp_write = exp_read;
  exp_read.is_read = true;
  exp_write.is_write = true;
  exp_write.is_atomic = true;
  exp_read.pc = reinterpret_cast<uptr>(&TestAccessRead);
  exp_write.pc = reinterpret_cast<uptr>(&TestAccessAtomicWrite);
  ExpectAllDataRaces(exp_read, exp_write);
}

TEST_F(RaceDetectorTest, MemcpyReadRace) {
  RunThreads({TestAccessRead, TestAccessMemcpyWrite});
  MemAccess exp_read;
  exp_read.addr = &test_data.var;
  exp_read.size = Sizeof(test_data.var);
  exp_read.is_read = true;
  exp_read.is_atomic = false;
  exp_read.pc = reinterpret_cast<uptr>(&TestAccessRead);
  MemAccess exp_write;
  exp_write.addr = &test_data.buf[1];
  exp_write.size = ByteSize(1);
  exp_write.is_write = true;
  exp_write.is_atomic = false;
  exp_write.pc = reinterpret_cast<uptr>(&memcpy);
  ExpectAllDataRaces(exp_read, exp_write);
}

TEST_F(RaceDetectorTest, MemcpyWriteRace) {
  RunThreads({TestAccessWrite, TestAccessMemcpyRead});
  MemAccess exp_write;
  exp_write.addr = &test_data.var;
  exp_write.size = Sizeof(test_data.var);
  exp_write.is_write = true;
  exp_write.is_atomic = false;
  exp_write.pc = reinterpret_cast<uptr>(&TestAccessWrite);
  MemAccess exp_read;
  exp_read.addr = &test_data.buf[2];
  exp_read.size = ByteSize(2);
  exp_read.is_read = true;
  exp_read.is_atomic = false;
  exp_read.pc = reinterpret_cast<uptr>(&memcpy);
  ExpectAllDataRaces(exp_read, exp_write);
}

TEST_F(RaceDetectorTest, SyscallWriteRace) {
  RunThreads({TestAccessWrite, TestAccessSyscall});
  MemAccess exp1;
  exp1.addr = &test_data.var;
  exp1.size = Sizeof(test_data.var);
  exp1.is_write = true;
  exp1.is_atomic = false;
  exp1.pc = reinterpret_cast<uptr>(&TestAccessWrite);
  MemAccess exp2 = exp1;
  exp2.pc = 0;
  ExpectAllDataRaces(exp1, exp2);
}

}  // namespace
}  // namespace gwpsan
