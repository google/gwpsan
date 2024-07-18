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

#include "gwpsan/core/semantic_metadata.h"

#include <dlfcn.h>

#include <atomic>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/fault_inject.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/optional.h"

namespace gwpsan {

uptr ExternNoAtomicFunc();
uptr ExternAtomicFunc();

namespace {

SAN_CONSTRUCTOR void TestInit() {
  SAN_CHECK(InitSemanticMetadata(kSemanticAll));
  FaultInjectDisableGlobal();
}

volatile long var;
long avar;

SAN_NOINSTR void DummyFunc() {
  // Do a memory access to that only using -fsanitize-breakpoint=atomics
  // includes this function in covered functions.
  var = 1;
}

SAN_NOINSTR uptr AtomicFuncPrecise() {
  var = 1;
atomic_op:
  // Use builtin atomic, because with compiler instrumentation enabled,
  // std::atomic accessors may be outlined.
  __atomic_store_n(&avar, 42, __ATOMIC_RELAXED);
  // "+ 0" to shut up compiler warning "returning address of label".
  return reinterpret_cast<uptr>(&&atomic_op) + 0;
}

SAN_NOINSTR uptr AtomicFunc() {
  var = var + 1;
  __atomic_store_n(&var, 1, __ATOMIC_RELAXED);
  var = var - 1;
here:
  return reinterpret_cast<uptr>(&&here) + 0;
}

// Function + function size pair.
using Func = Pair<uptr, uptr>;

void CheckUncovered(Func fn) {
  for (uptr pc = fn.first; pc < fn.second; ++pc)
    ASSERT_FALSE(IsAtomicPC(pc));
}

void CheckNoAtomics(Func fn) {
  for (uptr pc = fn.first; pc < fn.second; ++pc) {
    auto atomic = IsAtomicPC(pc);
    ASSERT_TRUE(atomic);
    ASSERT_FALSE(*atomic);
  }
}

void CheckAtomics(Func fn) {
  uptr count = 0;
  for (uptr pc = fn.first; pc < fn.second; ++pc) {
    auto atomic = IsAtomicPC(pc);
    ASSERT_TRUE(atomic);
    count += *atomic;
  }
  ASSERT_EQ(count, 1);
}

int ToInt(Optional<bool> v) {
  return v ? v.value() ? 1 : 0 : -1;
}

TEST(SemanticMetadata, Atomic) {
  EXPECT_FALSE(IsAtomicPC(0));
  EXPECT_FALSE(IsAtomicPC(uptr{-1ull}));
  EXPECT_FALSE(IsAtomicPC(reinterpret_cast<uptr>(&var)));
  const uptr dummy_func = reinterpret_cast<uptr>(&DummyFunc);
  EXPECT_EQ(ToInt(IsAtomicPC(dummy_func)), 0);
  EXPECT_EQ(ToInt(IsAtomicPC(dummy_func + 1)), 0);
  CheckAtomics({reinterpret_cast<uptr>(AtomicFunc), AtomicFunc()});

  if (!GWPSAN_ARM64 && !GWPSAN_INSTRUMENTED && GWPSAN_OPTIMIZE > 1) {
    // Requires: Generated code at 'atomic_op' not PC of atomic store.
    uptr atomic_op = AtomicFuncPrecise();
    EXPECT_EQ(__atomic_load_n(&avar, __ATOMIC_RELAXED), 42);
    const uptr atomic_func = reinterpret_cast<uptr>(&AtomicFuncPrecise);
    EXPECT_EQ(ToInt(IsAtomicPC(atomic_func)), 0);
    EXPECT_EQ(ToInt(IsAtomicPC(atomic_op)), 1);
    EXPECT_EQ(ToInt(IsAtomicPC(atomic_op + 1)), 0);
  }
}

// Checks that extern functions linked into the binary are intepreted correctly.
// This also tests multi-version semantic metadata, where the linked TU has a
// different semantic metadata version (such as when it has a different CM).
TEST(SemanticMetadata, ExternAtomic) {
  CheckNoAtomics(
      {reinterpret_cast<uptr>(ExternNoAtomicFunc), ExternNoAtomicFunc()});
  CheckAtomics({reinterpret_cast<uptr>(ExternAtomicFunc), ExternAtomicFunc()});
}

void UARFunc() {
  int local = 0;
  SAN_UNUSED static volatile int* volatile sink;
  sink = &local;
}

TEST(SemanticMetadata, UAR) {
  EXPECT_FALSE(IsUARFunctionStart(0));
  EXPECT_FALSE(IsUARFunctionStart(-1ull));
  EXPECT_FALSE(IsUARFunctionStart(reinterpret_cast<uptr>(&var)));
  const uptr dummy_func = reinterpret_cast<uptr>(&DummyFunc);
  EXPECT_FALSE(IsUARFunctionStart(dummy_func));
  EXPECT_FALSE(IsUARFunctionStart(dummy_func + 1));
  const uptr uar_func = reinterpret_cast<uptr>(&UARFunc);
  auto stack_args = IsUARFunctionStart(uar_func);
  EXPECT_TRUE(stack_args);
  EXPECT_EQ(*stack_args, 0);
  EXPECT_FALSE(IsUARFunctionStart(uar_func + 1));
}

Func GetFunc(void* lib, const char* name) {
  uptr fn = reinterpret_cast<uptr>(dlsym(lib, name));
  EXPECT_NE(fn, 0) << name;
  uptr end = reinterpret_cast<uptr (*)()>(fn)();
  EXPECT_GT(end, fn) << name;
  EXPECT_LT(end - fn, 1000) << name;
  return {fn, end};
}

constexpr char kLib1Name[] =
    "gwpsan/core/semantic_metadata_test_lib1.so";
constexpr char kLib2Name[] =
    "gwpsan/core/semantic_metadata_test_lib2.so";
constexpr char kLib3Name[] =
    "gwpsan/core/semantic_metadata_test_lib3.so";

TEST(SemanticMetadata, Modules) {
  void* lib1 = dlopen(kLib1Name, RTLD_LAZY);
  void* lib2 = dlopen(kLib2Name, RTLD_LAZY);
  ASSERT_NE(lib1, nullptr);
  ASSERT_NE(lib2, nullptr);
  ASSERT_NE(lib1, lib2);

  auto uncovered1 = GetFunc(lib1, "uncovered");
  CheckUncovered(uncovered1);
  auto no_atomics1 = GetFunc(lib1, "no_atomics");
  CheckNoAtomics(no_atomics1);
  auto atomics1 = GetFunc(lib1, "atomics");
  CheckAtomics(atomics1);

  auto no_atomics2 = GetFunc(lib2, "no_atomics");
  CheckNoAtomics(no_atomics2);

  // Now do a tricky sequence of unloads/loads with/without queries in between.
  // Note: queries also affect internal state because they force sorting and
  // compaction of modules.
  dlclose(lib2);
  CheckUncovered(no_atomics2);
  lib2 = dlopen(kLib2Name, RTLD_LAZY);
  no_atomics2 = GetFunc(lib2, "no_atomics");
  CheckNoAtomics(no_atomics2);
  dlclose(lib2);
  lib2 = dlopen(kLib2Name, RTLD_LAZY);
  dlclose(lib2);
  lib2 = dlopen(kLib2Name, RTLD_LAZY);
  no_atomics2 = GetFunc(lib2, "no_atomics");
  CheckNoAtomics(no_atomics2);
  dlclose(lib2);
  CheckUncovered(no_atomics2);

  dlclose(lib1);
  dlclose(lib2);
}

TEST(SemanticMetadata, ModulesStress) {
  log_enabled = true;
  std::atomic<bool> stop{false};
  std::vector<std::thread> threads;
  for (auto name : {kLib1Name, kLib2Name, kLib3Name}) {
    threads.emplace_back([name, &stop]() {
      while (!stop) {
        void* lib = dlopen(name, RTLD_LAZY);
        SAN_CHECK(lib);
        dlclose(lib);
      }
    });
  }
  threads.emplace_back([&]() {
    // Force module sorting.
    while (!stop)
      IsAtomicPC(0);
  });
  absl::SleepFor(absl::Seconds(3));
  stop = true;
  for (auto& th : threads)
    th.join();
}

}  // namespace
}  // namespace gwpsan
