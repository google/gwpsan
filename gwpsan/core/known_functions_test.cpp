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

#include "gwpsan/core/known_functions.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <functional>
#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/env.h"
#include "gwpsan/core/flags.h"

namespace gwpsan {
namespace {

using SyscallCallback = const std::function<bool(uptr nr, Span<MemAccess>)>&;

void Emulate(const std::function<void()>& fn,
             const std::function<bool(const CPUContext& ctx)>& check_ctx,
             SyscallCallback check_syscall = nullptr) {
  ScopedTestFlagMutator flags;
  flags->log_failures = true;
  HeapAllocatorLifetime alloc_lifetime;
  CPUContext ctx;
  uptr stack[1024] = {};  // 1024 words of stack should be enough for everyone
  ctx.SetupCall(
      [](void* arg) { (*static_cast<const std::function<void()>*>(arg))(); },
      const_cast<void*>(static_cast<const void*>(&fn)), stack, sizeof(stack),
      0);
  struct Callback final : Env::Callback {
    Callback(SyscallCallback check_syscall)
        : check_syscall(check_syscall) {}
    void Syscall(uptr nr, Span<MemAccess> accesses) override {
      if (check_syscall && check_syscall(nr, accesses))
        done = true;
    }
    SyscallCallback check_syscall;
    bool done = false;
  };
  Callback cb{check_syscall};
  Env env(0, &cb);
  for (;;) {
    ArchDecoder dec(ctx.reg(kPC).val);
    if (!dec.Decode()) {
      ADD_FAILURE() << "instruction decoding failed";
      return;
    }
    ctx.Execute(env, dec);
    if (!ctx.reg(kPC).val) {
      ADD_FAILURE() << "reached end of function";
      return;
    }
    if (cb.done || (check_ctx && check_ctx(ctx)))
      return;
  }
}

struct Access {
  void* addr;
  uptr size;
  bool is_write;
  bool is_use;
};

void CompareAccesses(Span<const MemAccess> got, Span<const Access> want) {
  ASSERT_EQ(got.size(), want.size());
  for (int i = 0; i < got.size(); ++i) {
    EXPECT_EQ(reinterpret_cast<void*>(Bytes(got[i].addr)), want[i].addr);
    EXPECT_EQ(Bytes(got[i].size), want[i].size);
    EXPECT_EQ(got[i].is_write, want[i].is_write);
    EXPECT_EQ(got[i].is_read, !want[i].is_write);
    EXPECT_EQ(got[i].is_use, want[i].is_use);
  }
}

template <typename T>
void Use(T v) {
  asm volatile("" ::"r"(v));
}

TEST(KnownFunctions, IsMallocPC) {
  struct Test {
    std::function<void*()> fn;
    uptr size;
    bool uninit;
  };
  const Test tests[] = {
      {[]() -> void* { return malloc(57); },    57, true },
      {[]() -> void* { return calloc(4, 12); }, 48, false},
      {[]() -> void* { return new int[12]; },   48, true },
  };
  for (const auto& test : tests) {
    Emulate([&] { Use(test.fn()); },
            [&](const CPUContext& ctx) -> bool {
              uptr size;
              bool uninit;
              if (IsMallocPC(ctx, size, uninit)) {
                EXPECT_EQ(size, test.size);
                EXPECT_EQ(uninit, test.uninit);
                return true;
              }
              return false;
            });
  }
}

TEST(KnownFunctions, IsFreePC) {
  struct Test {
    std::function<void(void*)> fn;
    uptr size;
  };
  const Test tests[] = {
      {[](void* ptr) { free(ptr); },                     0},
      {[](void* ptr) { delete static_cast<int*>(ptr); },
#if __cpp_sized_deallocation
       4
#else
       0
#endif
      },
  };
  for (const auto& test : tests) {
    Emulate(
        [&] {
          void* volatile ptr = reinterpret_cast<void*>(0x123);
          test.fn(ptr);
        },
        [&](const CPUContext& ctx) -> bool {
          uptr ptr, size;
          if (IsFreePC(ctx, ptr, size)) {
            EXPECT_EQ(ptr, 0x123);
            EXPECT_EQ(size, test.size);
            return true;
          }
          return false;
        });
  }
}

TEST(KnownFunctions, IsMemAccessFunc) {
  struct Test {
    std::function<void()> fn;
    std::vector<Access> accesses;
  };
  char buf1[100], buf2[100];
  const Test tests[] = {
      {[&] {
         volatile uptr size = 20;
         memset(buf1, 1, size);
       }, {{buf1, 20, true}}                                },
      {[&] {
         volatile uptr size = 10;
         memcpy(buf1, buf2, size);
       }, {{buf1, 10, true}, {buf2, 10, false}}             },
      {[&] {
         volatile uptr size = 10;
         Use(memchr(buf1, 1, size));
       }, {{buf1, 10, false, true}}                         },
      {[&] {
         volatile uptr size = 10;
         Use(strncmp(buf1, buf2, size));
       }, {{buf1, 10, false, true}, {buf2, 10, false, true}}},
  };
  for (const auto& test : tests) {
    Emulate([&] { test.fn(); },
            [&](const CPUContext& ctx) -> bool {
              std::vector<MemAccess> accesses;
              accesses.reserve(10);
              if (IsMemAccessFunc(ctx, accesses)) {
                CompareAccesses(accesses, test.accesses);
                return true;
              }
              return false;
            });
  }
}

TEST(KnownFunctions, ExtractSyscallAccesses) {
  struct Test {
    std::function<void()> fn;
    uptr nr;
    std::vector<Access> accesses;
  };
  char buf1[100];
  const Test tests[] = {
    {[&] { syscall(SYS_read, -1, buf1, 23); },
     SYS_read,                                                {{buf1, 23, true, false}}},
    {[&] { syscall(SYS_write, -1, buf1, 42); },
     SYS_write,                                               {{buf1, 42, false, true}}},
 // Using libc wrappers for syscalls gives higher fidelity for tests
  // (with raw syscalls it's easy to pass wrong arguments tailored for
  // buggy syscall analysis; it also tests what real programs will use).
  // But for Arm can't emulate libc functions completely.
#if GWPSAN_X64
    {[&] { (void)read(-1, buf1, 10); },         SYS_read,     {{buf1, 10, true, false}}},
    {[&] { recv(-1, buf1, 20, 0); },            SYS_recvfrom, {{buf1, 20, true, false}}},
    {[&] { (void)write(-1, buf1, 30); },        SYS_write,    {{buf1, 30, false, true}}},
    {[&] { send(-1, buf1, 40, 0); },            SYS_sendto,   {{buf1, 40, false, true}}},
#endif
  };
  for (const auto& test : tests) {
    // Call the function normally first so that dynamic linker resolves
    // pointers to any functions in dynamic libraries, if it's not yet.
    test.fn();
    Emulate([&]() { test.fn(); }, nullptr,
            [&](uptr nr, Span<MemAccess> accesses) -> bool {
              EXPECT_EQ(nr, test.nr);
              CompareAccesses(accesses, test.accesses);
              return true;
            });
  }
}

}  // namespace
}  // namespace gwpsan
