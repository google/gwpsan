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

#include <sched.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/env.h"
#include "gwpsan/core/meta.h"

namespace gwpsan {
namespace {

struct Data {
  Breakpoint* bp = nullptr;
  std::atomic<uptr> done[4] = {};
  std::atomic<uptr> accesses[4] = {};
  volatile char watched[8] = {};
};

struct MemAccessCallback final : Env::Callback {
  Addr addr_;

  Word Load(Addr addr, ByteSize size, uptr val) override {
    addr_ = addr;
    return {val};
  }

  void Store(Addr addr, ByteSize size, const Word& val) override {
    addr_ = addr;
  }
};

struct Callback : BreakManager::Callback {
  Data data_[BreakManager::kMaxBreakpoints];

  uptr OnEmulate(const CPUContext& ctx) override {
    HeapAllocatorLifetime alloc_lifetime;
    MemAccessCallback access;
    {
      ArchDecoder dec(ctx.reg(kPC).val);
      SAN_CHECK(dec.Decode());
      Env env(Env::kModeZero | Env::kModeImmutable, &access);
      CPUContext ctx_copy(ctx);
      ctx_copy.Execute(env, dec);
    }
    SAN_LOG("OnEmulate access 0x%zx", *access.addr_);
    for (auto& me : data_) {
      if (access.addr_ >= Addr(&me.watched) &&
          access.addr_ < Addr(&me.watched) + Sizeof(me.watched)) {
        me.accesses[Bytes(access.addr_ - Addr(&me.watched))]++;
        return 0;
      }
    }
    // On Arm it episodically fails with:
    // BUG: breakpoint on unknown address 0xffff9003e1a0,
    //     data 0xffffd40cd7c8-0xffffd40db8c8
    if (!GWPSAN_ARM64)
      SAN_BUG("breakpoint on unknown address 0x%zx, data %p-%p", *access.addr_,
              &data_, &data_ + sizeof(data_));
    return 0;
  }

  bool OnReset(BreakManager::ResetReason reason) override {
    for (auto& me : data_) {
      if (me.bp) {
        mgr()->Unwatch(me.bp);
        me.bp = nullptr;
      }
    }
    return false;
  }
};

// The stress ensures that we don't randomly miss breakpoints.
//
// Older Linux kernel versions will fail this test until this Linux kernel
// commit: https://git.kernel.org/torvalds/c/ca6c21327c6a
//
// The test creates pairs of threads. Each pair triggers 4 breakpoints
// strictly sequentially: first thread, second, first, second. The breakpoint
// can be reset concurrently. We check that hit breakpoints are "monotonic":
// some continuous prefix is hit and all remaining breakpoints are not hit.
// All following cases are good (* is hit, - is missed breakpoint):
//   ****, ***-, **--, *---, ----
// while the test are bad, for example:
//   *-*-, -*--, --**, etc.
TEST(BreakManager, Stress) {
  bool ok = true;
  ScopedBreakManagerSingleton<> mgr(ok);
  ASSERT_TRUE(ok);
  Callback cb;
  ASSERT_TRUE(mgr->Sample(Milliseconds(1)));  // Stress concurrent SIGTRAPs.
  const uptr kIters = 1000;
  std::vector<std::thread> threads;
  for (uptr t = 0; t < BreakManager::kMaxBreakpoints; ++t) {
    threads.emplace_back([&mgr, &cb, t] {
      Data& me = cb.data_[t];
      for (uptr iter = 1; iter < kIters; iter++) {
        mgr->CallbackLock();
        me.bp = mgr->Watch(
            {Breakpoint::Type::kReadWrite, &me.watched, Sizeof(me.watched)});
        SAN_CHECK(me.bp);
        mgr->CallbackUnlock();

        me.watched[0] = iter;  // ACCESS
        me.done[0]++;
        while (me.done[1] != iter) {}
        me.watched[2] = iter;  // ACCESS
        me.done[2]++;
        while (me.done[3] != iter) {}

        uptr accesses[4];
        for (uptr i = 0; i < 4; i++) {
          accesses[i] = me.accesses[i].exchange(0);
          SAN_CHECK_LE(accesses[i], 1);
        }
        for (uptr i = 0; i < 3; i++) {
          if (!accesses[i] && accesses[i + 1])
            SAN_BUG("iter=%zu: %zu %zu %zu %zu\n", iter, accesses[0],
                    accesses[1], accesses[2], accesses[3]);
        }
        mgr->CallbackLock();
        if (me.bp) {
          mgr->Unwatch(me.bp);
          me.bp = nullptr;
        }
        mgr->CallbackUnlock();
        usleep(rand() % 50);
      }
    });
    threads.emplace_back([&cb, t] {
      Data& me = cb.data_[t];
      for (uptr iter = 1; iter < kIters; iter++) {
        while (me.done[0] != iter) {}
        me.watched[1] = iter;  // ACCESS
        me.done[1]++;
        while (me.done[2] != iter) {}
        me.watched[3] = iter;  // ACCESS
        me.done[3]++;
      }
    });
  }
  for (auto& th : threads)
    th.join();
}

}  // namespace
}  // namespace gwpsan
