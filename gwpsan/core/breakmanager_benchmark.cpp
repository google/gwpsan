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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include "benchmark/benchmark.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"

namespace gwpsan {
namespace {

void BM_ThreadCreation(benchmark::State& state) {
  int watched[BreakManager::kMaxBreakpoints];
  if (state.range(0)) {
    // Callback not required if breakpoints do not fire.
    SAN_CHECK(BreakManager::singleton().try_emplace());
    for (auto& w : watched)
      BreakManager::singleton()->Watch(
          {Breakpoint::Type::kReadWrite, &w, Sizeof(w)});
  }
  const uptr kBatch = 100;
  while (state.KeepRunningBatch(kBatch)) {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<std::thread> threads;
    bool stop = false;
    for (uptr i = 0; i < kBatch; i++)
      threads.emplace_back([&]() {
        std::unique_lock<std::mutex> lock(mu);
        while (!stop)
          cv.wait(lock);
      });
    {
      std::unique_lock<std::mutex> lock(mu);
      stop = true;
    }
    cv.notify_all();
    for (auto& th : threads)
      th.join();
  }
  BreakManager::singleton().reset();
}
BENCHMARK(BM_ThreadCreation)->UseRealTime()->Arg(0)->Arg(1);

// The benchmark measures performance of breakpoint enable/disable in 3 modes:
// Arg=0: single-threaded app
// Arg=1: with 2 * NumCPU sleeping threads
// Arg=2: with 2 * NumCPU sleeping threads + NumCPU-1 actively spinning threads
void BM_BreakpointEnable(benchmark::State& state) {
  bool ok = true;
  ScopedBreakManagerSingleton<> mgr(ok);
  SAN_CHECK(ok);
  BreakManager::Callback cb;
  std::mutex mu;
  std::condition_variable cv;
  std::atomic<bool> stop = {false};
  std::vector<std::thread> threads;
  if (state.range(0) >= 1) {
    for (unsigned i = 0; i < 2 * std::thread::hardware_concurrency(); i++) {
      threads.emplace_back([&]() {
        std::unique_lock<std::mutex> lock(mu);
        while (!stop)
          cv.wait(lock);
      });
    }
  }
  if (state.range(0) >= 2) {
    for (unsigned i = 0; i < std::thread::hardware_concurrency() - 1; i++) {
      threads.emplace_back([&]() {
        while (!stop) {}
      });
    }
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  while (state.KeepRunningBatch(BreakManager::kMaxBreakpoints)) {
    int watched[BreakManager::kMaxBreakpoints];
    Breakpoint* bps[BreakManager::kMaxBreakpoints];
    for (uptr i = 0; i < BreakManager::kMaxBreakpoints; i++)
      bps[i] = mgr->Watch(
          {Breakpoint::Type::kReadWrite, &watched[i], Sizeof(watched[i])});
    for (uptr i = 0; i < BreakManager::kMaxBreakpoints; i++)
      mgr->Unwatch(bps[i]);
  }
  {
    std::unique_lock<std::mutex> lock(mu);
    stop = true;
  }
  cv.notify_all();
  for (auto& th : threads)
    th.join();
}
BENCHMARK(BM_BreakpointEnable)->UseRealTime()->Arg(0)->Arg(1)->Arg(2);

}  // namespace
}  // namespace gwpsan
