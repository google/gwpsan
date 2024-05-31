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

#include "benchmark/benchmark.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/breakpoint.h"

namespace gwpsan {
namespace {

template <int i>
SAN_NOINLINE int EmptyFunc() {
  __atomic_signal_fence(__ATOMIC_SEQ_CST);
  return i;
}

// This benchmark aims to measure effects of breakpoints on execution when
// they don't fire. Ideally the effect should be 0.
// The breakpoints are setup in a way we expect them to be setup in prod.
void BM_BreakpointEffect(benchmark::State& state) {
  const int kMaxBreakpoints = 4;
  Breakpoint bp[kMaxBreakpoints];
  int (*breaks[])() = {EmptyFunc<0>, EmptyFunc<1>, EmptyFunc<2>, EmptyFunc<3>};
  int watched[kMaxBreakpoints];
  const int num_bps = state.range(0);
  const int num_wps = state.range(1);
  SAN_CHECK_LE(num_bps + num_wps, kMaxBreakpoints);
  for (int i = 0; i < num_bps; i++) {
    SAN_CHECK(bp[i].Init(Breakpoint::kModePerThread));
    SAN_CHECK(!!bp[i].Enable({Breakpoint::Type::kCode, &breaks[i]}));
  }
  for (int i = num_bps; i < num_bps + num_wps; i++) {
    SAN_CHECK(bp[i].Init(0));
    SAN_CHECK(!!bp[i].Enable(
        {Breakpoint::Type::kReadWrite, &watched[i], Sizeof(watched[i])}));
  }
  const int kDataSize = 64 << 10;
  volatile int data[kDataSize] = {};
  for (auto s : state) {
    for (int i = 0; i < kDataSize; i++)
      data[i] = data[i] + 1;
  }
}
BENCHMARK(BM_BreakpointEffect)
    ->ArgPair(0, 0)
    ->ArgPair(1, 0)
    ->ArgPair(2, 0)
    ->ArgPair(3, 0)
    ->ArgPair(4, 0)
    ->ArgPair(0, 1)
    ->ArgPair(0, 2)
    ->ArgPair(0, 3)
    ->ArgPair(0, 4)
    ->ArgPair(1, 3)
    ->ArgPair(2, 2)
    ->ArgPair(3, 1);

}  // namespace
}  // namespace gwpsan
