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

#include <stdint.h>

#include "benchmark/benchmark.h"
#include "gwpsan/base/common.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/env.h"

namespace gwpsan {
namespace {

void BM_Emulate(benchmark::State& state) {
  const uptr kBatch = 100;
  auto body = +[](void* arg) {
    SAN_UNUSED volatile uptr a = 0, b = 0;
    for (uptr i = 0; i < kBatch; ++i)
      a += b;
  };
  int64_t instructions = 0;
  while (state.KeepRunningBatch(kBatch)) {
    CPUContext ctx;
    uptr stack[1024] = {};
    ctx.SetupCall(body, nullptr, stack, sizeof(stack), nullptr);
    Env env(0);
    for (; ctx.reg(kPC).val; ++instructions) {
      ArchDecoder dec(ctx.reg(kPC).val);
      SAN_CHECK(dec.Decode());
      ctx.Execute(env, dec);
    }
  }
  state.SetItemsProcessed(instructions);
}
BENCHMARK(BM_Emulate);

}  // namespace
}  // namespace gwpsan
