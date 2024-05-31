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

#include <stdlib.h>

#include <thread>

#include "benchmark/benchmark.h"

namespace gwpsan {

const char* DefaultFlags() {
  return "uar";
}

namespace {

void BM_ThreadCreation(benchmark::State& state) {
  for (auto _ : state) {
    std::thread th([]() {
      // Make comparison more apples-to-apples by triggerring
      // per-thread malloc initialization.
      void* volatile p = malloc(1);
      free(p);
    });
    th.join();
  }
}
BENCHMARK(BM_ThreadCreation);

}  // namespace
}  // namespace gwpsan
