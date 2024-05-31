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

#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/decoder_executor.h"

namespace gwpsan {
const char* DefaultFlags() {
  // LibFuzzer needs to catch SIGABRT to save the input.
  return "abort_on_error";
}

extern "C" int LLVMFuzzerTestOneInput(const char* data, uptr size) {
  using IE = InstructionExecutor;
  // We don't fully implement xsavec32/64 semantics (don't model what exactly
  // they store to memory).
  // We emulate pushf correctly in most cases, however sometimes real execution
  // suddenly gets ID and NT flags (0x204000) set, and as the result
  // memory contents differ with what we predict.
  if (!IE::singleton())
    IE::singleton().emplace(true, getenv("GWPSAN_OPCODES"),
                            "xsavec32,xsavec64,pushf");
  auto& exec = *IE::singleton();
  HeapAllocatorLifetime alloc_lifetime;
  CPUContext ctx;
  auto code = IE::FuzzerDecode({reinterpret_cast<const u8*>(data), size}, ctx);
  exec.Execute(code, {}, ctx);
  return 0;
}
}  // namespace gwpsan
