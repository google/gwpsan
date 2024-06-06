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

#ifndef GWPSAN_CORE_DECODER_EXECUTOR_H_
#define GWPSAN_CORE_DECODER_EXECUTOR_H_

#include <signal.h>

#include <vector>

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"

namespace gwpsan SAN_LOCAL {

class InstructionExecutor final
    : SignalListener<SIGTRAP, InstructionExecutor>,
      SignalListener<SIGILL, InstructionExecutor>,
      SignalListener<SIGSEGV, InstructionExecutor>,
      SignalListener<SIGBUS, InstructionExecutor>,
      public SynchronizedSingleton<InstructionExecutor> {
 public:
  // Flags can also accept CPUContext::Feature values and must not overlap.
  using Flags = uptr;
  // The instruction is expected to raise an exception.
  static constexpr Flags kFlagException = 1ul << 63;
  // The instruction is expected to not be executable on the real CPU
  // (e.g. accesses memory, raises an exception). end_ctxp must be passed
  // only if this flag is set.
  static constexpr Flags kFlagNotExecutable = 1ul << 62;
  // The test is known to be buggy, context mismatch is expected.
  // If emulated and real contexts match, the test will fail.
  static constexpr Flags kFlagKnownBuggy = 1ul << 61;
  // Don't do UnwindInstruction test (probably there is some bug).
  static constexpr Flags kFlagNoUnwind = 1ul << 60;
  // We may incorrectly decode instruction length.
  // Intended for very special cases, see uses.
  static constexpr Flags kFlagIncorrectDecodeLength = 1ul << 59;

  // Execute:
  // (1) decodes a single instruction pointed to by 'code'/'size',
  //
  // (2) emulates it starting from the given context 'start_ctx',
  //
  // (3) compares the resulting context with 'end_ctxp' if it's provided
  // (kPC in end_ctxp is relative to the instruction start, in particular for
  // non-control-transfer instructions it should be the size of the
  // instruction),
  //
  // (4) executes the instruction on the real CPU and compares the result with
  // the result of emulation. Note that some unsupported instructions won't be
  // executed.
  //
  // (5) executes UnwindInstruction on 'end_ctx'.
  // The 'prologue' bytes are copied before the instruction which may affect
  // UnwindInstruction.
  //
  // The function CHECK-fails on any errors/mismatches.
  void Execute(const Span<const u8>& code, const Span<const u8>& prologue,
               const CPUContext& start_ctx, Flags flags = 0,
               const CPUContext* end_ctxp = nullptr);

  bool OnSignal(int sig, siginfo_t* info, void* uctxp);

  // This range is mmaped for the executed instructions to use.
  // It's filled with incrementing bytes 0, 1, 2, ....
  // For now mmaped as read-only.
  static constexpr uptr kDataAddr = (1 << 30) + (1 << 20);
  static constexpr uptr kDataSize = 4 << 10;

  // Decode/encode fuzzer blob into instruction bytes + initial values
  // for registers in CPUContext. Decoder test uses FuzzerEncode to export
  // all test cases as seeds for decoder fuzzer.
  static Span<const u8> FuzzerDecode(
      Span<const u8> data, CPUContext& ctx,
      CPUContext::Features features = CPUContext::features());
  static std::vector<u8> FuzzerEncode(Span<const u8> code,
                                      const CPUContext& ctx);

 private:
  const bool fuzzing_;
  const char* const fuzzing_opcodes_;
  const char* const buggy_opcodes_;
  u8* code_mmap_ = nullptr;
  u8* code_ = nullptr;
  u8 code_copy_[3 * kMaxInstrLen];
  stack_t old_stack_;
  void* altstack_ = nullptr;
  Optional<CPUContext> init_ctx_;
  CPUContext real_ctx_;
  ucontext_t uctx_;
  Breakpoint bp_;
  int executing_ = 0;
  int unexpected_signal_ = 0;

  // Address where the tested instruction will be placed.
  static constexpr uptr kCodeAddr = 1ul << 30;

  // fuzzing_opcodes optionally specifies set of opcodes to fuzz.
  // Comparison with the real context is done only if the string contains
  // the decoded opcode as a substring.
  // For example the string may be "mul" or "shl,shr".
  // buggy_opcodes optionally specifies set of opcodes that will be ignored
  // during context checking, intended for fuzzing in presence of known bugs.
  InstructionExecutor(bool fuzzing, const char* fuzzing_opcodes = nullptr,
                      const char* buggy_opcodes = nullptr);
  ~InstructionExecutor();

  CPUContext& init_ctx() {
    if (!init_ctx_) {
      // Capture a real CPU context in real_ctx_ to use with InitUnemulated.
      // Do it lazily because it is not yet safe to call Emulate() from the
      // constructor (Singleton isn't yet fully initialized).
      SAN_CHECK(Execute(0, 0));
      init_ctx_ = real_ctx_;
    }
    return *init_ctx_;
  }

  // Execute an instruction at code_ with real_ctx_ as the initial CPU context.
  // On return updates real_ctx_ with the context after the instruction
  // execution. Returns if the instruction was successfully executed.
  bool Execute(uptr code_size, uptr prologue_size);
  bool OnSignalImpl(int sig, siginfo_t* info, void* uctxp);

  friend Singleton;
};

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_CORE_DECODER_EXECUTOR_H_
