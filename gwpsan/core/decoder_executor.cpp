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

#include "gwpsan/core/decoder_executor.h"

#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>

#include <algorithm>
#include <vector>

#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/test_report_interceptor.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/env.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/unwind_instruction.h"

namespace gwpsan {
namespace {

constexpr uptr kStackSize = 128 << 10;

#if GWPSAN_ARM64
// Ensures cache coherency for self-modifying code on ARM64. Cleans the data
// cache and invalidates the instruction cache for the given range. The code
// sequence is documented in Arm ARM (section B2.7.4.2 in DDI0487L.a).
void FlushInstructionCache(const void* start_addr, uptr size) {
  const uptr start = reinterpret_cast<uptr>(start_addr);
  const uptr end = start + size;

  u64 ctr;
  asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
  uptr dsize = 4 << ((ctr >> 16) & 0xf);
  uptr isize = 4 << ((ctr >> 0) & 0xf);

  for (uptr addr = RoundDownTo(start, dsize); addr < end; addr += dsize) {
    asm volatile("dc cvau, %0" : : "r"(addr) : "memory");
  }
  asm volatile("dsb ish" : : : "memory");
  for (uptr addr = RoundDownTo(start, isize); addr < end; addr += isize) {
    asm volatile("ic ivau, %0" : : "r"(addr) : "memory");
  }
  asm volatile("dsb ish" : : : "memory");
  asm volatile("isb" : : : "memory");
}
#else
void FlushInstructionCache(const void* start_addr, uptr size) {}
#endif

class RecordingCallback final : public Env::Callback {
 public:
  struct Access {
    uptr addr;
    uptr size;
    Word val;
    bool write;

    bool executable() const {
      return addr < addr + size && addr >= InstructionExecutor::kDataAddr &&
             addr + size <= InstructionExecutor::kDataAddr +
                                InstructionExecutor::kDataSize;
    }
  };

  const std::vector<Access>& accesses() const {
    return accesses_;
  }

  bool non_executable_access() const {
    for (const auto& access : accesses_) {
      if (!access.executable())
        return true;
    }
    return false;
  }

  bool exception() const {
    return exception_;
  }

  bool syscall() const {
    return syscall_;
  }

 private:
  std::vector<Access> accesses_;
  bool exception_ = false;
  bool syscall_ = false;

  Word Load(Addr addr, ByteSize size, uptr val) override {
    accesses_.push_back({Bytes(addr), Bytes(size), {}, false});
    return {val};
  }

  void Store(Addr addr, ByteSize size, const Word& val) override {
    accesses_.push_back({Bytes(addr), Bytes(size), val, true});
  }

  void Syscall(uptr nr, Span<MemAccess> accesses) override {
    syscall_ = true;
  }

  void Exception() override {
    exception_ = true;
  }
};
}  // namespace

InstructionExecutor::InstructionExecutor(bool fuzzing,
                                         const char* fuzzing_opcodes,
                                         const char* buggy_opcodes)
    : fuzzing_(fuzzing)
    , fuzzing_opcodes_(fuzzing_opcodes)
    , buggy_opcodes_(buggy_opcodes) {
  code_mmap_ = reinterpret_cast<u8*>(kCodeAddr);
  // TODO(dvyukov, elver): Switch to MAP_FIXED_NOREPLACE (supported since 4.17)
  // when we no longer try to support Linux kernel < 5.
  SAN_CHECK_EQ(code_mmap_,
               mmap(code_mmap_, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0));
  // Make things more interesting for UnwindInstruction.
  // It will be able to read few bytes before the actual instruction,
  // but then the previous page is unmapped (ensure UnwindInstruction does not
  // crash reading it).
  memcpy(code_mmap_, kUndefinedInstruction, sizeof(kUndefinedInstruction));
  code_ = code_mmap_ + sizeof(kUndefinedInstruction);
  SAN_CHECK(bp_.Init(Breakpoint::kModePerThread));

  u8* data_addr = reinterpret_cast<u8*>(kDataAddr);
  SAN_CHECK_EQ(data_addr, mmap(data_addr, kDataSize, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0));
  for (uptr i = 0; i < kDataSize; i++)
    data_addr[i] = i;

  // We need to install alt stack for signals b/c we receive signals
  // on totally bogus test context.
  altstack_ = Mmap(kStackSize);
  SAN_CHECK(altstack_);
  stack_t ss = {};
  ss.ss_sp = altstack_;
  ss.ss_size = kStackSize;
  SAN_CHECK(!sigaltstack(&ss, &old_stack_));

  SAN_CHECK((SignalListener<SIGTRAP, InstructionExecutor>::InstallSignalHandler(
      SA_ONSTACK)));
  SAN_CHECK((SignalListener<SIGILL, InstructionExecutor>::InstallSignalHandler(
      SA_ONSTACK)));
  SAN_CHECK((SignalListener<SIGSEGV, InstructionExecutor>::InstallSignalHandler(
      SA_ONSTACK)));
  SAN_CHECK((SignalListener<SIGBUS, InstructionExecutor>::InstallSignalHandler(
      SA_ONSTACK)));
}

InstructionExecutor::~InstructionExecutor() {
  SAN_CHECK(!munmap(code_mmap_, kPageSize));
  SAN_CHECK(!munmap(reinterpret_cast<void*>(kDataAddr), kDataSize));
  SAN_CHECK(!sigaltstack(&old_stack_, nullptr));
  SAN_CHECK(Munmap(altstack_, kStackSize));
}

void InstructionExecutor::Execute(const Span<const u8>& code,
                                  const Span<const u8>& prologue,
                                  const CPUContext& start_ctx, Flags flags,
                                  const CPUContext* end_ctxp) {
  SAN_CHECK_LE(code.size(), kMaxInstrLen);
  SAN_CHECK_LE(prologue.size(), kMaxInstrLen);
  memcpy(code_copy_, prologue.data(), prologue.size());
  memcpy(code_copy_ + prologue.size(), code.data(), code.size());
  for (uptr i = 0; i < sizeof(kUndefinedInstruction); i++)
    code_copy_[prologue.size() + code.size() + i] = kUndefinedInstruction[i];
  // Decode.
  HeapAllocatorLifetime alloc_lifetime;
  ArchDecoder dec(reinterpret_cast<uptr>(code_) + prologue.size(),
                  reinterpret_cast<uptr>(code_copy_) + prologue.size());
  bool ok = dec.Decode();
  if (dec.hard_failed())
    SAN_BUG("decoding failed: %s\n%s", dec.failed(),
            &DumpInstr(dec.pc(), kDumpAsm));
  if (!ok) {
    if (fuzzing_)
      return;
    SAN_BUG("failed to decode the instruction");
  }
  SAN_CHECK_GT(dec.GetSequenceSize(), 0);
  // Check that we decoded exactly 'size' bytes in unit tests.
  // For fuzzing we don't want to decode our UD trailer (and past it).
  if (!fuzzing_ && dec.GetByteSize() != code.size() &&
      !(flags & kFlagIncorrectDecodeLength))
    SAN_BUG("decoded %zu bytes instead of %zu", dec.GetByteSize(), code.size());
  if (fuzzing_ && dec.GetByteSize() > code.size())
    return;

  const char* opcode_name;
  dec.GetOpcode(opcode_name);
  if (fuzzing_opcodes_ && !strstr(fuzzing_opcodes_, opcode_name))
    return;

  // Emulate.
  RecordingCallback cb;
  Env env(Env::kModeImmutable | Env::kUninitTracking, &cb);
  CPUContext ctx = start_ctx;
  ctx.InitUnemulated(init_ctx());
  ctx.set_reg(kPC, reinterpret_cast<uptr>(code_) + prologue.size());
  SAN_LOG("initial context: %s", &ctx.Dump());
  {
    ReportInterceptor report_interceptor;
    ctx.Execute(env, dec);
    SAN_CHECK(report_interceptor.output().empty());
  }

  // Ensure that results with/without uninit tracking are equal.
  // If there were non-executable accesses, the results may be unstable
  // if we read some global counter/timer.
  if (!cb.non_executable_access()) {
    Env env(Env::kModeImmutable);
    CPUContext ctx_nouninit = start_ctx;
    ctx_nouninit.InitUnemulated(init_ctx());
    ctx_nouninit.set_reg(kPC, reinterpret_cast<uptr>(code_) + prologue.size());
    ctx_nouninit.Execute(env, dec);
    SAN_CHECK(ctx_nouninit.Synchronize(ctx), "diff: %s",
              &ctx.DumpDiff(ctx_nouninit));
  }

  // Execute the instruction for real.
  // Currently we don't cross-check instructions that access memory,
  // raise exceptions, call syscalls during fuzzing or transfer control for
  // simplicity.
  memcpy(code_, code_copy_, sizeof(code_copy_));
  FlushInstructionCache(code_mmap_, kPageSize);
  uptr next_pc =
      reinterpret_cast<uptr>(code_) + prologue.size() + dec.GetByteSize();
  bool executable = !cb.non_executable_access() && !cb.exception() &&
                    (!fuzzing_ || !cb.syscall()) && ctx.reg(kPC).val == next_pc;
  if (!fuzzing_)
    SAN_CHECK_EQ(executable, !(flags & kFlagNotExecutable));
  const bool buggy = buggy_opcodes_ && strstr(buggy_opcodes_, opcode_name);
  const bool supported =
      CPUContext::IsEnabled(flags & CPUContext::kAllFeatures);
  if (executable && supported) {
    real_ctx_ = start_ctx;
    real_ctx_.InitUnemulated(init_ctx());
    if (!Execute(dec.GetByteSize(), prologue.size())) {
      // Ignore instructions that cause signals during fuzzing.
      // There are lots of invalid instruction encodings that cause SIGILL
      // and are hard to detect. It's also hard to precisely model all
      // possible corner cases that cause SIGSEGV. We are not much interested
      // in emulating instructions that won't execute, so just ignore them.
      if (!fuzzing_)
        SAN_CHECK_EQ(unexpected_signal_, 0);
    } else {
      u8* const data_addr = reinterpret_cast<u8*>(kDataAddr);
      bool corrupted_data = false;
      CPUContext emulated_ctx(ctx);
      bool match = emulated_ctx.Synchronize(real_ctx_);
      if (!buggy) {
        if (!(flags & kFlagKnownBuggy) && !match)
          SAN_BUG("emulated and real contexts differ: %s",
                  &emulated_ctx.DumpDiff(real_ctx_));
        for (const auto& access : cb.accesses()) {
          if (!access.write)
            continue;
          // Check the instruction stored the same value we predicted
          // (unless the stored value is undef/uninit).
          u8* const addr = reinterpret_cast<u8*>(access.addr);
          if (!access.val.meta) {
            uptr stored = 0;
            SAN_CHECK_LE(access.size, sizeof(stored));
            memcpy(&stored, addr, access.size);
            if (access.val.val != stored) {
              Printf(
                  "emulated and real stored values differ: addr=%p size=%zu "
                  "emulated=0x%zx real=0x%zx\n",
                  addr, access.size, access.val.val, stored);
              corrupted_data = true;
            }
          }
          // Restore the original contents of the data region.
          for (uptr i = 0; i < access.size; i++)
            addr[i] = addr - data_addr + i;
        }
        // Check that the data region does not have any unintentional changes.
        for (uptr i = 0; i < kDataSize; i++) {
          if (data_addr[i] == static_cast<u8>(i))
            continue;
          Printf("byte at %p is corrupted: got %x want %x\n", &data_addr[i],
                 data_addr[i], static_cast<u8>(i));
          corrupted_data = true;
          data_addr[i] = static_cast<u8>(i);
        }
        if (!(flags & kFlagKnownBuggy) && corrupted_data)
          SAN_BUG("data region is corrupted");
        if ((flags & kFlagKnownBuggy) && match && !corrupted_data)
          SAN_BUG("emulated and real contexts match for known buggy test");
      } else {
        // Restore data region if the buggy instruction wrote to it.
        for (uptr i = 0; i < kDataSize; i++)
          data_addr[i] = static_cast<u8>(i);
      }
    }
  }

  // Compare with expected result.
  if (end_ctxp && !(flags & kFlagKnownBuggy)) {
    if (flags & kFlagNotExecutable) {
      const bool exception = flags & kFlagException;
      if (exception != cb.exception())
        SAN_BUG("expected/emulated kFlagException differ: %d/%d", exception,
                cb.exception());
      // For exceptions we check that the instruction did not alter context.
      CPUContext end_ctx = exception ? start_ctx : *end_ctxp;
      end_ctx.InitUnemulated(init_ctx());
      end_ctx.set_reg(kPC, end_ctx.reg(kPC).val +
                               reinterpret_cast<uptr>(code_) + prologue.size());
      CPUContext emulated_ctx(ctx);
      if (!emulated_ctx.Synchronize(end_ctx))
        SAN_BUG("emulated and expected contexts differ: %s",
                &emulated_ctx.DumpDiff(end_ctx));
    }
    // Check meta data values for all registers.
    for (int i = 0; i < kRegCount; i++) {
      uptr emulated = ctx.reg(static_cast<RegIdx>(i)).meta.shadow();
      uptr expected = end_ctxp->reg(static_cast<RegIdx>(i)).meta.shadow();
      if (emulated != expected)
        SAN_BUG("%s meta differs: emulated=%zx expected=%zx", RegNames[i],
                emulated, expected);
    }
  }

  // UnwindInstruction test.
  SAN_CHECK(!(flags & kFlagNoUnwind) || !cb.accesses().empty());
  for (const auto& access : cb.accesses()) {
    CPUContext end_ctx = real_ctx_;
    if (flags & kFlagNotExecutable) {
      end_ctx = *end_ctxp;
      end_ctx.InitUnemulated(init_ctx());
      end_ctx.set_reg(kPC, end_ctx.reg(kPC).val +
                               reinterpret_cast<uptr>(code_) + prologue.size());
    } else if (!supported) {
      end_ctx = ctx;
    }
    SAN_LOG("UnwindInstruction test: PC=%zx access=%zx/%zx",
            end_ctx.reg(kPC).val, access.addr, access.size);
    if (!UnwindInstruction(end_ctx,
                           {Breakpoint::Type::kReadWrite, Addr(access.addr),
                            ByteSize(access.size)})) {
      if (!fuzzing_ && !(flags & kFlagNoUnwind) && !(flags & kFlagException))
        SAN_BUG("UnwindInstruction failed");
    }
  }
}

bool InstructionExecutor::Execute(uptr code_size, uptr prologue_size) {
  unexpected_signal_ = 0;
  executing_ = 1;
  real_ctx_.set_reg(kPC, reinterpret_cast<uptr>(code_) + prologue_size);
  SAN_CHECK(
      bp_.Enable({Breakpoint::Type::kCode, code_ + prologue_size + code_size}));
  CPUContext::ToUContextEnable();
  // Use a signal to create the necessary context (handler can do it w/o asm).
  // On return from the signal real_ctx_ is updated with the resulting context.
  SAN_CHECK(!pthread_kill(pthread_self(), SIGTRAP));
  SAN_CHECK_EQ(executing_, 3);
  return unexpected_signal_ == 0;
}

SAN_NOINSTR bool InstructionExecutor::OnSignal(int sig, siginfo_t* info,
                                               void* uctxp) {
#if GWPSAN_X64
  // If the instruction sets the alignment check flags (AC), we can trap on
  // an unaligned memory access in the signal handler (this happened with asan
  // stack instrumentation). Clear AC to prevent that.
  // Note: strictly speaking we need to reset it as early as possible in an asm
  // entry function. But doing it here fixes the problem for now, so we do
  // it here to not complicate production code.
  // Note: CLAC instruction is privileged for some reason.
  asm volatile(R"(
    pushf
    btr $18, (%%rsp)
    popf
  )" ::
                   : "cc");
#endif
  return OnSignalImpl(sig, info, uctxp);
}

bool InstructionExecutor::OnSignalImpl(int sig, siginfo_t* info, void* uctxp) {
  auto& uctx = *static_cast<ucontext_t*>(uctxp);
  switch (executing_) {
  case 1:
    SAN_CHECK_EQ(sig, SIGTRAP);
    // On the first signal we remember the current ucontext (to restore it on
    // the second signal) and swap it with the context we need to emulate.
    // The breakpoint is supposed to fire after the instruction.
    executing_ = 2;
    memcpy(&uctx_, uctxp, sizeof(uctx_));
    real_ctx_.ToUContext(uctx);
    return true;
  case 2:
    executing_ = 3;
    if (sig == SIGTRAP) {
      // The second breakpoint singal: restore the original context to return
      // from pthread_kill.
      bp_.Disable();
      real_ctx_ = CPUContext(uctx);
    } else {
      unexpected_signal_ = sig;
    }
    memcpy(uctxp, &uctx_, sizeof(uctx_));
    return true;
  }
  return false;
}

namespace {
constexpr bool kDontFuzz[kRegCount] = {
    [kPC] = true, [kRZ] = true, [kUNDEF] = true, [kTEMP0... kTEMPFLAGS] = true,
#if GWPSAN_X64
    [kFS] = true, [kGS] = true,
#endif
};

using IE = InstructionExecutor;
static constexpr uptr kSpecial[] = {
    // Addresses of data arranged by InstructionExecutor:
    IE::kDataAddr, IE::kDataAddr + IE::kDataSize / 2,
    IE::kDataAddr + IE::kDataSize, IE::kDataAddr / 2, IE::kDataAddr / 4,
    IE::kDataAddr / 8, IE::kDataAddr + IE::kDataSize - 1,
    IE::kDataAddr + IE::kDataSize - 2, IE::kDataAddr + IE::kDataSize - 4,
    IE::kDataAddr + IE::kDataSize - 8, IE::kDataAddr + IE::kDataSize - 16,
    IE::kDataAddr + IE::kDataSize - 32,

    // Special float values:
    0x80000000,  // -0
    0x3f800000,  // +1
    0x7f7fffff,  // maximum normal number
    0x00800000,  // minimum positive normal number
    0x007fffff,  // maximum subnormal number
    0x00000001,  // minimum positive subnormal number
    0xff7fffff,  // negatived maximum normal number
    0x80800000,  // negatived minimum positive normal number
    0x807fffff,  // negatived maximum subnormal number
    0x80000001,  // negatived minimum positive subnormal number
    0x7f800000,  // infinity
    0xff800000,  // negative infinity
    0x7fc00000,  // NaN
    0x7f800001,  // NaN

    // Special double values:
    0x8000000000000000,  // -0
    0x3ff0000000000000,  // +1
    0x7fefffffffffffff,  // max normal number
    0x0010000000000000,  // min positive normal number
    0x000fffffffffffff,  // max subnormal number
    0x0000000000000001,  // min positive subnormal number
    0xffefffffffffffff,  // negatived max normal number
    0x8010000000000000,  // negatived min positive normal number
    0x800fffffffffffff,  // negatived max subnormal number
    0x8000000000000001,  // negatived min positive subnormal number
    0x7ff0000000000000,  // infinity
    0xfff0000000000000,  // negative infinity
    0x7ff8000000000000,  // NaN
    0x7ff0000000000001,  // SNaN
};
}  // namespace

Span<const u8> InstructionExecutor::FuzzerDecode(
    Span<const u8> data, CPUContext& ctx, CPUContext::Features features) {
  // The first kMaxInstrLen bytes will be treated as the instruction to execute.
  // The rest of the input describes initial values for registers:
  //  - 1 byte for register index
  //  - 1 bytes for special flag
  //  - if (special % 2) == 0, 8 bytes with the register value
  //  - if (special % 2) != 0, 1 byte with kSpecial value index
  // In order to not initialize a register twice, we build a pseudo-random
  // permutation of all registers we want to fill.
  uptr nregs = 0;
  RegIdx regs[kRegCount];
  for (int i = 0; i < kRegCount; ++i) {
    if (!kDontFuzz[i])
      regs[nregs++] = static_cast<RegIdx>(i);
  }
  static_assert(kRegCount <= (1 << kByteBits), "register won't fit into byte");
  for (const u8* pos = data.data() + kMaxInstrLen;
       nregs && pos + sizeof(uptr) + 2 <= data.end();) {
    uptr idx = pos[0] % nregs;
    RegIdx reg = regs[idx];
    regs[idx] = regs[--nregs];
    uptr val;
    if (!(pos[1] % 2)) {
      memcpy(&val, pos + 2, sizeof(val));
      pos += 2 + sizeof(uptr);
    } else {
      val = kSpecial[pos[2] % SAN_ARRAY_SIZE(kSpecial)];
      pos += 3;
    }
    // If we set AVX512 registers when they are not supported by CPU,
    // we get emulated/real context mismatch (when instruction itself is not
    // AVX512 and don't even use these registers). Don't we still want to
    // consume the fuzzer blob in the same way to make corpus work across
    // different machines.
    if (!(features & CPUContext::kFeatureAVX512) && IsAVX512Reg(reg))
      continue;
    ctx.set_reg(reg, val);
  }
  return {data.data(), min(data.size(), kMaxInstrLen)};
}

std::vector<u8> InstructionExecutor::FuzzerEncode(Span<const u8> code,
                                                  const CPUContext& ctx) {
  SAN_CHECK_LE(code.size(), kMaxInstrLen);
  std::vector<u8> data(kMaxInstrLen);
  std::copy(code.begin(), code.end(), data.begin());
  uptr nregs = 0;
  RegIdx regs[kRegCount];
  for (int i = 0; i < kRegCount; ++i) {
    if (!kDontFuzz[i])
      regs[nregs++] = static_cast<RegIdx>(i);
  }
  for (int i = 0; i < kRegCount; ++i) {
    auto val = ctx.reg(static_cast<RegIdx>(i)).val;
    if (!val || kDontFuzz[i])
      continue;
    int idx = -1;
    for (int j = 0; j < nregs; ++j) {
      if (regs[j] == i) {
        idx = j;
        break;
      }
    }
    SAN_CHECK_NE(idx, -1);
    data.push_back(idx);
    data.push_back(0);
    for (uptr j = 0; j < sizeof(val); ++j, val >>= kByteBits)
      data.push_back(val);
    regs[idx] = regs[--nregs];
  }
  // Do a round-trip test: decode and ensure we get the same code/context.
  CPUContext ctx1;
  auto code1 = FuzzerDecode(data, ctx1, CPUContext::kAllFeatures);
  SAN_CHECK_EQ(code1.size(), kMaxInstrLen);
  SAN_CHECK(!memcmp(code1.data(), code.data(), code.size()));
  for (int i = 0; i < kRegCount; ++i) {
    auto r = static_cast<RegIdx>(i);
    if (kDontFuzz[i]) {
      SAN_CHECK_EQ(ctx1.reg(r).val, 0);
      continue;
    }
    SAN_CHECK_EQ(ctx1.reg(r).val, ctx.reg(r).val);
  }
  return data;
}

}  // namespace gwpsan
