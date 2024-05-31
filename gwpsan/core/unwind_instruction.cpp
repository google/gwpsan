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

#include "gwpsan/core/unwind_instruction.h"

#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/type_id.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/env.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/operation.h"

namespace gwpsan {
namespace {

// CheckingEnv detects if an instruction accesses the gives memory address.
class CheckingEnv final : public Env::Callback {
 public:
  CheckingEnv(Breakpoint::Info bpinfo)
      : bpinfo_(bpinfo) {}

  bool matched() const {
    return matched_ && !special_;
  }

 private:
  const Breakpoint::Info bpinfo_;
  bool matched_ = false;
  bool special_ = false;

  Word Load(Addr addr, ByteSize size, uptr val) override {
    Access(addr, size, false);
    return {val};
  }

  void Store(Addr addr, ByteSize size, const Word& val) override {
    Access(addr, size, true);
  }

  void Syscall(uptr nr, Span<MemAccess> accesses) override {
    special_ = true;
  }

  void Exception() override {
    special_ = true;
  }

  void Access(Addr addr, ByteSize size, bool write) {
    if (!write && bpinfo_.type == Breakpoint::Type::kWriteOnly)
      return;
    if (DoRangesIntersect(bpinfo_.addr, bpinfo_.size, addr, size))
      matched_ = true;
  }
};
}  // namespace

uptr CopyPreceedingCode(uptr pc, u8* buf) {
  const u8* code = reinterpret_cast<const u8*>(pc);
  // We assume the memory at PC itself is accessible (since we get
  // a watchpoint on it). This allows us to avoid the syscall in most cases.
  const uptr safe_copy = min(kMaxInstrLen, pc % kPageSize);
  internal_memcpy(buf + kMaxInstrLen - safe_copy, code - safe_copy, safe_copy);
  if (safe_copy == kMaxInstrLen)
    return safe_copy;
  if (!NonFailingLoad(code - kMaxInstrLen, ByteSize(kMaxInstrLen - safe_copy),
                      buf))
    return safe_copy;
  return kMaxInstrLen;
}

bool UnwindInstruction(CPUContext& ctx, Breakpoint::Info bpinfo) {
  // This is a very simplistic strategy to find the previous instruction.
  // We just find the largest instruction that ends at the current PC.
  // Note that an instruction can destroy the address (e.g. mov (%rax), %rax).
  // Also the previous instruction is not necessary located before the
  // current one, for example RET both accesses memory and changes PC.
  NoHeapAllocationsScope no_allocations;
  const uptr orig_pc = ctx.reg(kPC).val;
  SAN_LOG("unwind %zx: type=%d addr=0x%zx/%zu", orig_pc,
          static_cast<int>(bpinfo.type), *bpinfo.addr, *bpinfo.size);
  u8 buf[2 * kMaxInstrLen] = {};
  uptr copied = CopyPreceedingCode(orig_pc, buf);
  for (uptr offset = kMaxInstrLen - copied; offset < kMaxInstrLen; offset++) {
    const uptr new_pc = orig_pc - kMaxInstrLen + offset;
    auto dec = MakeUniqueGlobal<ArchDecoder>(
        new_pc, reinterpret_cast<uptr>(buf + offset));
    if (!dec->Decode())
      continue;
    if (new_pc + dec->GetByteSize() != orig_pc) {
      SAN_LOG("wrong next pc");
      continue;
    }
    // This candidate instruction ends on the orig_pc.
    // Now try to restore the context as it was before the instruction.
    ctx.set_reg(kPC, new_pc);
    struct patched_tag;
    auto patched = MakeUniqueGlobal<CPUContext, patched_tag>(ctx);
    for (uptr instr_idx = 0; instr_idx < dec->GetSequenceSize(); instr_idx++) {
      const Instr& instr = dec->GetInstr(instr_idx);
      // Fix cases like "mov (%rax), %rax" and "popcnt (%rax), %rax".
      const auto* dst_reg = dyn_cast<RegArg>(instr.dst());
      const auto* src0_mem = dyn_cast<MemArg>(instr.src(0));
      if (dst_reg && src0_mem && src0_mem->IsRegDereference(dst_reg->reg())) {
        const uptr orig = Bytes(bpinfo.addr - src0_mem->offset());
        SAN_LOG("fixing register %s = %zx", RegNames[dst_reg->reg()], orig);
        patched->set_reg(dst_reg->reg(), orig);
      }
      // Fix add/sub of register with immidiate. This fixes PUSH and POP.
      if (instr.op() == OpAdd || instr.op() == OpSub) {
        const auto* dst_reg = dyn_cast<RegArg>(instr.dst());
        const auto* src0_reg = dyn_cast<RegArg>(instr.src(0));
        const auto* src1_imm = dyn_cast<ImmArg>(instr.src(1));
        if (dst_reg && src0_reg && src1_imm &&
            dst_reg->reg() == src0_reg->reg()) {
          uptr res = ctx.reg(dst_reg->reg()).val;
          uptr imm = src1_imm->val();
          uptr was = instr.op() == OpAdd ? res - imm : res + imm;
          SAN_LOG("fixing register %s = 0x%zx", RegNames[dst_reg->reg()], was);
          patched->set_reg(dst_reg->reg(), was);
        }
      }
      // TODO(dvyukov): fix other practically important cases.
    }
    // Now check that (1) the instruction indeed accesses the memory address,
    // (2) the next PC after emulation is indeed orig_pc.
    //
    // Note: a SYSCALL instruction can access the address in the kernel.
    // But emulating the SYSCALL instruction won't show us the memory access.
    //
    // TODO(dvyukov): it seems that some NOP instructions can also fire
    // a breakpoint (e.g. "nop (%rax)"). If it's indeed the case, we need to
    // skip address checking if we decoded just a single OpNop.
    CheckingEnv env_cb(bpinfo);
    Env env(Env::kModeZero | Env::kModeImmutable, &env_cb);
    struct copy_tag;
    auto copy = MakeUniqueGlobal<CPUContext, copy_tag>(*patched);
    copy->Execute(env, *dec);
    if (!env_cb.matched() || copy->reg(kPC).val != orig_pc) {
      SAN_LOG("candidate does not access the target address");
      continue;
    }
    ctx = *patched;
    return true;
  }
  SAN_LOG("unwind instruction failed");
  return false;
}

}  // namespace gwpsan
