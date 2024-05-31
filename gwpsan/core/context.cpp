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

#include "gwpsan/core/context.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/type_id.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/env.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/operation.h"
#include "gwpsan/core/origin.h"
#include "gwpsan/core/regset.h"

namespace gwpsan {

void CPUContext::Execute(Env& env, InstrSequence& seq) {
  bool updated_pc = false;
  const uptr num_instr = seq.GetSequenceSize();
  for (uptr i = 0; i < num_instr && !env.exception_raised(); i++) {
    const Instr& instr = seq.GetInstr(i);
    if (i == 0 && env.uninit_tracking()) {
      auto origin = new InstructionOrigin(*this, seq.GetByteSize());
      env.set_current_instruction(origin);
      for (auto& reg : regs_)
        reg.meta.Chain(origin);
    }
    if (Execute(env, instr)) {
      auto* dst = dyn_cast<RegArg>(instr.dst());
      updated_pc |= dst && dst->reg() == kPC;
    }
  }
  if (!updated_pc && !env.exception_raised())
    regs_[kPC].val += seq.GetByteSize();
  env.set_current_instruction(nullptr);
}

bool CPUContext::Execute(Env& env, const Instr& instr) {
  if (!EvalPredicate(env, instr.pred())) {
    SAN_LOG("skipped (predicate): %s", &instr.Dump());
    return false;
  }
  SAN_LOG("executing: %s", &instr.Dump());

  if (env.uninit_tracking()) {
    for (auto reg : instr.uses()) {
      if (auto* origin = regs_[reg].meta.Simplest(Origin::Type::kUninit))
        env.ReportUninit(*this, origin, reg, 0);
    }
  }

  OpArgs src;
  for (uptr i = 0; i < src.size(); i++) {
    if (Arg* arg = instr.src(i))
      src[i] = arg->Eval(env, *this);
  }
  Word res;
  if (instr.op() == OpIndexRegister)
    res = ExecuteIndexRegister(env, instr, src);
  else if (GWPSAN_X64 && instr.op() == OpZeroVectorRegisters)
    ExecuteZeroVectorRegisters(src);
  else if (!instr.vector_size())
    res = ExecuteOp(env, instr, src);
  else
    res = ExecuteVector(env, instr, src);
  if (env.exception_raised())
    return false;
  res = OpAnd(res, Bitmask(instr.dst()->size()));
  if (env.uninit_tracking())
    res.meta.Chain(new OpOrigin(instr.op(), res.val, src));
  if (log_enabled) {
    LogBuf args;
    for (uptr i = 0; i < instr.op().ArgCount(); i++)
      args.Append("%s0x%zx[%zx]", i ? ", " : "", src[i].val,
                  src[i].meta.shadow());
    SAN_LOG("result: (%s) -> 0x%zx[%zx]", &args, res.val, res.meta.shadow());
  }
  instr.dst()->Store(env, *this, res);
  UpdateFlags(env, instr, res, src);

  undefined_regs_ |= instr.undef();
  if (env.uninit_tracking()) {
    uninit_regs_ |= instr.uninit();
    for (auto reg : instr.init())
      regs_[reg].meta = Meta();
    for (auto reg : instr.uninit())
      regs_[reg].meta = Meta(new UndefinedResultOrigin(*this, reg));
  }
  return true;
}

Word CPUContext::ExecuteVector(Env& env, const Instr& instr,
                               const OpArgs& src) {
  // Do intra-word auto-vectorization: if an instruction does N independent
  // operations on adjacent bytes, transform it into N instructions.
  Word res;
  for (BitSize elem; elem < kPtrSize; elem += instr.vector_size()) {
    OpArgs vsrc;
    for (uptr i = 0; i < src.size(); i++) {
      Word arg = src[i];
      if (instr.src(i)) {
        arg = ShiftRight(arg, Bits(elem));
        if (instr.src(i)->sign_extend())
          arg = OpSignExtend(arg, Bits(instr.vector_size()));
        else
          arg = OpAnd(arg, Bitmask(instr.vector_size()));
      }
      vsrc[i] = arg;
    }
    Word vres = ExecuteOp(env, instr, vsrc);
    vres = OpAnd(vres, Bitmask(instr.vector_size()));
    vres = ShiftLeft(vres, Bits(elem));
    res = OpOr(res, vres);
  }
  return res;
}

Word CPUContext::ExecuteOp(Env& env, const Instr& instr, const OpArgs& src) {
  OpCtx ctx(env, instr, *this);
  return instr.op().invoke(ctx, src);
}

Word CPUContext::ExecuteIndexRegister(Env& env, const Instr& instr,
                                      const OpArgs& src) {
  if (src[1].val >= kVectorRegWords * sizeof(uptr))
    return Word{0, Meta::Blend(src[1].meta)};
  RegArg tmp(*dyn_cast<RegArg>(instr.src(0)));
  tmp.AdvanceBy(ByteSize(src[1].val));
  Word val = tmp.Eval(env, *this);
  if (env.uninit_tracking() && !val.meta && src[1].meta) {
    val.meta = Meta::Blend(src[1].meta);
    // Need some way to mark that this is not direct data taint.
    // Not exactly memory load via tainted address, but similar.
    val.meta.Chain(new MemLoadOrigin(src[1].val, val.val, true));
  }
  return val;
}

#if GWPSAN_X64
void CPUContext::ExecuteZeroVectorRegisters(const OpArgs& src) {
  const bool clear_all = src[0].val == 0;
  for (int reg = 0; reg < (kXMMLAST - kXMM0 + 1) / 2; reg++) {
    if (clear_all || (reg % kVectorRegWords) >= 2)
      regs_[kXMM0 + reg] = Word{};
  }
}
#endif

void CPUContext::UpdateFlags(Env& env, const Instr& instr, const Word& res,
                             const OpArgs& src) {
  Instr::Flags flags = instr.flags();
  auto& reg = regs_[flags.temp ? kTEMPFLAGS : kFLAGS];
  // First, compute any computed flags in op-specific way.
  // Note: this can change the flags object.
  uptr untainted = 0;
  if (flags.compute) {
    uptr computed = instr.op().ComputeFlags(instr, flags, untainted, res, src);
    flags.CheckValid();
    SAN_CHECK_EQ(computed & ~flags.compute, 0);
    SAN_CHECK_EQ(untainted & ~flags.compute, 0);
    reg.val = (reg.val & ~flags.compute) | computed;
  }
  // Then, set/reset flags.
  // Note: we also reset any undefined flags just to be more deterministic.
  reg.val |= flags.set;
  reg.val &= ~(flags.reset | flags.undefined);
  undefined_flags_ |= flags.undefined;

  // Lastly, set/reset meta bits.
  // Any flags set to const values are initialized/untainted.
  // Currently we use a simplistic model: any computed flags are uninit/tainted
  // if the instruction result is uninit/tainted.
  if (env.uninit_tracking()) {
    untainted |= flags.set | flags.reset;
    if (!res.meta)
      untainted |= flags.compute;
    reg.meta.Reset(untainted);
    uptr tainted = flags.compute & ~untainted;
    if (tainted && res.meta)
      reg.meta.Set(tainted, res.meta.Simplest(Origin::Type::kAny));
    if (flags.undefined)
      reg.meta.Set(flags.undefined,
                   new OriginChain(new UndefinedResultOrigin(*this, kFLAGS)));
  }
}

bool CPUContext::Synchronize(const CPUContext& real) {
  uctx_ = real.uctx_;
  // Sync all flags we don't care about from the real context. During fuzzing
  // on x86 some strange flags sometimes appear in the context (e.g. ID, NT).
  undefined_flags_ |= ~kAllFlags;
  // Arm CPUs without BTI support don't set these flags and we get mismatches
  // as the result. It's unclear if we need to model these flags at all or not.
  // But for now let's just ignore them during context checking.
  undefined_flags_ |= kFlagBranchJump | kFlagBranchCall;
  // If there were any undefined flags in the previous emulation,
  // set these bits from the real context.
  regs_[kFLAGS].val = (regs_[kFLAGS].val & ~undefined_flags_) |
                      (real.regs_[kFLAGS].val & undefined_flags_);
  undefined_flags_ = 0;
  // We were not able to predict these registers, so copy from the real context.
  for (auto reg : undefined_regs_) {
    regs_[reg].val = real.regs_[reg].val;
    // If the register is also marked as uninit, then we already set its
    // shadow/meta when it was marked as uninit and we want to preserve that
    // shadow/meta (otherwise it will become initialized).
    if (!uninit_regs_[reg])
      regs_[reg].meta = real.regs_[reg].meta;
  }
  undefined_regs_ = RegSet();
  uninit_regs_ = RegSet();
  for (int i = kTEMP0; i <= kTEMPFLAGS; i++)
    regs_[i] = Word{};
  bool equal = true;
  for (int i = 0; i < kRegCount; i++) {
    if (IsTempReg(i))
      continue;
    if (regs_[i].val != real.regs_[i].val)
      equal = false;
  }
  // These arm64 flags are set only for duration of one instruction.
  regs_[kFLAGS].val &= ~(kFlagBranchJump | kFlagBranchCall);
  return equal;
}

bool CPUContext::EvalPredicate(Env& env, const Instr::Predicate& pred) const {
  const Word& reg = regs_[pred.temp ? kTEMPFLAGS : kFLAGS];
  if (env.uninit_tracking()) {
    uptr uninit =
        reg.meta.shadow() & (pred.set | pred.reset | pred.eq | pred.neq);
    // TODO(dvyukov): instructions like CMOVcc probably shouldn't result in the
    // report, but rather propagate uninitness.
    // We probably need to propagate taint to the results of the instruction,
    // then for branches it will reach PC and that will be reported.
    if (uninit) {
      Meta meta = reg.meta;
      meta.Reset(~uninit);
      if (auto* origin = meta.Simplest(Origin::Type::kUninit))
        env.ReportUninit(*this, origin, kFLAGS, uninit);
    }
  }
  uptr flags = reg.val;
  bool res = true;
  if ((pred.set & flags) != pred.set)
    res = false;
  if ((pred.reset & ~flags) != pred.reset)
    res = false;
  if (__builtin_popcountll(pred.eq & flags) == 1)
    res = false;
  if (pred.neq && __builtin_popcountll(pred.neq & flags) != 1)
    res = false;
  if (pred.inverted)
    res = !res;
  return res;
}

bool CPUContext::Tainted() const {
  for (int i = 0; i < kRegCount; i++) {
    if (!IsTempReg(i) && regs_[i].meta)
      return true;
  }
  return false;
}

void CPUContext::SetupCall(void (*fn)(void*), void* arg, void* stack,
                           uptr stack_size, void (*return_to)()) {
  regs_[kPC].val = reinterpret_cast<uptr>(fn);
  regs_[kArgRegs[0]].val = reinterpret_cast<uptr>(arg);
  regs_[kSP].val = reinterpret_cast<uptr>(stack) + stack_size;
  SetupCallArch(reinterpret_cast<uptr>(return_to));
}

namespace {
LogBuf DumpFlags(uptr reg) {
  LogBuf buf;
  buf.Append(kFlagOverflow ? (reg & kFlagOverflow) ? "O" : "." : "");
  buf.Append(kFlagSign ? (reg & kFlagSign) ? "S" : "." : "");
  buf.Append(kFlagZero ? (reg & kFlagZero) ? "Z" : "." : "");
  buf.Append(kFlagAuxCarry ? (reg & kFlagAuxCarry) ? "A" : "." : "");
  buf.Append(kFlagParity ? (reg & kFlagParity) ? "P" : "." : "");
  buf.Append(kFlagCarry ? (reg & kFlagCarry) ? "C" : "." : "");
  return buf;
}
}  // namespace

LogBuf CPUContext::Dump() const {
  LogBuf buf;
  const char* delim = "";
  for (int i = 0, printed = 0; i < kRegCount; i++) {
    Word reg = regs_[i];
    if (i == kRZ || i == kUNDEF || IsTempReg(i) ||
        (IsVectorReg(i) && reg.val == 0))
      continue;
    buf.Append("%s%s:%zx", delim, RegNames[i], reg.val);
    if (i == kFLAGS)
      buf.Append("(%s)", &DumpFlags(reg.val));
    if (reg.meta)
      buf.Append("[%zx]", reg.meta.shadow());
    delim = (++printed % 6) ? " " : "\n  ";
  }
  return buf;
}

LogBuf CPUContext::DumpDiff(const CPUContext& other) const {
  LogBuf buf;
  for (int i = 0; i < kRegCount; i++) {
    if (IsTempReg(i))
      continue;
    if (regs_[i].val == other.regs_[i].val)
      continue;
    buf.Append("%s:%zx->%zx ", RegNames[i], regs_[i].val, other.regs_[i].val);
    if (i == kFLAGS)
      buf.Append("(%s->%s) ", &DumpFlags(regs_[i].val),
                 &DumpFlags(other.regs_[i].val));
  }
  return buf;
}

CPUContext::Features CPUContext::features_;

}  // namespace gwpsan
