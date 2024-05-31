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

#include "gwpsan/core/instruction.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/env.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/operation.h"
#include "gwpsan/core/origin.h"

namespace gwpsan {

Word Arg::Eval(Env& env, const CPUContext& ctx) const {
  Word val = EvalImpl(env, ctx);
  if (sign_extend_)
    return OpSignExtend(val, Bits(size()));
  return OpAnd(val, Bitmask(size()));
}

void Arg::Store(Env& env, CPUContext& ctx, const Word& val) const {
  StoreImpl(env, ctx, val);
}

bool Arg::Vectorize(BitSize size) {
  if ((size != 0 && size_ != size) || !CanVectorize())
    return false;
  size_ = kPtrSize;
  return true;
}

LogBuf Arg::Dump() const {
  LogBuf buf;
  buf.Append("%s[%zu]", &DumpImpl(), Bits(size_));
  if (sign_extend_)
    buf.Append("sx");
  return buf;
}

Word ImmArg::EvalImpl(Env& env, const CPUContext& ctx) const {
  return val_;
}

void ImmArg::StoreImpl(Env& env, CPUContext& ctx, Word val) const {
  SAN_BUG("storing into immidiate argument");
}

bool ImmArg::CanVectorize() const {
  return false;
}

Arg* ImmArg::AdvanceBy(BitSize bits) {
  SAN_BUG("immediate can't be advanced");
}

bool ImmArg::IsValidImpl(bool is_dst) const {
  return !is_dst;
}

LogBuf ImmArg::DumpImpl() const {
  LogBuf buf;
  buf.Append("0x%zx", val_);
  return buf;
}

Word RegArg::EvalImpl(Env& env, const CPUContext& ctx) const {
  if (reg_ == kUNDEF) {
    if (env.uninit_tracking())
      return {0, Meta(new UndefinedResultOrigin(ctx, kUNDEF))};
    return {};
  }
  Word res = ctx.reg(reg_);
  if (env.uninit_tracking())
    res.meta.Chain(new RegLoadOrigin(reg_, res.val));
  return ShiftRight(res, Bits(offset_));
}

void RegArg::StoreImpl(Env& env, CPUContext& ctx, Word val) const {
  if (env.uninit_tracking())
    val.meta.Chain(new RegStoreOrigin(reg_));
  SAN_CHECK_NE(reg_, kUNDEF);
  if (reg_ == kRZ)
    return;
  if (reg_ == kPC && env.uninit_tracking()) {
    if (auto* origin = val.meta.Simplest(Origin::Type::kUninit))
      env.ReportUninit(ctx, origin, kPC, 0);
  }
  if (!keep_rest_ && (GWPSAN_ARM64 || size() >= ByteSize(4))) {
    ctx.set_reg(reg_, move(val));
    return;
  }
  const uptr mask = Bitmask(size()) << Bits(offset_);
  Word reg = OpAnd(ctx.reg(reg_), ~mask);
  Word res = ShiftLeft(val, Bits(offset_));
  res = OpAnd(res, mask);
  res = OpOr(res, reg);
  ctx.set_reg(reg_, move(res));
}

bool RegArg::CanVectorize() const {
  return offset_ == 0 && !keep_rest_ &&
         (IsVectorReg(reg_) || IsGeneralTempReg(reg_));
}

Arg* RegArg::AdvanceBy(BitSize bits) {
  RegIdx reg = reg_;
  BitSize offset = offset_ + bits;
  while (offset >= kPtrSize) {
    reg = static_cast<RegIdx>(reg + 1);
    offset -= kPtrSize;
  }
  if (SAN_WARN(reg >= kRegCount))
    return this;
  SAN_WARN(IsVectorReg(reg_) && !IsVectorReg(reg));
  // Here we allow general temp reg -> flags temp reg transition
  // because loops advance args off-by-one on the last iteration.
  // But such arg shouldn't be used later.
  SAN_WARN(IsGeneralTempReg(reg_) && !IsTempReg(reg));
  reg_ = reg;
  offset_ = offset;
  return this;
}

bool RegArg::IsValidImpl(bool is_dst) const {
  return (reg_ < kRegCount) && (offset_ + size() <= kPtrSize) &&
         // Full register store must not have an offset (or set keep_rest_).
         (!is_dst || keep_rest_ || (GWPSAN_X64 && size() < ByteSize(4)) ||
          offset_ == 0);
}

LogBuf RegArg::DumpImpl() const {
  LogBuf buf;
  buf.Append("%%%s", RegNames[reg_]);
  if (offset_ != 0)
    buf.Append("+%zu", Bits(offset_));
  if (keep_rest_)
    buf.Append("+k");
  return buf;
}

Word MemArg::EvalImpl(Env& env, const CPUContext& ctx) const {
  Word addr = EvalAddr(ctx);
  if (!CheckAlignment(env, addr))
    return {};
  if (address_arg_)
    return addr;
  Word res = env.Load(Addr(addr.val), size());
  if (env.uninit_tracking()) {
    bool tainted_addr = !res.meta && addr.meta;
    if (tainted_addr)
      res.meta = Meta::Blend(addr.meta);
    res.meta.Chain(new MemLoadOrigin(addr.val, res.val, tainted_addr));
  }
  return res;
}

void MemArg::StoreImpl(Env& env, CPUContext& ctx, Word val) const {
  Word addr = EvalAddr(ctx);
  if (!CheckAlignment(env, addr))
    return;
  if (env.uninit_tracking())
    val.meta.Chain(new MemStoreOrigin(addr.val));
  env.Store(Addr(addr.val), size(), val);
}

bool MemArg::CheckAlignment(Env& env, const Word& addr) const {
  const uptr a = Bytes(required_alignment());
  if (a && (addr.val & (a - 1))) {
    env.Exception();
    return false;
  }
  return true;
}

Word MemArg::EvalAddr(const CPUContext& ctx) const {
  Word addr{Bytes(offset_)};
  addr = OpAdd(addr, ctx.reg(seg_reg_));
  addr = OpAdd(addr, ctx.reg(base_reg_));
  if (index_reg_ != kRZ) {
    Word idx = ctx.reg(index_reg_);
    if (index_extend_size_ != 0) {
      if (index_extend_sign_)
        idx = OpSignExtend(idx, Bits(index_extend_size_));
      else
        idx = OpAnd(idx, Bitmask(index_extend_size_));
    }
    idx = ShiftLeft(idx, Bits(index_shift_));
    addr = OpAdd(addr, idx);
  }
  return addr;
}

bool MemArg::CanVectorize() const {
  return !address_arg_;
}

Arg* MemArg::AdvanceBy(BitSize bits) {
  offset_ += bits;
  return this;
}

bool MemArg::IsRegDereference(RegIdx reg) const {
  return !address_arg_ && seg_reg_ == kRZ && base_reg_ == reg &&
         index_reg_ == kRZ;
}

bool MemArg::IsValidImpl(bool is_dst) const {
  return (!is_dst || !address_arg_) &&
         (index_extend_size_ == 0 || index_extend_size_ == ByteSize(1) ||
          index_extend_size_ == ByteSize(2) ||
          index_extend_size_ == ByteSize(4) ||
          index_extend_size_ == ByteSize(8)) &&
         (index_shift_ <= BitSize(3));
}

LogBuf MemArg::DumpImpl() const {
  LogBuf buf;
  if (seg_reg_ != kRZ)
    buf.Append("%%%s:", RegNames[seg_reg_]);
  if (!address_arg_)
    buf.Append("(");
  if (base_reg_ != kRZ)
    buf.Append("%%%s", RegNames[base_reg_]);
  if (index_reg_ != kRZ)
    buf.Append("+%%%s*%d", RegNames[index_reg_], 1 << Bits(index_shift_));
  if (offset_ != 0)
    buf.Append("%+zd", Bytes(offset_));
  if (!address_arg_)
    buf.Append(")");
  return buf;
}

bool Instr::Flags::Empty() const {
  return set == 0 && reset == 0 && compute == 0 && undefined == 0 && !temp;
}

void Instr::Flags::CheckValid() const {
  SAN_CHECK_EQ(compute & reset, 0);
  SAN_CHECK_EQ(compute & set, 0);
  SAN_CHECK_EQ(compute & undefined, 0);
  SAN_CHECK_EQ(reset & set, 0);
  SAN_CHECK_EQ(reset & undefined, 0);
  SAN_CHECK_EQ(set & undefined, 0);
  SAN_CHECK(!temp || undefined == 0);
}

LogBuf Instr::Flags::Dump() const {
  LogBuf buf;
  if (Empty())
    return buf;
  if (temp)
    buf.Append("[temp]");
  buf.Append("flags");
  if (set)
    buf.Append(":set=%zx", static_cast<uptr>(set));
  if (reset)
    buf.Append(":reset=%zx", static_cast<uptr>(reset));
  if (compute)
    buf.Append(":comp=%zx", static_cast<uptr>(compute));
  if (undefined)
    buf.Append(":undef=%zx", static_cast<uptr>(undefined));
  return buf;
}

Instr& Instr::Set(const Flags& flags) {
  flags.CheckValid();
  flags_ = flags;
  return *this;
}

Instr::Predicate Instr::Predicate::Inverted() const {
  auto copy = *this;
  copy.inverted = !copy.inverted;
  return copy;
}

LogBuf Instr::Predicate::Dump() const {
  LogBuf buf;
  if (!inverted && !set && !reset && !eq && !neq)
    return buf;
  if (temp)
    buf.Append("[temp]");
  buf.Append("if(");
  if (inverted)
    buf.Append("!");
  if (set)
    buf.Append("set=%zx ", static_cast<uptr>(set));
  if (reset)
    buf.Append("reset=%zx ", static_cast<uptr>(reset));
  if (eq)
    buf.Append("eq=%zx ", static_cast<uptr>(eq));
  if (neq)
    buf.Append("neq=%zx ", static_cast<uptr>(neq));
  return buf.Append(")");
}

void Instr::Predicate::CheckValid() const {
  SAN_CHECK_EQ(set & reset, 0);
  SAN_CHECK_EQ(eq & neq, 0);
  SAN_CHECK(eq == 0 || __builtin_popcountl(eq) == 2);
  SAN_CHECK(neq == 0 || __builtin_popcountl(neq) == 2);
}

Instr& Instr::Set(const Predicate& pred) {
  pred.CheckValid();
  pred_ = pred;
  return *this;
}

LogBuf Instr::Dump() const {
  LogBuf buf;
  buf.Append("%s(", op_.Name());
  for (Arg* arg : src_) {
    if (arg)
      buf.Append("%s%s", arg == src_[0] ? "" : ", ", &arg->Dump());
  }
  buf.Append(")");
  if (dst_)
    buf.Append(" -> %s", &dst_->Dump());
  if (vector_size_ != 0)
    buf.Append(" [vector=%zu]", Bits(vector_size_));
  buf.Append(" %s %s", &pred_.Dump(), &flags_.Dump());
  if (undef_)
    buf.Append(" undef:%s", &undef_.Dump());
  if (uninit_)
    buf.Append(" uninit:%s", &uninit_.Dump());
  if (init_)
    buf.Append(" init:%s", &init_.Dump());
  if (uses_)
    buf.Append(" uses:%s", &uses_.Dump());
  return buf;
}

}  // namespace gwpsan
