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

#include "gwpsan/core/decoder_arm64.h"

namespace gwpsan {

namespace {
constexpr Instr::Flags kFlagsArith = {kFlagOverflow | kFlagCarry | kFlagZero |
                                      kFlagSign};
constexpr Instr::Flags kFlagsLogical = {kFlagZero | kFlagSign, 0,
                                        kFlagOverflow | kFlagCarry};

void SetFlag(Instr::Flags& flags, uptr flag, bool val) {
  if (val)
    flags.set |= flag;
  else
    flags.reset |= flag;
}

Instr::Flags FlagsFromNZCV(uptr nzcv) {
  Instr::Flags flags;
  SetFlag(flags, kFlagOverflow, nzcv & 1);
  SetFlag(flags, kFlagCarry, nzcv & 2);
  SetFlag(flags, kFlagZero, nzcv & 4);
  SetFlag(flags, kFlagSign, nzcv & 8);
  return flags;
}
}  // namespace

Arm64Decoder::Arm64Decoder(uptr pc, uptr pc_copy)
    : DynamoRIODecoder(pc, pc_copy) {}

void Arm64Decoder::DecodeArch() {
  auto op = opcode();
  switch (op) {
  case OP_mrs:
  case OP_movz:
  case OP_ldrb:
  case OP_strb:
  case OP_ldrh:
  case OP_ldrsw:
  case OP_strh:
  case OP_ldr:
  case OP_str:
  case OP_stur:
  case OP_ldur:
    src(0)->set_sign_extend(op == OP_ldrsw);
    if (num_src() == 1) {
      Emit(OpMove, dst(0), src(0));
      return;
    }
    if (opnd_get_flags(instr_get_src(instr(), 1)) &
        (DR_OPND_IS_SHIFT | DR_OPND_IS_EXTEND)) {
      Emit(OpMove, dst(0), ShiftExtend(src(0), 1));
    } else {
      Emit(OpMove, dst(0), src(0));
      Emit(OpAdd, dst(1), src(1), src(2));
    }
    break;
  case OP_stp: {
    auto* arg = dst(0);
    arg->set_size(src(0)->size());
    Emit(OpMove, arg, src(0));
    Emit(OpMove, AdvanceBy(arg, arg->size()), src(1));
    if (num_src() == 4)
      Emit(OpAdd, dst(1), src(2), src(3));
    break;
  }
  case OP_ldp: {
    auto* arg = src(0);
    arg->set_size(dst(0)->size());
    // Note: need to use temp register b/c source and destination can overlap,
    // e.g.: ldp (%x0) -> %x0 %x8
    auto* tmp = NewRegArg(kTEMP0, dst(0)->size());
    Emit(OpMove, tmp, src(0));
    Emit(OpMove, dst(1), AdvanceBy(arg, arg->size()));
    Emit(OpMove, dst(0), tmp);
    if (num_src() > 1)
      Emit(OpAdd, dst(2), src(1), src(2));
    break;
  }
  case OP_movk: {
    auto* reg = dyn_cast<RegArg>(dst(0));
    if (!reg)
      return DECODE_FAIL("movk dst is not a register");
    reg->set_keep_rest(true);
    reg->set_size(src(1)->size());
    if (num_src() == 4) {
      SAN_WARN(!(opnd_get_flags(instr_get_src(instr(), 2)) & DR_OPND_IS_SHIFT));
      reg->set_offset(BitSize(src_imm(3)));
    }
    Emit(OpMove, reg, src(1));
    break;
  }
  case OP_movn:
    if (num_src() > 2)
      set_src(0, ShiftExtend(src(0), 1));
    Emit(OpXor, dst(0), src(0), NewImmArg(~0ul));
    break;
  case OP_movi:
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_umov:
    dyn_cast<RegArg>(src(0))->set_offset(ByteSize(src_imm(1)));
    src(0)->set_size(ByteSize(1 << src_imm(2)));
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_dup:
    src(0)->set_size(ByteSize(1 << src_imm(1)));
    Emit(OpBroadcast, dst(0), src(0));
    break;
  case OP_ld1:
    src(0)->set_size(dst(0)->size());
    Emit(OpMove, dst(0), src(0));
    Emit(OpMove, dst(1), AdvanceBy(src(0), src(0)->size()));
    Emit(OpAdd, dst(2), src(2), src(3));
    break;
  case OP_adrp: {
    auto src = instr_get_src(instr(), 0);
    SAN_WARN(!opnd_is_rel_addr(src));
    auto addr = NewImmArg(reinterpret_cast<uptr>(opnd_get_addr(src)));
    Emit(OpAnd, dst(0), addr, NewImmArg(~Bitmask(BitSize(12))));
    break;
  }
  case OP_add:
    if (num_src() > 2)
      set_src(1, ShiftExtend(src(1), 2));
    Emit(OpAdd, dst(0), src(0), src(1));
    break;
  case OP_adds:
    if (num_src() > 2)
      set_src(1, ShiftExtend(src(1), 2));
    Emit(OpAdd, dst(0), src(0), src(1)).Set(kFlagsArith);
    break;
  case OP_addp: {
    ByteSize size(1 << src_imm(2));
    // Note: need to use TEMP0 b/c src/dst can overlap.
    auto* tmp = NewRegArg(kTEMP0, size, 0, true);
    if (!dyn_cast<RegArg>(dst(0)) || !dyn_cast<RegArg>(src(0)) ||
        !dyn_cast<RegArg>(src(1))) {
      DECODE_FAIL("addp args are not registers");
      return;
    }
    uptr elems = *(src(0)->size() / size);
    src(0)->set_size(size);
    src(1)->set_size(size);
    auto* arg = src(0);
    for (uptr i = 0; i < elems; i++) {
      if (i == elems / 2)
        arg = src(1);
      auto* next = AdvanceBy(arg, size);
      Emit(OpAdd, tmp, arg, next);
      arg = AdvanceBy(next, size);
      tmp = AdvanceBy(tmp, size);
    }
    Emit(OpMove, dst(0), NewRegArg(kTEMP0, dst(0)->size()));
    break;
  }
  case OP_sbfm:
  case OP_ubfm: {
    // TODO(dvyukov): this is most likely wrong (need to somehow account for
    // 'bits' in Shl case?). But I can't comprehend the instruction meaning
    // based on the Arm manual.
    uptr shift = src_imm(1);
    uptr bits = src_imm(2);
    if (shift <= bits) {
      if (bits > 63) {
        auto mask = NewImmArg((1ul << (bits + 1)) - 1);
        Emit(OpAnd, dst(0), mask, src(0));
        set_src(0, dst(0));
      }
      Emit(op == OP_ubfm ? OpShiftRight : OpShiftRightArith, dst(0), src(0),
           src(1));
    } else {
      Emit(OpShiftLeft, dst(0), src(0), NewImmArg(64 - shift));
    }
    break;
  }
  case OP_sub:
    if (num_src() > 2)
      set_src(1, ShiftExtend(src(1), 2));
    Emit(OpSub, dst(0), src(0), src(1));
    break;
  case OP_subs:
    if (num_src() > 2)
      set_src(1, ShiftExtend(src(1), 2));
    Emit(OpSub, dst(0), src(0), src(1)).Set(kFlagsArith);
    break;
  case OP_umulh:
    Emit(OpMultiplyHigh, dst(0), src(0), src(1));
    break;
  case OP_msub:
    Emit(OpMultiply, NewRegArg(kTEMP0), src(0), src(1));
    Emit(OpSub, dst(0), src(2), NewRegArg(kTEMP0));
    break;
  case OP_and:
    if (num_src() > 2)
      set_src(1, ShiftExtend(src(1), 2));
    Emit(OpAnd, dst(0), src(0), src(1));
    break;
  case OP_ands:
    if (num_src() > 2)
      set_src(1, ShiftExtend(src(1), 2));
    Emit(OpAnd, dst(0), src(0), src(1)).Set(kFlagsLogical);
    break;
  case OP_orr:
    if (num_src() > 2)
      set_src(1, ShiftExtend(src(1), 2));
    Emit(OpOr, dst(0), src(0), src(1));
    break;
  case OP_lsrv:
    Emit(OpShiftRight, dst(0), src(0), src(1));
    break;
  case OP_bic:
    if (num_src() > 2)
      set_src(1, ShiftExtend(src(1), 2));
    Emit(OpXor, NewRegArg(kTEMP0), src(1), NewImmArg(~0ul));
    Emit(OpAnd, dst(0), NewRegArg(kTEMP0), src(0));
    break;
  case OP_rbit:
    Emit(OpReverseBits, dst(0), src(0));
    break;
  case OP_clz:
    Emit(OpReverseBits, NewRegArg(kTEMP0), src(0));
    Emit(OpCountTrailingZeros, dst(0), NewRegArg(kTEMP0));
    break;
  case OP_ccmp:
    Emit(OpSub, NewRegArg(kRZ), src(1), src(0))
        .Set(kFlagsArith)
        .Set(Predicate());
    Emit().Set(FlagsFromNZCV(src_imm(2))).Set(Predicate().Inverted());
    break;
  case OP_cmeq:
    if (dyn_cast<ImmArg>(src(1)))
      src(1)->set_size(kPtrSize);
    Emit(OpCompareEQ, dst(0), src(0), src(1)).set_vector_size(ByteSize(1));
    break;
  case OP_csinc:
    Emit(OpMove, dst(0), src(0)).Set(SrcPredicate(2));
    Emit(OpAdd, dst(0), src(1), NewImmArg(1)).Set(SrcPredicate(2).Inverted());
    break;
  case OP_csinv:
    Emit(OpMove, dst(0), src(0)).Set(SrcPredicate(2));
    Emit(OpXor, dst(0), src(1), NewImmArg(~0ul))
        .Set(SrcPredicate(2).Inverted());
    break;
  case OP_csneg:
    Emit(OpMove, dst(0), src(0)).Set(SrcPredicate(2));
    Emit(OpSub, dst(0), NewImmArg(0), src(1)).Set(SrcPredicate(2).Inverted());
    break;
  case OP_csel:
    Emit(OpMove, dst(0), src(0)).Set(SrcPredicate(2));
    Emit(OpMove, dst(0), src(1)).Set(SrcPredicate(2).Inverted());
    break;
  case OP_b:
    Emit(OpMove, NewRegArg(kPC), src(0));
    break;
  case OP_br:
    Emit(OpMove, NewRegArg(kPC), src(0)).Set(Instr::Flags{0, kFlagBranchJump});
    break;
  case OP_bl:
    Emit(OpMove, dst(0), NewImmArg(NextPC()));
    Emit(OpMove, NewRegArg(kPC), src(0));
    break;
  case OP_blr:
    Emit(OpMove, dst(0), NewImmArg(NextPC()));
    Emit(OpMove, NewRegArg(kPC), src(0)).Set(Instr::Flags{0, kFlagBranchCall});
    break;
  case OP_bcond:
    Emit(OpMove, NewRegArg(kPC), src(0)).Set(Predicate());
    break;
  case OP_tbz:
  case OP_tbnz:
  case OP_cbz:
  case OP_cbnz: {
    auto mask =
        NewImmArg(op == OP_tbz || op == OP_tbnz ? 1ul << src_imm(2) : ~0ul);
    auto flags = Instr::Flags{kFlagZero, 0, 0, 0, true};
    auto pred = Instr::Predicate{
        kFlagZero, 0, 0, 0, op == OP_cbnz || op == OP_tbnz, true};
    Emit(OpAnd, NewRegArg(kRZ), src(1), mask).Set(flags);
    Emit(OpMove, NewRegArg(kPC), src(0)).Set(pred);
    break;
  }
  case OP_cas:
  case OP_casa:
  case OP_casl:
  case OP_casal:
    Emit(OpSub, NewRegArg(kRZ, src(1)->size()), src(0), src(2))
        .Set(Instr::Flags{kFlagZero, 0, 0, 0, true});
    Emit(OpMove, dst(1), src(1))
        .Set(Instr::Predicate{kFlagZero, 0, 0, 0, 0, true});
    Emit(OpMove, dst(0), src(2))
        .Set(Instr::Predicate{0, kFlagZero, 0, 0, 0, true});
    break;
  case OP_svc:
    // We can't predict the syscall result, so mark it as undefined.
    Emit(OpSyscall).SetUndef(kX0);
    break;
  case OP_ret:
    Emit(OpMove, NewRegArg(kPC), src(0));
    break;
  case OP_yield:
  case OP_nop:
    Emit();
    break;
  default:
    DECODE_UNIMPL("unimplemented opcode");
    break;
  }
}

Arg* Arm64Decoder::ShiftExtend(Arg* arg, int shift_arg_idx) {
  Arg* res = arg;
  auto exop = instr_get_src(instr(), shift_arg_idx);
  if (opnd_get_flags(exop) & DR_OPND_IS_SHIFT) {
    OpRef shift_op = ShiftToOpRef(exop);
    auto shift_val = dyn_cast<ImmArg>(src(shift_arg_idx + 1));
    if (shift_val->val() != 0) {
      // If this is a shift of an immediate, then just compute the new value.
      if (auto* arg_imm = dyn_cast<ImmArg>(arg)) {
        res = NewImmArg(ShiftVal(shift_op, arg_imm->val(), shift_val->val()));
      } else {
        res = NewRegArg(kTEMP3);
        Emit(shift_op, res, arg, shift_val);
      }
    }
  } else if (opnd_get_flags(exop) & DR_OPND_IS_EXTEND) {
    auto ext = static_cast<dr_extend_type_t>(opnd_get_immed_int(exop));
    bool sign = false;
    res->set_size(DecodeExtend(ext, sign));
    res->set_sign_extend(sign);
  } else {
    // In some cases flags are 0, see:
    // https://groups.google.com/g/dynamorio-users/c/XcVJv-uUoMs
    SAN_WARN(opnd_get_flags(exop), "arg=%u flags=%u", shift_arg_idx,
             opnd_get_flags(exop));
  }
  return res;
}

OpRef Arm64Decoder::ShiftToOpRef(opnd_t opnd) {
  SAN_CHECK(opnd_get_flags(opnd) & DR_OPND_IS_SHIFT);
  int val = opnd_get_immed_int(opnd);
  switch (val) {
  case DR_SHIFT_LSL:
    return OpShiftLeft;
  case DR_SHIFT_LSR:
    return OpShiftRight;
  case DR_SHIFT_ASR:
    return OpShiftRightArith;
  default:
    DECODE_FAIL("unhandled shift type: %d", val);
    return OpShiftLeft;
  }
}

RegIdx Arm64Decoder::MapDRReg(reg_id_t reg0, ByteSize& offset) {
  offset = 0;
  reg_id_t reg = reg_to_pointer_sized(reg0);
  switch (reg) {
  case DR_REG_NULL:
  case DR_REG_XZR:
    return kRZ;
  case DR_REG_SP:
    return kSP;
  case DR_REG_X30:
    return kLR;
  case DR_REG_TPIDRURW:
  case DR_REG_TPIDRURO:
    return kTPIDR;
  }
  if (reg >= DR_REG_X0 && reg <= DR_REG_X29)
    return static_cast<RegIdx>(static_cast<int>(kX0) + reg - DR_REG_X0);
  if (reg >= DR_REG_Q0 && reg <= DR_REG_Q31)
    return static_cast<RegIdx>(static_cast<int>(kQ0) + (reg - DR_REG_Q0) * 2);
  if (reg >= DR_REG_Z0 && reg <= DR_REG_Z31)
    return static_cast<RegIdx>(static_cast<int>(kQ0) + (reg - DR_REG_Z0) * 2);
  DECODE_UNIMPL("unsupported register %s (%d)", get_register_name(reg0), reg0);
  return kRZ;
}

Instr::Predicate Arm64Decoder::MakePredicate(dr_pred_type_t pred) {
  switch (pred) {
  case DR_PRED_EQ:
    return {kFlagZero};
  case DR_PRED_NE:
    return {0, kFlagZero};
  case DR_PRED_CS:
    return {kFlagCarry, 0};
  case DR_PRED_CC:
    return {0, kFlagCarry};
  case DR_PRED_MI:
    return {kFlagSign, 0};
  case DR_PRED_PL:
    return {0, kFlagSign};
  case DR_PRED_VS:
    return {kFlagOverflow};
  case DR_PRED_VC:
    return {0, kFlagOverflow};
  case DR_PRED_HI:
    return {kFlagCarry, kFlagZero};
  case DR_PRED_LS:
    return {kFlagCarry, kFlagZero, 0, 0, true};
  case DR_PRED_GE:
    return {0, 0, kFlagSign | kFlagOverflow};
  case DR_PRED_LT:
    return {0, 0, 0, kFlagSign | kFlagOverflow};
  case DR_PRED_GT:
    return {0, kFlagZero, kFlagSign | kFlagOverflow};
  case DR_PRED_LE:
    return {0, kFlagZero, kFlagSign | kFlagOverflow, 0, true};
  case DR_PRED_AL:
    return {};
  case DR_PRED_NV:
    return {0, 0, 0, 0, true};
  default:
    DECODE_FAIL("bad instruction predicate: %d", pred);
    return {};
  }
}

}  // namespace gwpsan