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

#include "gwpsan/core/decoder_x86.h"

#include "gwpsan/import/drdecode/include/dr_ir_opcodes_x86.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/type_id.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/decoder.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/operation.h"
#include "gwpsan/core/regset.h"

namespace gwpsan {

namespace {
constexpr Instr::Flags kFlagsArith = {.compute = kFlagOverflow | kFlagCarry |
                                                 kFlagAuxCarry | kFlagZero |
                                                 kFlagSign | kFlagParity};
constexpr Instr::Flags kFlagsLogical = {
    .compute = kFlagZero | kFlagSign | kFlagParity,
    .reset = kFlagOverflow | kFlagCarry | kFlagAuxCarry};
constexpr Instr::Flags kFlagsMultiply = {
    .compute = kFlagCarry | kFlagOverflow,
    .undefined = kFlagZero | kFlagParity | kFlagSign | kFlagAuxCarry};

RegIdx XMM(int i) {
  SAN_WARN(kXMM0 + i > kXMMLAST);
  return static_cast<RegIdx>(kXMM0 + i);
}

template <int i>
RegIdx VectorTempReg() {
  static_assert(i < 4, "bad vector register index");
  return static_cast<RegIdx>(kTEMP0 + i * kVectorRegWords);
}

// Private DynamoRIO consts that we need for some checks.
constexpr unsigned PREFIX_DATA = 0x80;
constexpr unsigned PREFIX_ADDR = 0x100;
}  // namespace

X86Decoder::X86Decoder(uptr pc, uptr pc_copy)
    : DynamoRIODecoder(pc, pc_copy) {}

void X86Decoder::DecodeArch() {
  const auto op = opcode();

  // Smaller immediates seem to be always sign-extended.
  // If it turns out to be not the case, an instruction can opt-out
  // with set_sign_extend(false), or we can add this as an Operation property.
  if (num_dst() >= 1)
    if (auto* arg = dyn_cast<ImmArg>(src(0)))
      arg->set_sign_extend(arg->size() < dst(0)->size());
  if (auto* arg = dyn_cast<ImmArg>(src(1)))
    arg->set_sign_extend(arg->size() < src(0)->size());

  // Zero upper part of XMM registers for VEX/EVEX instructions.
  if (instr_zeroes_zmmh(instr()))
    ZeroUpperXMMRegister(dst(0));

  // A lot of vector instructions have variants where the first source register
  // is either a vector/memory operand or a mask register; if the mask register
  // is provided, the vector/memory operand is shifted to the second argument.
  // Deal with this by shifting the "normal" arguments back and keeping mask
  // register in `src_mask`, which simplifies special casing implementations.
  RegArg* src_mask = nullptr;
  if (auto* reg = dyn_cast<RegArg>(src(0)); reg && IsMaskReg(reg->reg())) {
    bool masking_supported = true;
    switch (op) {
    case OP_kmovb:
    case OP_kmovw:
    case OP_kmovd:
    case OP_kmovq:
      // These instructions don't need special operand treatment.
      break;
    // Despite most AVX512 instructions having a mask register variant, there is
    // no point in supporting them everywhere if we don't need them.  Explicitly
    // list instructions where we have added support.
    case OP_vpbroadcastb:
      // For these instructions we support the AVX512 variants, but not yet with
      // write masking.
      masking_supported = false;
      [[fallthrough]];
    case OP_vpmovzxbw:
    case OP_vpmovzxbd:
    case OP_vpmovzxbq:
    case OP_vpmovzxwd:
    case OP_vpmovzxwq:
    case OP_vpmovzxdq:
    case OP_vpcmpeqb:
    case OP_vpcmpeqw:
    case OP_vpcmpeqd:
    case OP_vpcmpeqq:
      src_mask = static_cast<RegArg*>(src_pop());
      if (src_mask->reg() == kK0) {
        // From the Intel Manual: "[...] k0 can not be used as a predicate
        // operand. [...] k0 will instead select an implicit opmask value of
        // 0xFFFFFFFFFFFFFFFF, thereby effectively disabling masking. [...] k0
        // can still be used for any instruction that takes opmask register(s)
        // as operand(s)."
        //
        // This means that for vector instructions (that only take a vector or
        // memory operand as source), we know that if we see k0 as source, it
        // means "masking is disabled".
        src_mask = nullptr;
        break;
      } else if (masking_supported)
        break;
      [[fallthrough]];
    default:
      DECODE_UNIMPL("mask register unsupported");
      return;
    }
  }

  switch (op) {
  case OP_vmovdqu:
  case OP_movups:
  case OP_vmovups:
  case OP_movupd:
  case OP_vmovupd:
  case OP_movdqu:
  case OP_movlpd:
  case OP_movzx:
  case OP_mov_ld:
  case OP_mov_st:
  case OP_mov_imm:
  case OP_lddqu:
  case OP_vlddqu:
  case OP_kmovb:
  case OP_kmovw:
  case OP_kmovd:
  case OP_kmovq:
    switch (op) {
    // Instruction operates on fewer bytes than the register arguments.
    case OP_kmovb:
      dst(0)->set_size(ByteSize(1));
      break;
    case OP_kmovw:
      dst(0)->set_size(ByteSize(2));
      break;
    case OP_kmovd:
      dst(0)->set_size(ByteSize(4));
      break;
    }
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_movdqa:
  case OP_vmovdqa:
  case OP_movaps:
  case OP_vmovaps:
  case OP_movapd:
  case OP_vmovapd:
    src(0)->set_required_alignment(src(0)->size());
    dst(0)->set_required_alignment(dst(0)->size());
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_movsd:
  case OP_vmovsd: {
    if (dst(0)->size() == ByteSize(16) && src(0)->size() == ByteSize(8)) {
      dst(0)->set_size(kPtrSize);
      if (num_src() == 2) {
        Emit(OpMove, dst(0), src(1));
        Emit(OpMove, NextWord(dst(0)), NextWord(src(0)));
      } else {
        Emit(OpMove, dst(0), src(0));
        Emit(OpMove, NextWord(dst(0)), NewImmArg(0));
      }
    } else {
      Emit(OpMove, dst(0), src(0));
    }
    break;
  }
  case OP_movsxd:
  case OP_movsx:
    src(0)->set_sign_extend(true);
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_cwde:
    // DynamoRIO says it's "cwde %ax -> %ax", while it's "cwde %al -> %ax",
    // see https://github.com/DynamoRIO/dynamorio/issues/5448
    // TODO: remove this when/if the issue is resolved.
    src(0)->set_size(dst(0)->size() / BitSize(2));
    src(0)->set_sign_extend(true);
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_movd:
  case OP_movq:
  case OP_vmovd:
  case OP_vmovq:
    if (dst(0)->size() == WordSize(2) ||
        (dyn_cast<RegArg>(dst(0)) &&
         IsVectorReg(dyn_cast<RegArg>(dst(0))->reg()))) {
      dst(0)->set_size(kPtrSize);
      Emit(OpMove, dst(0), src(0));
      Emit(OpMove, NextWord(dst(0)), NewImmArg(0));
    } else {
      src(0)->set_size(kPtrSize);
      Emit(OpMove, dst(0), src(0));
    }
    break;
  case OP_movhpd:
  case OP_movhps:
    if (dyn_cast<RegArg>(dst(0)))
      dst(0)->AdvanceBy(kPtrSize);
    else if (dyn_cast<RegArg>(src(0)))
      src(0)->AdvanceBy(kPtrSize);
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_movlps:
    // If both operands are registers, this is actually what ISA calls MOVHLPS
    // (it does not have a separate opcode).
    if (dyn_cast<RegArg>(dst(0)) && dyn_cast<RegArg>(src(0)))
      src(0)->AdvanceBy(kPtrSize);
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_movss:
  case OP_vmovss: {
    auto* reg = dyn_cast<RegArg>(dst(0));
    if (num_src() == 2) {
      if (!reg)
        return DECODE_FAIL("vmovss dst is not reg");
      // Need to use temp reg here b/c dst/src can overlap.
      auto* tmp = NewRegArg(kTEMP0, reg->size());
      src(0)->set_size(reg->size());
      Emit(OpMove, tmp, src(0));
      Emit(OpMove, NewRegArg(kTEMP0, src(1)->size(), 0, true), src(1));
      Emit(OpMove, reg, tmp);
    } else {
      if (reg) {
        if (dyn_cast<MemArg>(src(0)))
          Emit(OpMove, CopyArg(dst(0)), NewImmArg(0));
        else
          reg->set_keep_rest(true);
        reg->set_size(ByteSize(4));
      }
      Emit(OpMove, dst(0), src(0));
    }
    break;
  }
  case OP_cvtsi2ss:
  case OP_cvtsi2sd:
    src(0)->set_sign_extend(true);
    dyn_cast<RegArg>(dst(0))->set_keep_rest(true);
    Emit(OpConvertIntToFloat, dst(0), src(0));
    break;
  case OP_cvtss2si:
  case OP_cvtsd2si:
    Emit(OpConvertFloatToInt, dst(0), src(0), NewImmArg(0));
    break;
  case OP_cvttss2si:
  case OP_cvttsd2si:
    Emit(OpConvertFloatToInt, dst(0), src(0), NewImmArg(1));
    break;
  case OP_cvtss2sd:
  case OP_cvtsd2ss:
    dyn_cast<RegArg>(dst(0))->set_keep_rest(true);
    Emit(OpConvertFloatToFloat, dst(0), src(0));
    break;
  case OP_lea:
    if (auto* arg = dyn_cast<MemArg>(src(0))) {
      arg->address_arg();
      arg->set_seg_reg(kRZ);  // LEA ignores the segment base.
    }
    // If the instruction has 0x66/0x67 prefixes DynamoRIO claims incorrect
    // result size. It's unclear what's the proper way to fetch this info
    // from DynamoRIO. We check for PREFIX_DATA/ADDR private consts.
    if (instr_get_prefix_flag(instr(), PREFIX_DATA))
      dst(0)->set_size(ByteSize(2));
    else if (instr_get_prefix_flag(instr(), PREFIX_ADDR))
      dst(0)->set_size(ByteSize(4));
    Emit(OpMove, dst(0), src(0));
    break;
  case OP_push_imm:
  case OP_push: {
    auto* reg = dyn_cast<RegArg>(src(0));
    // Push FS/GS refers to the segment registers themselves (the segment
    // descriptor, not the FS/GS base). They tend to have 0 value on linux.
    // This come up only during fuzzing so far.
    if (reg && (reg->reg() == kFS || reg->reg() == kGS))
      reg->set_reg(kRZ);
    Emit(OpMove, dst(1), src(0));
    Emit(OpSub, dst(0), src(1), NewImmArg(Bytes(dst(1)->size())));
    break;
  }
  case OP_pop: {
    auto* reg = dyn_cast<RegArg>(dst(0));
    // "pop fs/gs" only happened during fuzzing so far and we crash on it.
    // Hopefully real code doesn't mess with segment selectors.
    if (reg && (reg->reg() == kFS || reg->reg() == kGS))
      DECODE_UNIMPL("pop fs/gs");
    uptr size = Bytes(dst(0)->size());
    Emit(OpAdd, dst(1), src(0), NewImmArg(size));
    dyn_cast<MemArg>(src(1))->set_offset(Addr(-size));
    Emit(OpMove, dst(0), src(1));
    break;
  }
  case OP_pushf:
    Emit(OpMove, dst(1), NewRegArg(kFLAGS));
    Emit(OpSub, dst(0), src(0), NewImmArg(Bytes(dst(1)->size())));
    break;
  case OP_popf: {
    constexpr uptr kSetFlags = kAllFlags | 0x204500;  // ID, NT, DF, TF
    uptr size = Bytes(src(1)->size());
    Emit(OpAdd, dst(0), src(0), NewImmArg(size));
    dyn_cast<MemArg>(src(1))->set_offset(Addr(-size));
    Emit(OpAnd, NewRegArg(kTEMP0), src(1), NewImmArg(kSetFlags));
    Emit(OpAnd, NewRegArg(kTEMP1), NewRegArg(kFLAGS), NewImmArg(~kSetFlags));
    Emit(OpOr, NewRegArg(kFLAGS), NewRegArg(kTEMP0), NewRegArg(kTEMP1));
    break;
  }
  case OP_call_ind:
  case OP_call:
    Emit(OpMove, dst(1), NewImmArg(NextPC()));
    Emit(OpSub, dst(0), src(1), NewImmArg(sizeof(uptr)));
    // We used to mark registers that are not used to pass arguments as uninit
    // here and unmark callee-saved registers on RET. Potentially it can find
    // some compiler/asm bugs. However, it turned out to be problematic
    // w/o precise compiler meta information because of functions with custom
    // calling convention (e.g. some functions in VDSO, some tls-related
    // functions, some asan callbacks).
    Emit(OpMove, NewRegArg(kPC), src(0));
    break;
  case OP_ret:
    Emit(OpAdd, dst(0), src(0), NewImmArg(sizeof(uptr)));
    Emit(OpMove, NewRegArg(kPC),
         NewMemArg(kRZ, kSP, kRZ, 0, 0, false, Addr(-8), kPtrSize));
    break;
  case OP_leave:
    dst(1)->set_size(src(2)->size());
    Emit(OpAdd, dst(0), src(0), NewImmArg(Bytes(src(2)->size())));
    Emit(OpMove, dst(1), src(2));
    break;
  case OP_test:
    Emit(OpAnd, NewRegArg(kRZ, src(0)->size()), src(0), src(1))
        .Set(kFlagsLogical);
    break;
  case OP_cmp:
    Emit(OpSub, NewRegArg(kRZ, src(0)->size()), src(0), src(1))
        .Set(kFlagsArith);
    break;
  case OP_cdq: {
    auto sign = NewImmArg(SignBit(src(0)->size()));
    Emit(OpAnd, NewRegArg(kTEMP0), src(0), sign);
    Emit(OpCompareEQ, dst(0), NewRegArg(kTEMP0), sign);
    break;
  }
  case OP_pcmpeqb:
  case OP_pcmpeqw:
  case OP_pcmpeqd:
  case OP_pcmpeqq:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpcmpeqb:
  case OP_vpcmpeqw:
  case OP_vpcmpeqd:
  case OP_vpcmpeqq: {
    if (src(0)->size() != src(1)->size()) {
      // TODO(elver): Probably a DynamoRIO issue, that it tries to interpret
      // encodings that real CPUs don't actually support (fuzzer finds them).
      DECODE_UNIMPL("impossible?");
      break;
    }
    BitSize vector_size;
    switch (op) {
    case OP_pcmpeqb:
    case OP_vpcmpeqb:
      vector_size = ByteSize(1);
      break;
    case OP_pcmpeqw:
    case OP_vpcmpeqw:
      vector_size = ByteSize(2);
      break;
    case OP_pcmpeqd:
    case OP_vpcmpeqd:
      vector_size = ByteSize(4);
      break;
    case OP_pcmpeqq:
    case OP_vpcmpeqq:
      vector_size = ByteSize(8);
      break;
    default:
      break;
    }
    auto* tmp = NewRegArg(VectorTempReg<0>(), src(0)->size());
    Emit(OpCompareEQ, tmp, src(0), src(1)).set_vector_size(vector_size);
    if (auto* dst_reg = dyn_cast<RegArg>(dst(0)); IsMaskReg(dst_reg->reg())) {
      Emit(OpMove, dst_reg, NewImmArg(0));
      auto* tmp_elem = CopyArg(tmp);
      tmp_elem->set_size(vector_size);
      for (BitSize elem; elem < src(0)->size(); elem += vector_size) {
        const uptr idx = *(elem / vector_size);
        Emit(OpAnd, NewRegArg(kRZ), tmp_elem, NewImmArg(1ul))
            .Set(Instr::Flags{.compute = kFlagZero, .temp = true});
        Emit(OpOr, dst_reg, dst_reg, NewImmArg(1ul << idx))
            .Set(Instr::Predicate{.reset = kFlagZero, .temp = true});
        tmp_elem = AdvanceBy(tmp_elem, vector_size);
      }
      if (src_mask)
        Emit(OpAnd, dst_reg, dst_reg, src_mask);
    } else {
      Emit(OpMove, dst(0), tmp);
    }
    break;
  }
  case OP_and:
    Emit(OpAnd, dst(0), src(1), src(0)).Set(kFlagsLogical);
    break;
  case OP_andps:
  case OP_andpd:
  case OP_pand:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpand:
    Emit(OpAnd, dst(0), src(1), src(0));
    break;
  case OP_or:
    Emit(OpOr, dst(0), src(1), src(0)).Set(kFlagsLogical);
    break;
  case OP_orps:
  case OP_orpd:
  case OP_por:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpor:
    Emit(OpOr, dst(0), src(1), src(0));
    break;
  case OP_xor:
    Emit(OpXor, dst(0), src(1), src(0)).Set(kFlagsLogical);
    break;
  case OP_xorps:
  case OP_xorpd:
  case OP_pxor:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vxorps:
  case OP_vxorpd:
  case OP_vpxor:
    Emit(OpXor, dst(0), src(1), src(0));
    break;
  case OP_andn:
  case OP_pandn:
  case OP_vpandn:
  case OP_andnps:
  case OP_andnpd: {
    auto swap = op == OP_pandn || op == OP_andnps || op == OP_andnpd;
    auto tmp = NewRegArg(kTEMP0, dst(0)->size());
    Emit(OpXor, tmp, src(swap ? 1 : 0), NewImmArg(-1));
    Emit(OpAnd, dst(0), tmp, src(swap ? 0 : 1))
        .Set(op == OP_andn ? Instr::Flags{.compute = kFlagZero | kFlagSign,
                                          .reset = kFlagOverflow | kFlagCarry,
                                          kFlagAuxCarry | kFlagParity}
                           : Instr::Flags{});
    break;
  }
  case OP_sub:
    Emit(OpSub, dst(0), src(1), src(0)).Set(kFlagsArith);
    break;
  case OP_psubb:
    src(0)->set_required_alignment(src(0)->size());
    Emit(OpSub, dst(0), src(1), src(0)).set_vector_size(ByteSize(1));
    break;
  case OP_vpsubb:
    Emit(OpSub, dst(0), src(0), src(1)).set_vector_size(ByteSize(1));
    break;
  case OP_psubw:
    src(0)->set_required_alignment(src(0)->size());
    Emit(OpSub, dst(0), src(1), src(0)).set_vector_size(ByteSize(2));
    break;
  case OP_vpsubw:
    Emit(OpSub, dst(0), src(0), src(1)).set_vector_size(ByteSize(2));
    break;
  case OP_psubd:
    src(0)->set_required_alignment(src(0)->size());
    Emit(OpSub, dst(0), src(1), src(0)).set_vector_size(ByteSize(4));
    break;
  case OP_vpsubd:
    Emit(OpSub, dst(0), src(0), src(1)).set_vector_size(ByteSize(4));
    break;
  case OP_psubq:
    src(0)->set_required_alignment(src(0)->size());
    Emit(OpSub, dst(0), src(1), src(0));
    break;
  case OP_vpsubq:
    Emit(OpSub, dst(0), src(0), src(1));
    break;
  case OP_subps:
    src(0)->set_required_alignment(src(0)->size());
    Emit(OpSubFloat, dst(0), src(1), src(0)).set_vector_size(ByteSize(4));
    break;
  case OP_vsubps:
    Emit(OpSubFloat, dst(0), src(0), src(1)).set_vector_size(ByteSize(4));
    break;
  case OP_subpd:
  case OP_subsd:
    src(0)->set_required_alignment(src(0)->size());
    Emit(OpSubFloat, dst(0), src(1), src(0));
    break;
  case OP_vsubpd:
    Emit(OpSubFloat, dst(0), src(0), src(1));
    break;
  case OP_vsubss:
  case OP_vsubsd: {
    auto* tmp = NewRegArg(kTEMP0, dst(0)->size());
    Emit(OpMove, tmp, src(0));
    auto* res = NewRegArg(kTEMP0, src(1)->size(), 0, true);
    Emit(OpSubFloat, res, res, src(1));
    Emit(OpMove, dst(0), tmp);
    break;
  }
  case OP_comiss:
  case OP_comisd:
  case OP_ucomiss:
  case OP_ucomisd:
  case OP_vcomiss:
  case OP_vcomisd:
  case OP_vucomiss:
  case OP_vucomisd:
    Emit(OpSubFloat, NewRegArg(kRZ, src(0)->size()), src(1), src(0))
        .Set(Instr::Flags{.compute = kFlagZero | kFlagParity | kFlagCarry,
                          .reset = kFlagOverflow | kFlagAuxCarry | kFlagSign});
    break;
  case OP_add:
    Emit(OpAdd, dst(0), src(1), src(0)).Set(kFlagsArith);
    break;
  case OP_paddb:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpaddb:
    Emit(OpAdd, dst(0), src(1), src(0)).set_vector_size(ByteSize(1));
    break;
  case OP_paddw:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpaddw:
    Emit(OpAdd, dst(0), src(1), src(0)).set_vector_size(ByteSize(2));
    break;
  case OP_paddd:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpaddd:
    Emit(OpAdd, dst(0), src(1), src(0)).set_vector_size(ByteSize(4));
    break;
  case OP_paddq:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpaddq:
    Emit(OpAdd, dst(0), src(1), src(0));
    break;
  case OP_addps:
    src(0)->set_required_alignment(src(0)->size());
    Emit(OpAddFloat, dst(0), src(1), src(0)).set_vector_size(ByteSize(4));
    break;
  case OP_vaddps:
    Emit(OpAddFloat, dst(0), src(0), src(1)).set_vector_size(ByteSize(4));
    break;
  case OP_addpd:
  case OP_addsd:
    src(0)->set_required_alignment(src(0)->size());
    Emit(OpAddFloat, dst(0), src(1), src(0));
    break;
  case OP_vaddpd:
    Emit(OpAddFloat, dst(0), src(0), src(1));
    break;
  case OP_addss:
    dyn_cast<RegArg>(dst(0))->set_keep_rest(true);
    Emit(OpAddFloat, dst(0), src(0), src(1));
    break;
  case OP_vaddss:
  case OP_vaddsd: {
    auto* tmp = NewRegArg(kTEMP0, dst(0)->size());
    Emit(OpMove, tmp, src(0));
    auto* res = NewRegArg(kTEMP0, src(1)->size(), 0, true);
    Emit(OpAddFloat, res, res, src(1));
    Emit(OpMove, dst(0), tmp);
    break;
  }
  case OP_inc:
    Emit(OpAdd, dst(0), src(0), NewImmArg(1))
        .Set(Instr::Flags{.compute = kFlagOverflow | kFlagAuxCarry | kFlagZero |
                                     kFlagSign | kFlagParity});
    break;
  case OP_dec:
    Emit(OpSub, dst(0), src(0), NewImmArg(1))
        .Set(Instr::Flags{.compute = kFlagOverflow | kFlagAuxCarry | kFlagZero |
                                     kFlagSign | kFlagParity});
    break;
  case OP_adc:
  case OP_adcx: {
    // Need to use temp flags so that we don't execute both OpAddOne and OpAdd.
    auto pred = Instr::Predicate{.set = kFlagCarry, .temp = true};
    Emit(OpMove, NewRegArg(kTEMPFLAGS), NewRegArg(kFLAGS));
    // TODO(dvyukov): This does not model meta info precisely.
    // If kFlagCarry is uninit, then we will either report use of uninit
    // or mark the whole result as uninit, while in reality only some low
    // bits are uninit. It's unclear how to handle this w/o 3-operand
    // instructions or special casing the operation.
    const auto flags = op == OP_adc ? kFlagsArith : Instr::Flags{kFlagCarry};
    Emit(OpAddOne, dst(0), src(1), src(0)).Set(pred).Set(flags);
    Emit(OpAdd, dst(0), src(1), src(0)).Set(pred.Inverted()).Set(flags);
    break;
  }
  case OP_sbb: {
    // Need to use temp flags so that we don't execute both OpSubOne and OpSub.
    auto pred = Instr::Predicate{.set = kFlagCarry, .temp = true};
    Emit(OpMove, NewRegArg(kTEMPFLAGS), NewRegArg(kFLAGS));
    Emit(OpSubOne, dst(0), src(1), src(0)).Set(pred).Set(kFlagsArith);
    Emit(OpSub, dst(0), src(1), src(0)).Set(pred.Inverted()).Set(kFlagsArith);
    break;
  }
  case OP_mul:
  case OP_mulx: {
    auto flags = op == OP_mul ? kFlagsMultiply : Instr::Flags{};
    if (src(0)->size() == ByteSize(1)) {
      Emit(OpMultiply, dst(0), src(0), src(1)).Set(flags);
    } else {
      auto tmp = NewRegArg(kTEMP0);
      Emit(OpMultiplyHigh, tmp, src(0), src(1)).Set(flags);
      Emit(OpMultiply, dst(op == OP_mul ? 1 : 0), src(0), src(1));
      Emit(OpMove, dst(op == OP_mul ? 0 : 1), tmp);
    }
    break;
  }
  case OP_imul:
    src(0)->set_sign_extend(true);
    src(1)->set_sign_extend(true);
    if (src(0)->size() == ByteSize(1)) {
      Emit(OpMultiplySigned, dst(0), src(0), src(1)).Set(kFlagsMultiply);
    } else {
      Arg* dst0 = num_dst() >= 2 ? dst(1) : dst(0);
      Arg* dst1 = num_dst() >= 2 ? dst(0) : NewRegArg(kRZ);
      Emit(OpMultiplySigned, NewRegArg(kTEMP0), src(0), src(1));
      Emit(OpMultiplyHighSigned, dst1, src(0), src(1)).Set(kFlagsMultiply);
      Emit(OpMove, dst0, NewRegArg(kTEMP0));
    }
    break;
  case OP_mulss:
    dyn_cast<RegArg>(dst(0))->set_keep_rest(true);
    Emit(OpMultiplyFloat, dst(0), src(1), src(0));
    break;
  case OP_mulsd:
    Emit(OpMultiplyFloat, dst(0), src(1), src(0));
    break;
  case OP_mulps:
    Emit(OpMultiplyFloat, dst(0), src(1), src(0)).set_vector_size(ByteSize(4));
    break;
  case OP_mulpd:
    Emit(OpMultiplyFloat, dst(0), src(1), src(0));
    break;
  case OP_div:
  case OP_idiv: {
    if (dst(0)->size() == ByteSize(1))
      dyn_cast<RegArg>(dst(1))->set_keep_rest(true);
    // It can be in memory, copy to avoid loading twice.
    auto* div = NewRegArg(kTEMP1, src(0)->size());
    Emit(OpMove, div, src(0));
    auto* tmp = NewRegArg(kTEMP0, dst(1)->size());
    Emit(op == OP_div ? OpDivide : OpDivideSigned, tmp, dst(1), dst(0), div)
        .SetUndef(kFLAGS)
        .SetUninit(kFLAGS);
    Emit(op == OP_div ? OpRemainder : OpRemainderSigned, dst(0), dst(1), dst(0),
         div);
    Emit(OpMove, dst(1), tmp);
    break;
  }
  case OP_divsd:
    Emit(OpDivideFloat, dst(0), src(1), src(0));
    break;
  case OP_neg:
    Emit(OpSub, dst(0), NewImmArg(0), src(0)).Set(kFlagsArith);
    break;
  case OP_not:
    Emit(OpXor, dst(0), src(0), NewImmArg(~0ul));
    break;
  case OP_sar:
    src(1)->set_sign_extend(true);
    Emit(OpShiftRightArith, dst(0), src(1), src(0)).Set(kFlagsArith);
    break;
  case OP_sarx:
    src(0)->set_sign_extend(true);
    Emit(OpShiftRightArith, dst(0), src(0), src(1));
    break;
  case OP_shr:
    Emit(OpShiftRight, dst(0), src(1), src(0)).Set(kFlagsArith);
    break;
  case OP_shrx:
    Emit(OpShiftRight, dst(0), src(0), src(1));
    break;
  case OP_shl:
    Emit(OpShiftLeft, dst(0), src(1), src(0)).Set(kFlagsArith);
    break;
  case OP_shlx:
    Emit(OpShiftLeft, dst(0), src(0), src(1));
    break;
  case OP_rol:
    Emit(OpRotateLeft, dst(0), src(1), src(0))
        .Set(Instr::Flags{kFlagOverflow | kFlagCarry});
    break;
  case OP_ror:
    Emit(OpRotateRight, dst(0), src(1), src(0))
        .Set(Instr::Flags{kFlagOverflow | kFlagCarry});
    break;
  case OP_rorx:
    Emit(OpRotateRight, dst(0), src(0), src(1));
    break;
  case OP_shld:
  case OP_shrd: {
    Instr::Predicate pred{};
    if (dst(0)->size() == BitSize(16)) {
      // If the shift is larger than the operand size,
      // the result and flags are undefined.
      const uptr mask = dyn_cast<RegArg>(src(1)) ? 0x10 : ~0xful;
      Emit(OpAnd, NewRegArg(kRZ), src(1), NewImmArg(mask))
          .Set(Instr::Flags{.compute = kFlagZero, .temp = true});
      pred = Instr::Predicate{.set = kFlagZero, .temp = true};
      const RegArg* dst_reg = dyn_cast<RegArg>(dst(0));
      const RegSet undef = RegSet{kFLAGS, dst_reg ? dst_reg->reg() : kFLAGS};
      Emit(OpMove, dst(0), NewRegArg(kUNDEF))
          .SetUndef(undef)
          .SetUninit(undef)
          .Set(pred.Inverted());
    }
    const auto& opcode = op == OP_shld ? OpShiftLeftDouble : OpShiftRightDouble;
    Emit(opcode, dst(0), src(2), src(0), src(1)).Set(kFlagsArith).Set(pred);
    break;
  }
  case OP_pslldq:
  case OP_vpslldq: {
    // Shift of 2-word value, we need to manually move part of the value
    // from one register to the next one. Currenlty we support only XMM
    // registers. There are also YMM and ZMM variants, but they will require way
    // more logic.
    if (dst(0)->size() != WordSize(2))
      DECODE_UNIMPL("unsupported pslldq size %zu", *dst(0)->size());
    const uptr shift_by = src_imm(0) * kByteBits;
    if (shift_by == 0) {
      Emit(OpMove, dst(0), src(1));
      break;
    }
    if (!src(1)->Vectorize())
      DECODE_FAIL("failed to vectorize src arg");
    if (shift_by >= Bits(dst(0)->size())) {
      NoteMemoryAccess(src(1));
      NoteMemoryAccess(NextWord(src(1)));
      Emit(OpMove, dst(0), NewRegArg(kRZ));
      break;
    }
    if (!dst(0)->Vectorize())
      DECODE_FAIL("failed to vectorize args");
    if (shift_by >= kWordBits) {
      Emit(OpShiftLeft, NextWord(dst(0)), src(1),
           NewImmArg(shift_by - kWordBits));
      Emit(OpMove, dst(0), NewRegArg(kRZ));
      break;
    }
    auto* tmp = NewRegArg(kTEMP0);
    auto* shift = NewImmArg(shift_by);
    Emit(OpMove, tmp, src(1));
    Emit(OpShiftLeft, dst(0), tmp, shift);
    Emit(OpShiftLeftDouble, NextWord(dst(0)), NextWord(src(1)), tmp, shift);
    break;
  }
  case OP_psrldq:
  case OP_vpsrldq: {
    if (dst(0)->size() != WordSize(2))
      DECODE_UNIMPL("unsupported psrldq size %zu", *dst(0)->size());
    const uptr shift_by = src_imm(0) * kByteBits;
    if (shift_by == 0) {
      Emit(OpMove, dst(0), src(1));
      break;
    }
    if (!src(1)->Vectorize())
      DECODE_FAIL("failed to vectorize src arg");
    if (shift_by >= Bits(dst(0)->size())) {
      NoteMemoryAccess(src(1));
      NoteMemoryAccess(NextWord(src(1)));
      Emit(OpMove, dst(0), NewRegArg(kRZ));
      break;
    }
    if (!dst(0)->Vectorize())
      DECODE_FAIL("failed to vectorize dst arg");
    if (shift_by >= kWordBits) {
      NoteMemoryAccess(src(1));
      Emit(OpShiftRight, dst(0), NextWord(src(1)),
           NewImmArg(shift_by - kWordBits));
      Emit(OpMove, NextWord(dst(0)), NewRegArg(kRZ));
      break;
    }
    auto* tmp = NewRegArg(kTEMP0);
    auto* shift = NewImmArg(shift_by);
    Emit(OpMove, tmp, NextWord(src(1)));
    Emit(OpShiftRight, NextWord(dst(0)), tmp, shift);
    Emit(OpShiftRightDouble, dst(0), src(1), tmp, shift);
    break;
  }
  case OP_bsr:
  case OP_bsf: {
    auto* tmp = dst(0);
    if (op == OP_bsr) {
      Emit(OpReverseBits, NewRegArg(kTEMP0), src(0));
      set_src(0, NewRegArg(kTEMP0));
      tmp = NewRegArg(kTEMP1);
    }
    Emit(OpCountTrailingZeros, tmp, src(0))
        .Set(Instr::Flags{.compute = kFlagCarry, .temp = true});
    if (op == OP_bsr)
      Emit(OpSub, dst(0), NewImmArg(kWordBits - 1), tmp);
    // kFlagCarry is set if source arg is 0, then we set kFlagZero and mark
    // result register as undefined. Otherwise reset kFlagZero.
    // TODO(dvyukov): if the result is tainted, kFlagZero should be tainted.
    uptr undef =
        kFlagCarry | kFlagSign | kFlagOverflow | kFlagAuxCarry | kFlagParity;
    Emit()
        .Set(Instr::Predicate{.reset = kFlagCarry, .temp = true})
        .Set(Instr::Flags{.reset = kFlagZero, .undefined = undef});
    Emit()
        .Set(Instr::Predicate{.set = kFlagCarry, .temp = true})
        .Set(Instr::Flags{.set = kFlagZero, .undefined = undef})
        .SetUndef(dyn_cast<RegArg>(dst(0))->reg())
        .SetUninit(dyn_cast<RegArg>(dst(0))->reg());
    break;
  }
  case OP_tzcnt:
    Emit(OpCountTrailingZeros, dst(0), src(0))
        .Set(Instr::Flags{.compute = kFlagZero | kFlagCarry,
                          .undefined = kFlagOverflow | kFlagAuxCarry |
                                       kFlagParity | kFlagSign});
    // TODO(dvyukov): if the result was tainted, it should remain tainted.
    if (src(0)->size() != kPtrSize)
      Emit(OpMove, dst(0), NewImmArg(Bits(src(0)->size())))
          .Set(Instr::Predicate{.set = kFlagCarry});
    break;
  case OP_lzcnt: {
    auto tmp = NewRegArg(kTEMP1);
    Emit(OpReverseBits, tmp, src(0));
    if (uptr shift = Bits(kPtrSize) - Bits(src(0)->size()))
      Emit(OpShiftRight, tmp, tmp, NewImmArg(shift));
    Emit(OpCountTrailingZeros, dst(0), tmp)
        .Set(Instr::Flags{.compute = kFlagZero | kFlagCarry,
                          .undefined = kFlagOverflow | kFlagAuxCarry |
                                       kFlagParity | kFlagSign});
    // TODO(dvyukov): if the result was tainted, it should remain tainted.
    if (src(0)->size() != kPtrSize)
      Emit(OpMove, dst(0), NewImmArg(Bits(src(0)->size())))
          .Set(Instr::Predicate{.set = kFlagCarry});
    break;
  }
  case OP_maxss:
  case OP_maxsd:
  case OP_minss:
  case OP_minsd: {
    dyn_cast<RegArg>(dst(0))->set_keep_rest(true);
    auto *src0 = src(0), *src1 = src(1);
    if (op == OP_maxss || op == OP_maxsd)
      swap(src0, src1);
    Emit(OpSubFloat, NewRegArg(kRZ, dst(0)->size()), src0, src1)
        .Set(Instr::Flags{.compute = kFlagSign, .temp = true});
    Emit(OpMove, dst(0), src(0))
        .Set(Instr::Predicate{.set = kFlagSign, .temp = true});
    break;
  }
  case OP_vmaxss:
  case OP_vmaxsd:
  case OP_vminss:
  case OP_vminsd: {
    auto size = ByteSize(op == OP_vminss || op == OP_vmaxss ? 4 : 8);
    auto* src0 = CopyArg(src(0));
    src0->set_size(ByteSize(size));
    auto* src1 = src(1);
    src1->set_size(ByteSize(size));
    if (op == OP_vminss || op == OP_vminsd)
      swap(src0, src1);
    Emit(OpSubFloat, NewRegArg(kRZ, size), src0, src1)
        .Set(Instr::Flags{.compute = kFlagSign, .temp = true});
    auto* tmp = NewRegArg(kTEMP0, dst(0)->size());
    Emit(OpMove, tmp, src(0));
    auto* res = NewRegArg(kTEMP0, ByteSize(size), 0, true);
    Emit(OpMove, res, src(1))
        .Set(Instr::Predicate{.set = kFlagSign, .temp = true});
    Emit(OpMove, dst(0), tmp);
    break;
  }
  case OP_popcnt:
    Emit(OpPopulationCount, dst(0), src(0))
        .Set(Instr::Flags{.compute = kFlagZero,
                          .reset = kAllFlags & ~kFlagZero});
    break;
  case OP_xchg:
    // TODO(dvyukov): figure out what to do with LOCK prefix.
    Emit(OpMove, NewRegArg(kTEMP0), src(0));
    Emit(OpMove, dst(0), src(1));
    Emit(OpMove, dst(1), NewRegArg(kTEMP0));
    break;
  case OP_cmpxchg:
    Emit(OpSub, NewRegArg(kRZ, src(1)->size()), src(2), src(1))
        .Set(kFlagsArith);
    Emit(OpMove, dst(0), src(0)).Set(Instr::Predicate{.set = kFlagZero});
    Emit(OpMove, dst(1), src(1)).Set(Instr::Predicate{.reset = kFlagZero});
    break;
  case OP_cmpxchg8b: {  // cmpxchg16b is the same opcode
    if (src(1)->size() == ByteSize(2)) {
      // DynamoRIO claims wrong argument size with 0x66 prefix,
      // it's still 4 bytes even with 0x66.
      for (int i = 1; i <= 4; i++)
        src(i)->set_size(ByteSize(4));
      for (int i = 1; i <= 2; i++)
        dst(i)->set_size(ByteSize(4));
    }
    auto mem1 = src(0);
    mem1->set_size(src(1)->size());
    auto mem2 = AdvanceBy(mem1, src(1)->size());
    if (mem1->size() == ByteSize(8))
      mem1->set_required_alignment(ByteSize(16));
    auto tmp1 = NewRegArg(kTEMP0);
    auto tmp2 = NewRegArg(kTEMP1);
    Emit(OpMove, tmp1, mem1);
    Emit(OpMove, tmp2, mem2);
    Emit(OpSub, NewRegArg(kRZ), tmp1, src(1))
        .Set(Instr::Flags{.compute = kFlagZero});
    Emit(OpSub, NewRegArg(kRZ), tmp2, src(2))
        .Set(Instr::Flags{.compute = kFlagZero})
        .Set(Instr::Predicate{.set = kFlagZero});
    Emit(OpMove, mem1, src(3)).Set(Instr::Predicate{.set = kFlagZero});
    Emit(OpMove, mem2, src(4)).Set(Instr::Predicate{.set = kFlagZero});
    Emit(OpMove, dst(1), tmp1).Set(Instr::Predicate{.reset = kFlagZero});
    Emit(OpMove, dst(2), tmp2).Set(Instr::Predicate{.reset = kFlagZero});
    break;
  }
  case OP_xadd: {
    auto tmp0 = NewRegArg(kTEMP0, dst(0)->size());
    auto tmp1 = NewRegArg(kTEMP1, dst(0)->size());
    Emit(OpMove, tmp0, src(0));
    Emit(OpAdd, tmp1, src(1), tmp0).Set(kFlagsArith);
    // There 2 possible corner cases:
    // 1. dst(0) is a memory operand, which uses dst(1) register.
    //    In this case we need to store into dst(0) first.
    // 2. dst(0) and dst(1) are the same register.
    //    In this case we need to store into dst(1) first.
    if (dyn_cast<MemArg>(dst(0))) {
      Emit(OpMove, dst(0), tmp1);
      Emit(OpMove, dst(1), tmp0);
    } else {
      Emit(OpMove, dst(1), tmp0);
      Emit(OpMove, dst(0), tmp1);
    }
    break;
  }
  case OP_cmovo:
  case OP_cmovno:
  case OP_cmovb:
  case OP_cmovnb:
  case OP_cmovz:
  case OP_cmovnz:
  case OP_cmovbe:
  case OP_cmovnbe:
  case OP_cmovs:
  case OP_cmovns:
  case OP_cmovp:
  case OP_cmovnp:
  case OP_cmovl:
  case OP_cmovnl:
  case OP_cmovle:
  case OP_cmovnle:
    Emit(OpMove, NewRegArg(kTEMP0), src(0));
    Emit(OpMove, dst(0), NewRegArg(kTEMP0)).Set(Predicate());
    if (dst(0)->size() == ByteSize(4)) {
      // If not moving, still need to clear the high part.
      auto high = NewRegArg(dyn_cast<RegArg>(dst(0))->reg(), ByteSize(4),
                            ByteSize(4), true);
      Emit(OpMove, high, NewRegArg(kRZ)).Set(Predicate().Inverted());
    }
    break;
  case OP_seto:
  case OP_setno:
  case OP_setb:
  case OP_setnb:
  case OP_setz:
  case OP_setnz:
  case OP_setbe:
  case OP_setnbe:
  case OP_sets:
  case OP_setns:
  case OP_setp:
  case OP_setnp:
  case OP_setl:
  case OP_setnl:
  case OP_setle:
  case OP_setnle: {
    // Note: we could make this a predicated instruction in DynamoRIO,
    // but currently it's not so we need to compute the predicate manually.
    auto pred =
        MakePredicate(static_cast<dr_pred_type_t>(DR_PRED_O + op - OP_seto));
    Emit(OpMove, dst(0), NewImmArg(1)).Set(pred);
    Emit(OpMove, dst(0), NewImmArg(0)).Set(pred.Inverted());
    break;
  }
  case OP_jmp_short:
  case OP_jmp_ind:
  case OP_jmp:
    Emit(OpMove, NewRegArg(kPC), src(0));
    break;
  case OP_jo:
  case OP_jno:
  case OP_jb:
  case OP_jnb:
  case OP_jz:
  case OP_jnz:
  case OP_jbe:
  case OP_jnbe:
  case OP_js:
  case OP_jns:
  case OP_jp:
  case OP_jnp:
  case OP_jl:
  case OP_jnl:
  case OP_jle:
  case OP_jnle:
  case OP_jo_short:
  case OP_jno_short:
  case OP_jb_short:
  case OP_jnb_short:
  case OP_jz_short:
  case OP_jnz_short:
  case OP_jbe_short:
  case OP_jnbe_short:
  case OP_js_short:
  case OP_jns_short:
  case OP_jp_short:
  case OP_jnp_short:
  case OP_jl_short:
  case OP_jnl_short:
  case OP_jle_short:
  case OP_jnle_short:
    Emit(OpMove, NewRegArg(kPC), src(0)).Set(Predicate());
    break;
  case OP_vzeroall:
    Emit(OpZeroVectorRegisters, NewRegArg(kRZ), NewImmArg(0));
    break;
  case OP_vzeroupper:
    Emit(OpZeroVectorRegisters, NewRegArg(kRZ), NewImmArg(1));
    break;
  case OP_vpbroadcastb:
    Emit(OpBroadcast, dst(0), src(0));
    break;
  case OP_pmovmskb:
  case OP_vpmovmskb: {
    Arg* arg = src(0);
    uptr words = Words(arg->size());
    if (!arg->Vectorize())
      DECODE_FAIL("can't vectorize pmovmskb arg");
    for (uptr i = 0; i < words; i++, arg = NextWord(arg))
      Emit(OpMoveMask, NewRegArg(kTEMP0, ByteSize(1), ByteSize(i), true), arg);
    Emit(OpMove, dst(0), NewRegArg(kTEMP0, dst(0)->size()));
    break;
  }
  case OP_punpcklbw:
  case OP_punpcklwd:
  case OP_punpckldq:
  case OP_punpcklqdq:
  case OP_punpckhbw:
  case OP_punpckhwd:
  case OP_punpckhdq:
  case OP_punpckhqdq:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpunpcklbw:
  case OP_vpunpcklwd:
  case OP_vpunpckldq:
  case OP_vpunpcklqdq:
  case OP_vpunpckhbw:
  case OP_vpunpckhwd:
  case OP_vpunpckhdq:
  case OP_vpunpckhqdq: {
    bool hi = false, swap_args = false;
    ByteSize elem;
    switch (op) {
    case OP_punpcklbw:
      swap_args = true;
      [[fallthrough]];
    case OP_vpunpcklbw:
      elem = ByteSize(1);
      break;
    case OP_punpcklwd:
      swap_args = true;
      [[fallthrough]];
    case OP_vpunpcklwd:
      elem = ByteSize(2);
      break;
    case OP_punpckldq:
      swap_args = true;
      [[fallthrough]];
    case OP_vpunpckldq:
      elem = ByteSize(4);
      break;
    case OP_punpcklqdq:
      swap_args = true;
      [[fallthrough]];
    case OP_vpunpcklqdq:
      elem = ByteSize(8);
      break;
    case OP_punpckhbw:
      swap_args = true;
      [[fallthrough]];
    case OP_vpunpckhbw:
      hi = true;
      elem = ByteSize(1);
      break;
    case OP_punpckhwd:
      swap_args = true;
      [[fallthrough]];
    case OP_vpunpckhwd:
      hi = true;
      elem = ByteSize(2);
      break;
    case OP_punpckhdq:
      swap_args = true;
      [[fallthrough]];
    case OP_vpunpckhdq:
      hi = true;
      elem = ByteSize(4);
      break;
    case OP_punpckhqdq:
      swap_args = true;
      [[fallthrough]];
    case OP_vpunpckhqdq:
      hi = true;
      elem = ByteSize(8);
      break;
    }
    const auto size = dst(0)->size();
    auto* src0 = src(0);
    auto* src1 = src(1);
    src0->set_size(elem);
    src1->set_size(elem);
    if (hi) {
      src0->AdvanceBy(ByteSize(8));
      src1->AdvanceBy(ByteSize(8));
    }
    auto* tmp = NewRegArg(kTEMP0, elem, 0, true);
    for (uptr i = 0; i < Bytes(size) / Bytes(elem); i++) {
      if (i * Bytes(elem) == 16) {
        src0->AdvanceBy(ByteSize(8));
        src1->AdvanceBy(ByteSize(8));
      }
      auto*& src = (i + swap_args) % 2 ? src1 : src0;
      Emit(OpMove, tmp, src);
      src = AdvanceBy(src, elem);
      tmp = AdvanceBy(tmp, elem);
    }
    Emit(OpMove, dst(0), NewRegArg(kTEMP0, size));
    break;
  }
  case OP_pshufd:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpshufd: {
    const auto size = dst(0)->size();
    if (size != BitSize(128)) {
      // 256/512-bit versions behave slightly differently and we don't have
      // a good way to test them now.
      DECODE_UNIMPL("unimplemented opcode");
      return;
    }
    auto elem = ByteSize(4);
    src(0)->set_size(elem);
    const uptr mask = src_imm(1);
    auto* tmp = NewRegArg(kTEMP0, elem, 0, true);
    for (uptr i = 0; i < Bytes(size) / Bytes(elem); i++) {
      auto off = ByteSize(((mask >> (i * 2)) & 3) * 4);
      Emit(OpMove, tmp, AdvanceBy(src(0), off));
      tmp = AdvanceBy(tmp, elem);
    }
    Emit(OpMove, dst(0), NewRegArg(kTEMP0, size));
    break;
  }
  case OP_pblendw: {
    const auto size = dst(0)->size();
    auto elem = ByteSize(2);
    // src(0) may be in memory, so load it once first.
    src(0)->set_required_alignment(src(0)->size());
    auto* src0_copy = NewRegArg(VectorTempReg<0>(), src(0)->size());
    Emit(OpMove, src0_copy, src(0));
    auto* src0 = NewRegArg(kTEMP0, elem);
    auto* src1 = CopyArg(src(2));
    src1->set_size(elem);
    const uptr mask = src_imm(1);
    auto* tmp = NewRegArg(VectorTempReg<1>(), elem, 0, true);
    for (uptr i = 0; i < Bytes(size) / Bytes(elem); i++) {
      bool selector = mask & (1 << (i % kByteBits));
      Emit(OpMove, tmp, selector ? src0 : src1);
      tmp = AdvanceBy(tmp, elem);
      src0 = AdvanceBy(src0, elem);
      src1 = AdvanceBy(src1, elem);
    }
    Emit(OpMove, dst(0), NewRegArg(VectorTempReg<1>(), size));
    break;
  }
  case OP_pinsrb:
  case OP_pinsrw:
  case OP_pinsrd: {
    auto* reg = dyn_cast<RegArg>(dst(0));
    auto opsize = reg->size();
    reg->set_keep_rest(true);
    uptr index = src_imm(1) % (16 / Bytes(opsize));
    reg->AdvanceBy(BitSize(Bits(reg->size()) * index));
    Emit(OpMove, reg, src(0));
    break;
  }
  case OP_vpinsrb:
  case OP_vpinsrw:
  case OP_vpinsrd: {
    // DynamoRIO says the first source arg has strange size,
    // e.g. 14 bytes for vpinsrw: vpinsrw %xmm0[14byte] %ebp $0x0f -> %xmm0
    // And using this size seems to be the only way to understand size of the
    // inserted element b/c the second source argument can be 4-byte register
    // for vpinsrw which has element size 2.
    auto opsize = dst(0)->size() - src(0)->size();
    src(0)->set_size(dst(0)->size());
    Emit(OpMove, dst(0), src(0));
    auto* reg = dyn_cast<RegArg>(CopyArg(dst(0)));
    reg->set_keep_rest(true);
    reg->set_size(opsize);
    uptr index = src_imm(2) % (16 / Bytes(opsize));
    reg->AdvanceBy(BitSize(Bits(opsize) * index));
    Emit(OpMove, reg, src(1));
    break;
  }
  case OP_pshufb:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpshufb: {
    auto* src0 = src(op == OP_pshufb ? 0 : 1);
    auto* src1 = src(op == OP_pshufb ? 1 : 0);
    // Load into temp in case src(0) is in memory.
    auto* tmp_full = NewRegArg(kTEMP0, src0->size());
    Emit(OpMove, tmp_full, src0);
    auto* tmp = NewRegArg(kTEMP0, ByteSize(1), 0, true);
    // YMM/ZMM operations operate on 128-bit lanes (effectively 2 or 4 128-bit
    // operations), so we use 4-bit mask for index regardless of register size.
    // When top bit 0x80 is set, the result must be 0. OpIndexRegister operation
    // returns 0 for out-of-bounds accesses, so we just include the the top
    // mask bit in the index.
    auto* index_mask = NewImmArg(0x8f, ByteSize(1));
    src1->set_size(ByteSize(1));
    for (uptr i = 0; i < Bytes(dst(0)->size()); i++) {
      if (i == 16)
        src1 = AdvanceBy(src1, ByteSize(16));
      Emit(OpAnd, tmp, tmp, index_mask);
      Emit(OpIndexRegister, tmp, src1, tmp);
      tmp = AdvanceBy(tmp, tmp->size());
    }
    Emit(OpMove, dst(0), tmp_full);
    break;
  }
  case OP_pshuflw:
  case OP_pshufhw:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpshuflw:
  case OP_vpshufhw: {
    // Load into temp in case src(0) is in memory.
    RegIdx tmp_reg = kTEMP0;
    auto* tmp = NewRegArg(tmp_reg, src(0)->size());
    Emit(OpMove, tmp, src(0));
    auto* res = dyn_cast<RegArg>(dst(0));
    res->set_keep_rest(true);
    const uptr lanes = Bytes(res->size()) / 16;
    const uptr mask = src_imm(1);
    for (uptr lane = 0; lane < lanes; lane++) {
      for (uptr part = 0; part < 2; part++) {
        if ((part == 0) == (op == OP_pshuflw || op == OP_vpshuflw)) {
          res->set_size(ByteSize(2));
          for (uptr j = 0; j < 4; j++) {
            const auto off = ByteSize(((mask >> (2 * j)) & 3) * 2);
            Emit(OpMove, res, NewRegArg(tmp_reg, ByteSize(2), off));
            res = static_cast<RegArg*>(AdvanceBy(res, res->size()));
          }
          tmp_reg = static_cast<RegIdx>(tmp_reg + 1);
        } else {
          res->set_size(kPtrSize);
          Emit(OpMove, res, NewRegArg(tmp_reg));
          res = static_cast<RegArg*>(AdvanceBy(res, res->size()));
          tmp_reg = static_cast<RegIdx>(tmp_reg + 1);
        }
      }
    }
    break;
  }
  case OP_pextrb:
  case OP_vpextrb:
  case OP_pextrw:
  case OP_vpextrw:
  case OP_pextrd:
  case OP_vpextrd: {
    const uptr size = Bytes(src(0)->size());
    const auto offset = ByteSize((src_imm(1) % (16 / size)) * size);
    Emit(OpMove, dst(0), AdvanceBy(src(0), offset));
    break;
  }
  case OP_pmovzxbw:
  case OP_vpmovzxbw:
  case OP_pmovzxbd:
  case OP_vpmovzxbd:
  case OP_pmovzxbq:
  case OP_vpmovzxbq:
  case OP_pmovzxwd:
  case OP_vpmovzxwd:
  case OP_pmovzxwq:
  case OP_vpmovzxwq:
  case OP_pmovzxdq:
  case OP_vpmovzxdq: {
    uptr src_size = 0, dst_size = 0;
    switch (op) {
    case OP_pmovzxbw:
    case OP_vpmovzxbw:
      src_size = 1, dst_size = 2;
      break;
    case OP_pmovzxbd:
    case OP_vpmovzxbd:
      src_size = 1, dst_size = 4;
      break;
    case OP_pmovzxbq:
    case OP_vpmovzxbq:
      src_size = 1, dst_size = 8;
      break;
    case OP_pmovzxwd:
    case OP_vpmovzxwd:
      src_size = 2, dst_size = 4;
      break;
    case OP_pmovzxwq:
    case OP_vpmovzxwq:
      src_size = 2, dst_size = 8;
      break;
    case OP_pmovzxdq:
    case OP_vpmovzxdq:
      src_size = 4, dst_size = 8;
      break;
    }
    const uptr elems = Bytes(dst(0)->size()) / dst_size;
    auto* res =
        NewRegArg(dyn_cast<RegArg>(dst(0))->reg(), ByteSize(dst_size), 0, true);
    // Copy src since it can be in memory.
    Emit(OpMove, NewRegArg(kTEMP0, src(0)->size()), src(0));
    auto* tmp = NewRegArg(kTEMP0, ByteSize(src_size));
    for (uptr i = 0;;) {
      if (src_mask) {
        Emit(OpAnd, NewRegArg(kRZ), src_mask, NewImmArg(1ul << i))
            .Set(Instr::Flags{.compute = kFlagZero, .temp = true});
        Emit(OpMove, res, tmp)
            .Set(Instr::Predicate{.reset = kFlagZero, .temp = true});
      } else {
        Emit(OpMove, res, tmp);
      }
      if (++i >= elems)
        break;
      // Advance after loop-termination condition to avoid advancing register
      // out-of-bounds.
      res = AdvanceBy(res, res->size());
      tmp = AdvanceBy(tmp, tmp->size());
    }
    break;
  }
  case OP_ptest:
  case OP_vptest: {
    auto* src0 = src(0);
    auto* src1 = src(1);
    uptr words = Words(src0->size());
    if (!src0->Vectorize() || !src1->Vectorize())
      DECODE_FAIL("can't vectorize ptest args");
    auto* rz = NewRegArg(kRZ);
    auto* tmp = NewRegArg(VectorTempReg<0>());
    auto* tmp_and = NewRegArg(VectorTempReg<1>());
    auto* tmp_andnot = NewRegArg(VectorTempReg<2>());
    auto* all_bits = NewImmArg(-1);
    for (uptr i = 0; i < words; i++) {
      Emit(OpAnd, tmp, src0, src1);
      Emit(OpOr, tmp_and, tmp_and, tmp);
      Emit(OpXor, tmp, src0, all_bits);
      Emit(OpAnd, tmp, src1, tmp);
      Emit(OpOr, tmp_andnot, tmp_andnot, tmp);
      src0 = NextWord(src0);
      src1 = NextWord(src1);
    }
    Emit(OpAnd, rz, tmp_and, tmp_and)
        .Set(Instr::Flags{.compute = kFlagZero,
                          .reset = kAllFlags & ~kFlagZero});
    Emit(OpAnd, rz, tmp_andnot, tmp_andnot)
        .Set(Instr::Flags{.compute = kFlagZero, .temp = true});
    Emit()
        .Set(Instr::Flags{.set = kFlagCarry})
        .Set(Instr::Predicate{.set = kFlagZero, .temp = true});
    break;
  }
  case OP_bt:
  case OP_bts:
  case OP_btr:
  case OP_btc: {
    auto *src0 = src(0), *src1 = src(1);
    const Operation* add_op = nullptr;
    switch (op) {
    case OP_bt:
      swap(src0, src1);
      break;
    case OP_bts:
      add_op = &OpOr;
      break;
    case OP_btr:
      add_op = &OpAnd;
      break;
    case OP_btc:
      add_op = &OpXor;
      break;
    }
    auto* tmp = NewRegArg(kTEMP0);
    auto* reg = dyn_cast<RegArg>(src1);
    uptr mask = -1;
    if (reg || dyn_cast<ImmArg>(src0))
      mask = Bits(src1->size()) - 1;
    Emit(OpAnd, tmp, src0, NewImmArg(mask));
    if (reg) {
      Emit(OpShiftLeft, tmp, NewImmArg(1), tmp);
      Emit(OpAnd, NewRegArg(kRZ), tmp, reg)
          .Set(Instr::Flags{.compute = kFlagZero, .temp = true});
      if (add_op) {
        if (add_op == &OpAnd)
          Emit(OpXor, tmp, tmp, NewImmArg(~0ul));
        Emit(*add_op, dst(0), tmp, reg);
      }
    } else {
      auto* mem = dyn_cast<MemArg>(src1);
      ByteSize size = mem->size();
      mem->address_arg();
      mem->set_size(kPtrSize);
      Emit(OpShiftRight, tmp, tmp, NewImmArg(3));
      Emit(OpAnd, tmp, tmp, NewImmArg(Bytes(size) == 2 ? ~1 : ~3));
      Emit(OpAdd, NewRegArg(kTEMP1), mem, tmp);
      Emit(OpAnd, tmp, src0, NewImmArg(Bits(size) - 1));
      Emit(OpShiftLeft, tmp, NewImmArg(1), tmp);
      mem = static_cast<MemArg*>(
          NewMemArg(kRZ, kTEMP1, kRZ, 0, 0, false, 0, size));
      auto* copy = NewRegArg(kTEMP2);
      Emit(OpMove, copy, mem);
      Emit(OpAnd, NewRegArg(kRZ), tmp, copy)
          .Set(Instr::Flags{.compute = kFlagZero, .temp = true});
      if (add_op) {
        if (add_op == &OpAnd)
          Emit(OpXor, tmp, tmp, NewImmArg(~0ul));
        Emit(*add_op, mem, tmp, copy);
      }
    }
    Emit().Set(Instr::Flags{
        .reset = kFlagCarry,
        .undefined = kFlagOverflow | kFlagSign | kFlagAuxCarry | kFlagParity});
    Emit()
        .Set(Instr::Flags{.set = kFlagCarry})
        .Set(Instr::Predicate{.reset = kFlagZero, .temp = true});
    break;
  }
  case OP_bzhi: {
    src(1)->set_size(ByteSize(1));
    auto size = Bits(dst(0)->size());
    Emit(OpSub, NewRegArg(kRZ), NewImmArg(size - 1), src(1))
        .Set(Instr::Flags{.compute = kFlagCarry});
    Emit(OpAnd, NewRegArg(kRZ), src(1), NewImmArg(0xff))
        .Set(Instr::Flags{.compute = kFlagZero});
    auto tmp = NewRegArg(kTEMP0);
    Emit(OpSub, tmp, NewImmArg(size), src(1))
        .Set(Instr::Predicate{.reset = kFlagCarry | kFlagZero});
    Emit(OpShiftRight, tmp, NewImmArg(-1ull >> (64 - size)), tmp)
        .Set(Instr::Predicate{.reset = kFlagCarry | kFlagZero});
    Emit(OpMove, tmp, NewImmArg(-1))
        .Set(Instr::Predicate{.set = kFlagCarry, .reset = kFlagZero});
    Emit(OpAnd, dst(0), src(0), tmp)
        .Set(Instr::Flags{kFlagZero | kFlagSign, 0, kFlagOverflow,
                          kFlagAuxCarry | kFlagParity});
    break;
  }
  case OP_blsr: {
    auto tmp = NewRegArg(kTEMP0);
    Emit(OpSub, tmp, src(0), NewImmArg(1))
        .Set(Instr::Flags{.compute = kFlagCarry});
    Emit(OpAnd, dst(0), src(0), tmp)
        .Set(Instr::Flags{.compute = kFlagZero | kFlagSign,
                          .reset = kFlagOverflow,
                          .undefined = kFlagAuxCarry | kFlagParity});
    break;
  }
  case OP_bswap: {
    // The Intel manual says for "16-bit register, the result is undefined"
    // (0x66 prefix). But in practice on tested CPUs the low 2 bytes are zeroed.
    // DynamoRIO claims wrong size for such encodings (4 bytes),
    // so we check the private PREFIX_DATA const.
    if (instr_get_prefix_flag(instr(), PREFIX_DATA)) {
      dst(0)->set_size(ByteSize(2));
      Emit(OpMove, dst(0), NewImmArg(0));
      return;
    }
    auto size = src(0)->size();
    auto src1 = src(0);
    src1->set_size(ByteSize(1));
    for (uptr i = 0; i < Bytes(size); i++) {
      auto tmp = NewRegArg(kTEMP0, ByteSize(1), size - ByteSize(i + 1), true);
      Emit(OpMove, tmp, src1);
      src1 = AdvanceBy(src1, ByteSize(1));
    }
    Emit(OpMove, dst(0), NewRegArg(kTEMP0));
    break;
  }
  case OP_psllw:
  case OP_pslld:
  case OP_psllq:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpsllw:
  case OP_vpslld:
  case OP_vpsllq: {
    const uptr size_log = (op == OP_psllw || op == OP_vpsllw)   ? 4
                          : (op == OP_pslld || op == OP_vpslld) ? 5
                                                                : 6;
    bool swap = (op == OP_vpsllw || op == OP_vpslld || op == OP_vpsllq) &&
                !dyn_cast<ImmArg>(src(0));
    auto* src0 = src(swap ? 0 : 1);
    auto* src1 = src(swap ? 1 : 0);
    // Copy it in case it's in memory.
    src1->set_required_alignment(src1->size());
    Emit(OpMove, NewRegArg(kTEMP0, src1->size()), src1);
    auto* shift = NewRegArg(kTEMP0);
    // The instruction uses all 64 bits of the shift value
    // (as opposed to SHL/SHR which only use 5/6 bits).
    // So if we have any high bits set, we explicitly store 0 into dst.
    const uptr mask = Bitmask(BitSize(size_log));
    Emit(OpAnd, NewRegArg(kRZ), shift, NewImmArg(~mask))
        .Set(Instr::Flags{.compute = kFlagZero, .temp = true});
    auto pred = Instr::Predicate{.set = kFlagZero, .temp = true};
    Emit(OpMove, dst(0), NewImmArg(0)).Set(pred.Inverted());
    Emit(OpAnd, shift, shift, NewImmArg(mask)).Set(pred);
    const auto elem = BitSize(1 << size_log);
    const uptr elems = Bytes(dst(0)->size()) / Bytes(elem);
    auto* dst_reg = dyn_cast<RegArg>(CopyArg(dst(0)));
    dst_reg->set_size(elem);
    dst_reg->set_keep_rest(true);
    auto* src_reg = dyn_cast<RegArg>(src0);
    src_reg->set_size(elem);
    src_reg->set_keep_rest(true);
    for (uptr i = 0; i < elems; i++) {
      Emit(OpShiftLeft, dst_reg, src_reg, shift).Set(pred);
      dst_reg = dyn_cast<RegArg>(AdvanceBy(dst_reg, elem));
      src_reg = dyn_cast<RegArg>(AdvanceBy(src_reg, elem));
    }
    break;
  }
  case OP_psignb:
  case OP_psignw:
  case OP_psignd:
    src(0)->set_required_alignment(src(0)->size());
    [[fallthrough]];
  case OP_vpsignb:
  case OP_vpsignw:
  case OP_vpsignd: {
    uptr elem_size;
    bool swap_src = false;
    switch (op) {
    case OP_psignb:
      elem_size = 1;
      break;
    case OP_psignw:
      elem_size = 2;
      break;
    case OP_psignd:
      elem_size = 4;
      break;
    case OP_vpsignb:
      elem_size = 1;
      swap_src = true;
      break;
    case OP_vpsignw:
      elem_size = 2;
      swap_src = true;
      break;
    case OP_vpsignd:
      elem_size = 4;
      swap_src = true;
      break;
    }
    // Copy it in case it's in memory.
    auto mem_arg = src(swap_src ? 1 : 0);
    mem_arg->set_required_alignment(mem_arg->size());
    auto src0 = NewRegArg(kTEMP0, mem_arg->size());
    Emit(OpMove, src0, mem_arg);
    auto src1 = src(swap_src ? 0 : 1);
    src1->set_sign_extend(true);
    auto sign_mask = NewRegArg(kTEMP4, dst(0)->size());
    auto sign_bits = NewImmArg(elem_size == 1   ? 0x8080808080808080
                               : elem_size == 2 ? 0x8000800080008000
                                                : 0x8000000080000000);
    Emit(OpAnd, sign_mask, src0, sign_bits);
    Emit(OpCompareEQ, sign_mask, sign_mask, sign_bits)
        .set_vector_size(ByteSize(elem_size));
    auto pos_mask = NewRegArg(kTEMP8, dst(0)->size());
    Emit(OpCompareEQ, pos_mask, src0, NewImmArg(0))
        .set_vector_size(ByteSize(elem_size));
    Emit(OpOr, pos_mask, pos_mask, sign_mask);
    Emit(OpXor, pos_mask, pos_mask, NewImmArg(-1));
    auto pos_valus = NewRegArg(kTEMP12, dst(0)->size());
    Emit(OpAnd, pos_valus, src1, pos_mask);
    auto one = NewImmArg(elem_size == 1   ? 0x0101010101010101
                         : elem_size == 2 ? 0x0001000100010001
                                          : 0x0000000100000001);
    one = NewImmArg(0);
    Emit(OpSub, dst(0), one, src1).set_vector_size(ByteSize(elem_size));
    Emit(OpAnd, dst(0), dst(0), sign_mask);
    Emit(OpOr, dst(0), dst(0), pos_valus);
    break;
  }
  case OP_crc32:
    Emit(OpCRC32, dst(0), src(1), src(0));
    break;
  case OP_rdtsc:
    Emit().SetUndef(kRAX, kRDX);
    break;
  case OP_rdtscp:
    Emit().SetUndef(kRAX, kRDX, kRCX);
    break;
  case OP_syscall:
    // We can't predict the syscall result, so mark RAX as undefined.
    Emit(OpSyscall).SetUndef(kRAX);
    // Clear RF flags b/c kernel clears it on syscall return:
    // https://elixir.bootlin.com/linux/v5.17-rc5/source/arch/x86/entry/entry_64.S#L162
    Emit(OpAnd, NewRegArg(kR11), NewRegArg(kFLAGS), NewImmArg(~0x10000));
    Emit(OpMove, NewRegArg(kRCX), NewImmArg(NextPC()));
    // Return ENOSYS from the syscall in case we emulate only.
    Emit(OpMove, NewRegArg(kRAX), NewImmArg(-38)).SetUses(kRAX);
    break;
  case OP_cpuid:
    Emit().SetUses(kRAX).SetUndef(kRAX, kRBX, kRCX, kRDX);
    break;
  case OP_xsavec32:
  case OP_xsavec64:
    // TODO(dvyukov): implement it for real (may be tricky).
    // Since it doesn't affect register state, we only note the memory access
    // address for now.
    dst(0)->set_required_alignment(ByteSize(64));
    NoteMemoryAccess(dst(0));
    Emit().SetUses(kRAX, kRDX);
    break;
  case OP_xrstor32:
  case OP_xrstor64:
    // TODO(dvyukov): implement it for real (may be tricky).
    // For now just mark the affected registers as undefined.
    src(0)->set_required_alignment(ByteSize(64));
    NoteMemoryAccess(src(0));
    Emit().SetUses(kRAX, kRDX).SetUndef(RegSet().AddRange(kXMM0, kXMMLAST));
    break;
  case OP_prefetch:
  case OP_prefetchw:
  case OP_prefetcht0:
  case OP_prefetcht1:
  case OP_prefetcht2:
  case OP_prefetchnta:
  case OP_nop_modrm:
  case OP_pause:
  case OP_emms:
  case OP_nop:
    Emit();
    break;
  case OP_ud2a:
  case OP_ud2b:
    Emit(OpException);
    break;
  default:
    DECODE_UNIMPL("unimplemented opcode");
    break;
  }
}

void X86Decoder::ZeroUpperXMMRegister(const Arg* dst) {
  const RegArg* reg = dyn_cast<RegArg>(dst);
  // Instructions like VZEROALL/VZEROUPPER don't have destination argument.
  if (!reg)
    return;
  // Some instructions can have an XMM register as destination, but operand
  // size is only 4 bytes, so we need to round up.
  uptr start_reg = RoundUpTo(Bits(reg->size()), kWordBits) / kWordBits;
  for (uptr i = start_reg; i < kVectorRegWords; i++)
    Emit(OpMove, NewRegArg(static_cast<RegIdx>(reg->reg() + i)), NewImmArg(0));
}

RegIdx X86Decoder::MapDRReg(reg_id_t reg, ByteSize& offset) {
  offset = 0;
  switch (reg) {
  case DR_REG_AH:
  case DR_REG_BH:
  case DR_REG_CH:
  case DR_REG_DH:
    offset = ByteSize(1);
    break;
  default:
    break;
  }
  switch (reg_to_pointer_sized(reg)) {
  case DR_REG_NULL:
    return kRZ;
  case DR_REG_RSP:
    return kSP;
  case DR_REG_RBP:
    return kRBP;
  case DR_REG_RAX:
    return kRAX;
  case DR_REG_RBX:
    return kRBX;
  case DR_REG_RCX:
    return kRCX;
  case DR_REG_RDX:
    return kRDX;
  case DR_REG_RDI:
    return kRDI;
  case DR_REG_RSI:
    return kRSI;
  case DR_REG_R8:
    return kR8;
  case DR_REG_R9:
    return kR9;
  case DR_REG_R10:
    return kR10;
  case DR_REG_R11:
    return kR11;
  case DR_REG_R12:
    return kR12;
  case DR_REG_R13:
    return kR13;
  case DR_REG_R14:
    return kR14;
  case DR_REG_R15:
    return kR15;
  case DR_SEG_FS:
    return kFS;
  case DR_SEG_GS:
    return kGS;
  case DR_SEG_DS:
  case DR_SEG_ES:
  case DR_SEG_CS:
  case DR_SEG_SS:
    // TODO(dvyukov): is this correct? so far I've seen these only in nops.
    return kRZ;
  case DR_REG_K0:
    return kK0;
  case DR_REG_K1:
    return kK1;
  case DR_REG_K2:
    return kK2;
  case DR_REG_K3:
    return kK3;
  case DR_REG_K4:
    return kK4;
  case DR_REG_K5:
    return kK5;
  case DR_REG_K6:
    return kK6;
  case DR_REG_K7:
    return kK7;
  }
  if (reg >= DR_REG_XMM0 && reg <= DR_REG_XMM31)
    return XMM(kVectorRegWords * (reg - DR_REG_XMM0));
  if (reg >= DR_REG_YMM0 && reg <= DR_REG_YMM31)
    return XMM(kVectorRegWords * (reg - DR_REG_YMM0));
  // There are also:
  // DR_REG_ST0..DR_REG_ST7
  // DR_REG_MM0..DR_REG_MM7
  // DR_REG_BND0..DR_REG_BND3
  // Some of these we may want to support in future,
  // some only come up in fuzzing and UnwindInstruction.
  DECODE_UNIMPL("unsupported register %s (%d)", get_register_name(reg), reg);
  return kRZ;
}

Instr::Predicate X86Decoder::MakePredicate(dr_pred_type_t pred) {
  switch (pred) {
  case DR_PRED_O:
    return {kFlagOverflow};
  case DR_PRED_NO:
    return {0, kFlagOverflow};
  case DR_PRED_B:
    return {kFlagCarry};
  case DR_PRED_NB:
    return {0, kFlagCarry};
  case DR_PRED_Z:
    return {kFlagZero};
  case DR_PRED_NZ:
    return {0, kFlagZero};
  case DR_PRED_BE:
    return {0, kFlagCarry | kFlagZero, 0, 0, true};
  case DR_PRED_NBE:
    return {0, kFlagCarry | kFlagZero};
  case DR_PRED_S:
    return {kFlagSign};
  case DR_PRED_NS:
    return {0, kFlagSign};
  case DR_PRED_P:
    return {kFlagParity};
  case DR_PRED_NP:
    return {0, kFlagParity};
  case DR_PRED_L:
    return {0, 0, 0, kFlagSign | kFlagOverflow};
  case DR_PRED_NL:
    return {0, 0, kFlagSign | kFlagOverflow};
  case DR_PRED_LE:
    return {0, kFlagZero, kFlagSign | kFlagOverflow, 0, true};
  case DR_PRED_NLE:
    return {0, kFlagZero, kFlagSign | kFlagOverflow};
  default:
    DECODE_FAIL("bad instruction predicate: %d", pred);
    return {};
  }
}

}  // namespace gwpsan
