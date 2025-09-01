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

#include "gwpsan/core/decoder_dynamorio.h"

#include "gwpsan/import/drdecode/include/dr_api.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/decoder.h"
#include "gwpsan/core/instruction.h"

// For DynamoRIO instruction and operand API reference see:
// https://dynamorio.org/dr__ir__instr_8h.html
// https://dynamorio.org/dr__ir__opnd_8h.html

namespace gwpsan {

bool DynamoRIODecoder::Init() {
  if (CPUContext::IsEnabled(CPUContext::kFeatureIntel)) {
    if (SAN_WARN(proc_set_vendor(VENDOR_INTEL) < 0))
      return false;
  } else if (CPUContext::IsEnabled(CPUContext::kFeatureAMD)) {
    if (SAN_WARN(proc_set_vendor(VENDOR_AMD) < 0))
      return false;
  }
  return true;
}

DynamoRIODecoder::DynamoRIODecoder(uptr pc, uptr pc_copy)
    : InstrDecoder(pc, pc_copy) {}

void DynamoRIODecoder::DecodeImpl() {
  instr_noalloc_init(GLOBAL_DCONTEXT, &noalloc_);
  instr_ = instr_from_noalloc(&noalloc_);
  u8* code_orig = reinterpret_cast<u8*>(pc());
  u8* code_copy = reinterpret_cast<u8*>(pc_copy());
  u8* next_pc = decode_from_copy(GLOBAL_DCONTEXT, code_copy, code_orig, instr_);
  if (!next_pc || !instr_valid(instr_)) {
    DECODE_UNIMPL("DynamoRIO failed to decode instruction");
    return;
  }
  const uptr len = next_pc - code_copy;
  SAN_LOG("decoding %s", &DumpInstr(pc(), pc_copy(), kDumpAll));
  if (len > kMaxInstrLen) {
    DECODE_UNIMPL("instruction is too long (%zu)", len);
    return;
  }
  const int num_src = instr_num_srcs(instr_);
  const int num_dst = instr_num_dsts(instr_);
  if (num_src > src_.capacity()) {
    DECODE_FAIL("too many source arguments: %u", num_src);
    return;
  }
  if (num_dst > dst_.capacity()) {
    DECODE_FAIL("too many destination arguments: %u", num_dst);
    return;
  }
  instr_set_translation(instr_, code_orig);
  set_byte_size(len);
  set_opcode(opcode(), decode_opcode_name(opcode()));
  set_atomic(instr_get_prefix_flag(instr_, PREFIX_LOCK));
  src_.reset();
  dst_.reset();
  for (int i = 0; i < num_src; i++)
    src_.emplace_back(MakeArg(instr_get_src(instr_, i)));
  for (int i = 0; i < num_dst; i++)
    dst_.emplace_back(MakeArg(instr_get_dst(instr_, i)));

  if (!failed())
    DecodeArch();
}

Arg* DynamoRIODecoder::MakeArg(opnd_t opnd) {
  if (opnd_is_reg(opnd))
    return MakeRegArg(opnd);
  if (opnd_is_immed(opnd) || opnd_is_pc(opnd))
    return MakeImmArg(opnd);
  if (opnd_is_memory_reference(opnd))
    return MakeMemArg(opnd);
  DECODE_UNIMPL("unknown operand type");
  return &imm_fallback_;
}

Arg* DynamoRIODecoder::MakeRegArg(opnd_t opnd) {
  auto size_class = opnd_get_size(opnd);
  BitSize size;
  if (size_class == OPSZ_SCALABLE)
    // TODO(dvyukov): This is arm64 scalable vector instructions, we need to
    // match what hardware will actually use. Or for pure emulation we can
    // choose our own size.
    size = WordSize(2);
  else
    size = ByteSize(opnd_size_in_bytes(size_class));
  ByteSize offset;
  RegIdx reg = MapDRReg(opnd_get_reg(opnd), offset);
  return NewRegArg(reg, size, offset);
}

Arg* DynamoRIODecoder::MakeImmArg(opnd_t opnd) {
  uptr imm = 0;
  if (opnd_is_pc(opnd)) {
    imm = reinterpret_cast<uptr>(opnd_get_pc(opnd));
  } else if (opnd_is_immed_int64(opnd)) {
    imm = opnd_get_immed_int64(opnd);
  } else if (opnd_is_immed_int(opnd)) {
    imm = opnd_get_immed_int(opnd);
  } else if (opnd_is_immed_float(opnd)) {
    float v = opnd_is_immed_float(opnd);
    static_assert(sizeof(v) == sizeof(u32), "unexpected float size");
    imm = reinterpret_cast<u32&>(v);
  } else {
    DECODE_FAIL("unknown immidiate type");
    return nullptr;
  }
  ByteSize size(opnd_size_in_bytes(opnd_get_size(opnd)));
  if (size == 0)
    size = ByteSize(1);
  return NewImmArg(imm, size);
}

Arg* DynamoRIODecoder::MakeMemArg(opnd_t opnd) {
  ByteSize reg_offset;
  RegIdx seg = MapDRReg(opnd_get_segment(opnd), reg_offset);
  if (reg_offset != 0)
    DECODE_FAIL("segment register has offset");
  RegIdx base = kRZ;
  RegIdx index = kRZ;
  u32 index_shift = 0;
  BitSize index_extend_size;
  bool index_extend_sign = false;
  Addr offset;
  if (opnd_is_abs_addr(opnd) || opnd_is_rel_addr(opnd)) {
    offset = opnd_get_addr(opnd);
  } else if (opnd_is_base_disp(opnd)) {
    auto reg = opnd_get_index(opnd);
    if (reg != REG_NULL) {
      index = MapDRReg(reg, reg_offset);
      if (reg_offset != 0)
        DECODE_FAIL("index register has offset");
      int scale = opnd_get_scale(opnd);
      if (scale) {
        index_shift = __builtin_ctz(scale);
      } else {
#if GWPSAN_ARM64
        index_extend_size =
            DecodeExtend(opnd_get_index_extend(opnd, nullptr, &index_shift),
                         index_extend_sign);
#else
        DECODE_FAIL("address index scale is 0");
#endif
      }
    }
    base = MapDRReg(opnd_get_base(opnd), reg_offset);
    if (reg_offset != 0)
      DECODE_FAIL("base register has offset");
    offset = Addr(static_cast<s64>(opnd_get_disp(opnd)));
    if (opnd_get_flags(opnd) & DR_OPND_NEGATED)
      offset = -offset;
  } else {
    DECODE_FAIL("unhandled memory arg type");
  }
  ByteSize size(opnd_size_in_bytes(opnd_get_size(opnd)));
  if (size == 0)
    size = kPtrSize;  // DynamoRIO says it's 0 for LEA
  return NewMemArg(seg, base, index, BitSize(index_shift), index_extend_size,
                   index_extend_sign, Addr(offset), size);
}

Instr::Predicate DynamoRIODecoder::Predicate() {
  return MakePredicate(instr_get_predicate(instr_));
}

Instr::Predicate DynamoRIODecoder::SrcPredicate(int idx) {
  auto opnd = instr_get_src(instr_, idx);
  SAN_CHECK(opnd_get_flags(opnd) & DR_OPND_IS_CONDITION);
  SAN_CHECK(opnd_is_immed(opnd));
  auto pred =
      static_cast<dr_pred_type_t>(DR_PRED_NONE + 1 + opnd_get_immed_int(opnd));
  return MakePredicate(pred);
}

BitSize DynamoRIODecoder::DecodeExtend(dr_extend_type_t ex, bool& sign) {
  sign = false;
  switch (ex) {
  case DR_EXTEND_UXTB:
    return ByteSize(1);
  case DR_EXTEND_UXTH:
    return ByteSize(2);
  case DR_EXTEND_UXTW:
    return ByteSize(4);
  case DR_EXTEND_SXTB:
    sign = true;
    return ByteSize(1);
  case DR_EXTEND_SXTH:
    sign = true;
    return ByteSize(2);
  case DR_EXTEND_SXTW:
    sign = true;
    return ByteSize(4);
  default:
    return 0;
  }
}

const char* DynamoRIODecoder::OpcodeName(uptr opcode) {
  if (opcode == OP_INVALID)
    return "invalid";
  if (opcode == OP_UNDECODED)
    return "undecoded";
  if (opcode == OP_CONTD)
    return "contd";
  if (opcode == OP_LABEL)
    return "label";
  if (opcode >= kMaxOpcodes)
    return "max";
  return decode_opcode_name(opcode);
}

inline constexpr DumpWhat DumpNeedDecode = kDumpAsm | kDumpBytes;

LogBuf DumpInstr(uptr pc, uptr pc_copy, DumpWhat what) {
  LogBuf buf;
  // These are used in tests, but also don't crash on nullptr.
  if (pc < (64 << 10))
    return buf.Append("pc=0x%zx", pc);
  if (what & DumpNeedDecode) {
    auto noalloc = MakeUniqueFreelist<instr_noalloc_t>();
    instr_noalloc_init(GLOBAL_DCONTEXT, noalloc.get());
    instr_t* instr = instr_from_noalloc(noalloc.get());
    auto next_pc = reinterpret_cast<uptr>(
        decode_from_copy(GLOBAL_DCONTEXT, reinterpret_cast<u8*>(pc_copy),
                         reinterpret_cast<u8*>(pc), instr));
    if (!next_pc || !instr_valid(instr))
      return buf.Append("failed to decode pc 0x%zx", pc);
    instr_set_translation(instr, reinterpret_cast<u8*>(pc));
    if (what & kDumpBytes)
      buf.Append("%s", &DumpBytesImpl(pc_copy, next_pc - pc_copy));
    if (what & kDumpAsm) {
      disassemble_set_syntax(DR_DISASM_DR);
      LogBuf buf1;
      instr_disassemble_to_buffer(GLOBAL_DCONTEXT, instr, &buf1, buf1.kSize);
      buf.Append("%s%s", what & kDumpBytes ? " :: " : "", &buf1);
    }
  }
  if ((what & (kDumpBytes | kDumpAsm)) && (what & (kDumpPC | kDumpModule)))
    buf.Append(" at");
  if (what & kDumpPC)
    buf.Append("%s0x%zx", what & (kDumpBytes | kDumpAsm) ? " " : "", pc);
  if (what & kDumpModule)
    buf.Append("%s%s", what & (kDumpBytes | kDumpAsm | kDumpPC) ? " " : "",
               &DumpModuleImpl(pc));
  return buf;
}

LogBuf DumpInstr(uptr pc, DumpWhat what) {
  uptr pc_copy = 0;
  char code_copy[2 * kMaxInstrLen] = {};
  if (what & DumpNeedDecode) {
    // Copy the code so that we don't crash on broken stack frames when trying
    // to decode bogus PCs. This function is called only from slow paths where
    // we report/print something, or from tests, so performance is not critical.
    pc_copy = reinterpret_cast<uptr>(code_copy);
    if (!NonFailingLoad(Addr(pc), ByteSize(kMaxInstrLen), code_copy)) {
      LogBuf buf;
      return buf.Append("pc=0x%zx (faulted)", pc);
    }
  }
  return DumpInstr(pc, pc_copy, what);
}

}  // namespace gwpsan
