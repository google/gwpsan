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

#include "gwpsan/core/decoder.h"

#include <stdarg.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/type_id.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/operation.h"
#include "gwpsan/core/origin.h"

namespace gwpsan {

InstrDecoder::InstrDecoder(uptr pc, uptr pc_copy)
    : imm_fallback_(0)
    , reg_fallback_(kRZ)
    , mem_fallback_(kRZ, kRZ, kRZ, 0, 0, false, 0, kPtrSize)
    , pc_(pc)
    , pc_copy_(pc_copy ?: pc) {}

bool InstrDecoder::Decode() {
  DecodeImpl();
  if (failed())
    return false;
  if (instrs_.empty())
    DECODE_FAIL("no instructions decoded");
  Vectorize();
  // We check arg validity here rather than in Emit because decoding code and
  // vectorization can modify instructions after Emit.
  for (auto& instr : instrs_) {
    static_assert(kMaxInstrArgs == 3, "this function needs to be updated");
    const Arg* all_args[] = {instr->dst(), instr->src(0), instr->src(1),
                             instr->src(2)};

    for (const Arg* arg : all_args)
      if (arg && !arg->IsValid(arg == instr->dst()))
        DECODE_FAIL("instr %s: invalid arg %s", &instr->Dump(), &arg->Dump());
    if (!instr->vector_size())
      continue;
    if (!instr->flags().Empty())
      DECODE_FAIL("instr %s: can't vectorize flags", &instr->Dump());
    if (instr->op().ArgCount() > 2)
      DECODE_FAIL("instr %s: vectorize 2+ args", &instr->Dump());
    // Check what CPUContext::ExecuteVector currently expects.
    for (const Arg* arg : all_args)
      if (arg && arg->size() != kPtrSize)
        DECODE_FAIL("instr %s: can't vectorize arg %s", &instr->Dump(),
                    &arg->Dump());
  }
  return !failed();
}

void InstrDecoder::Vectorize() {
  // Do inter-word auto-vectorization: if an instruction does independent
  // operations on N adjacent words, transform it into N instructions on
  // individual words.
  Span<Instr*> instrs = instrs_;
  for (sptr i = 0; i < instrs.size(); ++i) {
    const bool is_copy = instrs.data() != instrs_.data();
    auto* current = instrs[i];
    if (is_copy && instrs_.size() >= instrs_.capacity()) {
      // If the list of instructions is full, we know we can't proceed because
      // we need at least one more slot (no vectorization needed), or multiple
      // if this instruction should be vectorized.
      DECODE_FAIL("too many instructions to vectorize");
      return;
    }
    if (current->dst()->size() <= kPtrSize) {
      if (is_copy)
        instrs_.emplace_back(current);
      continue;
    }

    // Slow-path: only vector instructions will get here.
    if (!is_copy) {
      // This instruction needs vectorization; copy all instructions after
      // current and rewrite the current instruction stream.
      const Span<Instr*> to_copy = instrs.subspan(i + 1);
      if (to_copy.empty()) {
        instrs = Span<Instr*>();  // terminates loop
      } else {
        instrs = Span<Instr*>(
            static_cast<Instr**>(alloc_.Alloc(to_copy.size_bytes())),
            to_copy.size());
        if (!instrs.data()) {
          DECODE_FAIL("out of memory");
          return;
        }
        internal_memcpy(instrs.data(), to_copy.data(), to_copy.size_bytes());
      }
      // Keep all unvectorized instructions before current (or none if i == 0).
      instrs_.shrink(i);
      i = -1;  // incremented before next iteration
    }

    VectorizeOne(*current);
  }
}

void InstrDecoder::VectorizeOne(const Instr& instr) {
  if (!instr.flags().Empty())
    DECODE_FAIL("instr %s: can't vectorize flags", &instr.Dump());
  if (instr.op().ArgCount() > 2)
    DECODE_FAIL("instr %s: vectorize 2+ args", &instr.Dump());
  const BitSize size = instr.dst()->size();
  if (size != WordSize(2) && size != WordSize(4))
    DECODE_FAIL("instr %s: bad bitsize %zu in vectorize", &instr.Dump(), *size);
  // Copy args before modifying b/c they can be shared with other instructions.
  auto* dst = CopyArg(instr.dst());
  auto* src0 = instr.src(0) ? CopyArg(instr.src(0)) : nullptr;
  auto* src1 = instr.src(1) ? CopyArg(instr.src(1)) : nullptr;
  // Vectorize says if this arg should be vectorized and changes size to 1 word.
  if (!dst->Vectorize(size))
    DECODE_FAIL("instr %s: failed to vectorize dst", &instr.Dump());
  // A source arg can be an immediate that does not need to be vectorized.
  bool vsrc0 = src0 ? src0->Vectorize(size) : false;
  bool vsrc1 = src1 ? src1->Vectorize(size) : false;
  for (uptr i = 0; i < Words(size); i++) {
    if (i != 0) {
      dst = NextWord(dst);
      // Alignment should be checked only for the first word.
      // Subsequent words are indeed not aligned, but that's not what
      // was supposed to be checked.
      dst->set_required_alignment(0);
      if (vsrc0) {
        src0 = NextWord(src0);
        src0->set_required_alignment(0);
      }
      if (vsrc1) {
        src1 = NextWord(src1);
        src1->set_required_alignment(0);
      }
    }
    Emit(instr.op(), dst, src0, src1)
        .Set(instr.pred())
        .set_vector_size(instr.vector_size());
  }
}

Instr& InstrDecoder::Emit(OpRef op, Arg* dst, Arg* src0, Arg* src1, Arg* src2) {
  if (!dst)
    dst = NewRegArg(kRZ);
  Instr::ArgArray srcs{src0, src1, src2};
  for (uptr i = 0; i < srcs.size(); i++) {
    if (i < op.ArgCount()) {
      if (!srcs[i])
        DECODE_FAIL("instr %s: expect %zu args, but arg %zu is missing",
                    op.Name(), op.ArgCount(), i);
    } else if (srcs[i]) {
      DECODE_FAIL("instr %s: expect %zu args, but arg %zu is present",
                  op.Name(), op.ArgCount(), i);
    }
  }
  auto* instr = New<Instr>(pc_, op, dst, srcs);
  if (!instr || instrs_.size() >= instrs_.capacity()) {
    DECODE_FAIL("too many instructions");
    return *instrs_[0];
  }
  instrs_.emplace_back(instr);
  return *instr;
}

void InstrDecoder::NoteMemoryAccess(Arg* addr) {
  SAN_LOG("NoteMemoryAccess: %s %d", &addr->Dump(), !!dyn_cast<MemArg>(addr));
  if (dyn_cast<MemArg>(addr))
    Emit(OpMove, NewRegArg(kRZ), addr);
}

Arg* InstrDecoder::NewImmArg(uptr val, BitSize size) {
  auto* ret = New<ImmArg>(val, size);
  if (!ret)
    return &imm_fallback_;
  return ret;
}

Arg* InstrDecoder::NewRegArg(RegIdx reg, BitSize size, BitSize offset,
                             bool keep_rest) {
  auto* ret = New<RegArg>(reg, size, offset, keep_rest);
  if (!ret)
    return &reg_fallback_;
  return ret;
}

Arg* InstrDecoder::NewMemArg(RegIdx seg_reg, RegIdx base_reg, RegIdx index_reg,
                             BitSize index_shift, BitSize index_extend_size,
                             bool index_extend_sign, Addr offset,
                             BitSize size) {
  auto* ret = New<MemArg>(seg_reg, base_reg, index_reg, index_shift,
                          index_extend_size, index_extend_sign, offset, size);
  if (!ret)
    return &mem_fallback_;
  return ret;
}

template <typename T>
Arg* InstrDecoder::TryCopyArg(const Arg* arg, T* fallback) {
  auto* arg1 = dyn_cast<T>(arg);
  if (!arg1)
    return nullptr;
  auto* ret = New<T>(*arg1);
  if (!ret)
    // Alloc already failed decoding, just prevent nullptr derefs.
    return fallback;
  return ret;
}

Arg* InstrDecoder::CopyArg(const Arg* arg) {
  if (Arg* arg1 = TryCopyArg<ImmArg>(arg, &imm_fallback_))
    return arg1;
  if (Arg* arg1 = TryCopyArg<RegArg>(arg, &reg_fallback_))
    return arg1;
  if (Arg* arg1 = TryCopyArg<MemArg>(arg, &mem_fallback_))
    return arg1;
  DECODE_FAIL("unknown arg type");
  return const_cast<Arg*>(arg);
}

Arg* InstrDecoder::NextWord(const Arg* arg) {
  return AdvanceBy(arg, kPtrSize);
}

Arg* InstrDecoder::AdvanceBy(const Arg* arg, BitSize bits) {
  return CopyArg(arg)->AdvanceBy(bits);
}

void InstrDecoder::set_byte_size(uptr byte_size) {
  SAN_CHECK_EQ(byte_size_, 0);
  byte_size_ = byte_size;
}

void InstrDecoder::set_opcode(uptr opcode, const char* opcode_name) {
  SAN_CHECK_EQ(opcode_, 0);
  SAN_CHECK_NE(opcode, 0);
  opcode_ = opcode;
  opcode_name_ = opcode_name;
}

void InstrDecoder::Fail(bool hard, const char* msg, ...) {
  if (failed_) {
    if (failed_hard_ || !hard)
      return;
    failed_hard_ = true;
  } else {
    failed_ = true;
    failed_hard_ = hard;
  }
  va_list args;
  va_start(args, msg);
  VSPrintf(fail_message_, sizeof(fail_message_), msg, args);
  va_end(args);
  SAN_LOG("decoding %s failed: %s", hard ? "hard" : "soft", fail_message_);
}

}  // namespace gwpsan
