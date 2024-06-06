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

#ifndef GWPSAN_CORE_DECODER_DYNAMORIO_H_
#define GWPSAN_CORE_DECODER_DYNAMORIO_H_

#include "gwpsan/import/drdecode/include/dr_api.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/type_id.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/decoder.h"
#include "gwpsan/core/instruction.h"

namespace gwpsan SAN_LOCAL {

// Base class for instruction decoders based on DynamoRIO.
class DynamoRIODecoder : public InstrDecoder {
 public:
  static bool Init();
  static constexpr uptr kMaxOpcodes = OP_AFTER_LAST;
  static const char* OpcodeName(uptr opcode);

 protected:
  DynamoRIODecoder(uptr pc, uptr pc_copy);

  int opcode() {
    return instr_get_opcode(instr_);
  }

  int num_src() {
    return src_.size();
  }

  int num_dst() {
    return dst_.size();
  }

  Arg* src(int idx) {
    return idx < src_.size() ? src_[idx] : &imm_fallback_;
  }

  // Returns value of the immediate operand idx.
  uptr src_imm(int idx) {
    const auto* arg = dyn_cast<ImmArg>(src(idx));
    if (!arg) {
      DECODE_FAIL("immediate argument is not immediate");
      return 0;
    }
    return arg->val();
  }

  void set_src(int idx, Arg* arg) {
    src_.at(idx) = arg;
  }

  Arg* src_pop() {
    Arg* arg = src_.at(0);
    for (uptr i = 1; i < src_.size(); ++i)
      src_[i - 1] = src_[i];
    src_.pop_back();
    return arg;
  }

  Arg* dst(int idx) {
    return idx < dst_.size() ? dst_[idx] : &imm_fallback_;
  }

  uptr CurrentPC() {
    return reinterpret_cast<uptr>(instr_get_app_pc(instr_));
  }

  uptr NextPC() {
    return CurrentPC() + instr_length(GLOBAL_DCONTEXT, instr_);
  }

  instr_t* instr() {
    return instr_;
  }

  // Returns predicate associated with the instruction.
  Instr::Predicate Predicate();
  // Returns predicate associated with the source argument idx.
  Instr::Predicate SrcPredicate(int idx);
  BitSize DecodeExtend(dr_extend_type_t ex, bool& sign);

 private:
  instr_noalloc_t noalloc_;
  instr_t* instr_ = nullptr;
  ArrayVector<Arg*, 5> src_;
  ArrayVector<Arg*, 4> dst_;

  void DecodeImpl() override;

  Arg* MakeArg(opnd_t opnd);
  Arg* MakeRegArg(opnd_t opnd);
  Arg* MakeImmArg(opnd_t opnd);
  Arg* MakeMemArg(opnd_t opnd);

  virtual void DecodeArch() = 0;
  virtual RegIdx MapDRReg(reg_id_t reg, ByteSize& offset) = 0;
  virtual Instr::Predicate MakePredicate(dr_pred_type_t pred) = 0;
};

}  // namespace gwpsan SAN_LOCAL

#endif
