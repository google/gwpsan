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

#ifndef GWPSAN_CORE_DECODER_ARM64_H_
#define GWPSAN_CORE_DECODER_ARM64_H_

#include "gwpsan/core/decoder_dynamorio.h"

namespace gwpsan SAN_LOCAL {

class Arm64Decoder : public DynamoRIODecoder {
 public:
  Arm64Decoder(uptr pc, uptr pc_copy = 0);

 private:
  void DecodeArch() override;
  // Lots of instructions can have additional operands that encode shift
  // or extend of the preceeding operand. This function decodes these operands
  // starting from 'shift_arg_idx', applies shift/extend to 'arg' and returns
  // shifted/extended argument.
  Arg* ShiftExtend(Arg* arg, int shift_arg_idx);
  OpRef ShiftToOpRef(opnd_t opnd);
  RegIdx MapDRReg(reg_id_t reg, ByteSize& offset) override;
  Instr::Predicate MakePredicate(dr_pred_type_t pred) override;
};

}  // namespace gwpsan SAN_LOCAL

#endif
