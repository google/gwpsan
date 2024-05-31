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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_DECODER_X86_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_DECODER_X86_H_

#include "gwpsan/core/decoder_dynamorio.h"

namespace gwpsan SAN_LOCAL {

class X86Decoder : public DynamoRIODecoder {
 public:
  X86Decoder(uptr pc, uptr pc_copy = 0);

 private:
  void DecodeArch() override;
  // Zeros the upper (unoccupied by dst) part of YMM/ZMM register.
  void ZeroUpperXMMRegister(const Arg* dst);
  RegIdx MapDRReg(reg_id_t reg, ByteSize& offset) override;
  Instr::Predicate MakePredicate(dr_pred_type_t pred) override;
};

}  // namespace gwpsan SAN_LOCAL

#endif
