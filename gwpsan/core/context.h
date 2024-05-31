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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_CONTEXT_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_CONTEXT_H_

#include <signal.h>

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/origin.h"
#include "gwpsan/core/regset.h"

namespace gwpsan SAN_LOCAL {

// CPU context (mainly registers + meta information).
class CPUContext {
 public:
  CPUContext() = default;
  explicit CPUContext(ucontext_t& uctx);

  // Copies this back to uctx.
  void ToUContext(ucontext_t& uctx) const;

  ucontext_t* uctx() const {
    return uctx_;
  }

  const Word& reg(RegIdx reg) const {
    return regs_[reg];
  }

  void set_reg(RegIdx reg, Word val) {
    regs_[reg] = move(val);
  }

  void Execute(Env& env, InstrSequence& seq);

  // Assuming this is an emulated context, Synchronize updates some unpredicted
  // bits from the corresponding real context and returns if the emulated
  // and real contexts match.
  bool Synchronize(const CPUContext& real);

  // Initialize from the real context parts of this context that we don't
  // emulate
  void InitUnemulated(const CPUContext& real);

  // Returns true if any registers contain tainted values.
  bool Tainted() const;

  // Setup the context to call function fn with the provided arg on the given
  // stack/stack_size and return the the function return_to.
  void SetupCall(void (*fn)(void*), void* arg, void* stack, uptr stack_size,
                 void (*return_to)());
  // Extracts return PC after a call instruction.
  uptr ReturnPC() const;

  // Updates the specified register both in this object
  // and in the underlying ucontext_t.
  void UpdateRegister(RegIdx reg, uptr val);

  LogBuf Dump() const;
  LogBuf DumpDiff(const CPUContext& other) const;

  static bool Init();
  // Must be called before raising a signal that generates ucontext_t for use
  // with ToUContext method.
  static void ToUContextEnable();

  // The current underlying CPU features.
  using Features = uptr;
  static constexpr Features kFeatureInitialized = 1 << 0;
  static constexpr Features kFeatureIntel = 1 << 1;
  static constexpr Features kFeatureAMD = 1 << 2;
  static constexpr Features kFeatureAVX512 = 1 << 3;
  static constexpr Features kFeatureXSAVEC = 1 << 4;
  static constexpr Features kAllFeatures = (1ul << 32) - 1;

  static bool IsEnabled(Features f) {
    return (features() & f) == f;
  }

  static Features features() {
    SAN_DCHECK_NE(features_, 0);
    SAN_DCHECK_EQ(features_ & ~kAllFeatures, 0);
    return features_;
  }

 private:
  static Features features_;
  ucontext_t* uctx_ = nullptr;
  Array<Word, kRegCount> regs_ = {};
  RegSet undefined_regs_;     // see Instr::undef_
  RegSet uninit_regs_;        // see Instr::uninit_
  uptr undefined_flags_ = 0;  // these bits in the kFLAGS register are undefined

  bool Execute(Env& env, const Instr& instr);
  Word ExecuteVector(Env& env, const Instr& instr, const OpArgs& src);
  Word ExecuteOp(Env& env, const Instr& instr, const OpArgs& src);
  Word ExecuteIndexRegister(Env& env, const Instr& instr, const OpArgs& src);
  void ExecuteZeroVectorRegisters(const OpArgs& src);
  void UpdateFlags(Env& env, const Instr& instr, const Word& res,
                   const OpArgs& src);
  bool EvalPredicate(Env& env, const Instr::Predicate& pred) const;
  void SetupCallArch(uptr return_to);
};

}  // namespace gwpsan SAN_LOCAL

#endif
