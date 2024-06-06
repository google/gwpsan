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

#ifndef GWPSAN_CORE_OPERATION_H_
#define GWPSAN_CORE_OPERATION_H_

#include "gwpsan/base/common.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/origin.h"

namespace gwpsan SAN_LOCAL {

// Context passed to operation implementations.
class OpCtx {
 public:
  OpCtx() = default;
  OpCtx(Env& env, const Instr& instr, CPUContext& ctx)
      : env_(&env)
      , instr_(&instr)
      , ctx_(&ctx) {}

  const Instr& instr() const;
  void Syscall();
  Word RaiseException();  // returns a zero Word for convenience

 private:
  Env* env_ = nullptr;
  const Instr* instr_ = nullptr;
  CPUContext* ctx_ = nullptr;
};

// Abstract ISA instruction operation type.
// Operation types are identified by the single object instance below.
// All users must use the OpRef typedef to refer to operations.
class Operation final {
  using OpFunc0 = Word (*)(OpCtx& ctx);
  using OpFunc1 = Word (*)(OpCtx& ctx, const Word&);
  using OpFunc2 = Word (*)(OpCtx& ctx, const Word&, const Word&);
  using OpFunc3 = Word (*)(OpCtx& ctx, const Word&, const Word&, const Word&);
  // FlagsFunc computes kFLAGS register bits after an instruction execution.
  // 'instr', 'flags', 'res', 'src0' and 'src1' match ComputeFlags arguments.
  // The function returns the computed flags in 'val'. The computed flags may
  // be a subset of all flags that need to be computed (flags.compute),
  // the actually computed flags are returned in 'computed' argument.
  // The remaining flags (flags.compute & ~computed), if any, are computed by
  // ComputeFlags using the default meaning for flags.
  using FlagsFunc1 = void (*)(const Instr& instr, Instr::Flags& flags,
                              uptr& val, uptr& computed, uptr res, uptr src0);
  using FlagsFunc2 = void (*)(const Instr& instr, Instr::Flags& flags,
                              uptr& val, uptr& computed, uptr res, uptr src0,
                              uptr src1);
  using FlagsFunc3 = void (*)(const Instr& instr, Instr::Flags& flags,
                              uptr& val, uptr& computed, uptr res, uptr src0,
                              uptr src1, uptr src2);

 public:
  constexpr Operation(const char* name, OpFunc0 op_fn)
      : name_(name)
      , args_(0)
      , op_fn0_(op_fn) {}

  constexpr Operation(const char* name, OpFunc1 op_fn,
                      FlagsFunc1 flags_fn = nullptr)
      : name_(name)
      , args_(1)
      , op_fn1_(op_fn)
      , flags_fn1_(flags_fn) {}

  constexpr Operation(const char* name, OpFunc2 op_fn,
                      FlagsFunc2 flags_fn = nullptr)
      : name_(name)
      , args_(2)
      , op_fn2_(op_fn)
      , flags_fn2_(flags_fn) {}

  constexpr Operation(const char* name, OpFunc3 op_fn,
                      FlagsFunc3 flags_fn = nullptr)
      : name_(name)
      , args_(3)
      , op_fn3_(op_fn)
      , flags_fn3_(flags_fn) {}

  const char* Name() const {
    return name_;
  }

  uptr ArgCount() const {
    return args_;
  }

  Word operator()(const Word& src0, const Word& src1) const {
    SAN_CHECK_EQ(args_, 2);
    OpCtx ctx;
    return op_fn2_(ctx, src0, src1);
  }

  Word invoke(OpCtx& ctx, const OpArgs& src) const {
    switch (args_) {
    case 0:
      return op_fn0_(ctx);
    case 1:
      return op_fn1_(ctx, src[0]);
    case 2:
      return op_fn2_(ctx, src[0], src[1]);
    default:
      return op_fn3_(ctx, src[0], src[1], src[2]);
    }
  }

  // ComputeFlags computes kFLAGS register bits after an instruction
  // execution. 'instr' is the executed instruction. 'flags' is a copy of the
  // instruction affected flags. The function can change this object (e.g. to
  // say that some bits need to be set/reset instead of being computed).
  // 'res', 'src0' and 'src1' are the instruction execution result and source
  // arguments.
  // Returns the computed flags denoted by flags.compute.
  // On return 'untainted' contains computed flags that are untainted even
  // if 'res' is tainted.
  uptr ComputeFlags(const Instr& instr, Instr::Flags& flags, uptr& untainted,
                    const Word& res, const OpArgs& src) const;

  bool operator==(const Operation& other) const {
    // Operations are only used as unique global non-copyable instances.
    return this == &other;
  }

 private:
  const char* const name_;
  const uptr args_;
  union {
    const OpFunc0 op_fn0_;
    const OpFunc1 op_fn1_;
    const OpFunc2 op_fn2_;
    const OpFunc3 op_fn3_;
  };
  union {
    const FlagsFunc1 flags_fn1_;
    const FlagsFunc2 flags_fn2_;
    const FlagsFunc3 flags_fn3_;
  };

  Operation(const Operation&) = delete;
  Operation& operator=(const Operation&) = delete;
};

using OpRef = const Operation&;

extern const Operation OpNop;
extern const Operation OpException;  // unconditionally raises an exception
extern const Operation OpSyscall;
extern const Operation OpMove;
extern const Operation OpAdd;
extern const Operation OpSub;
extern const Operation OpAddOne;  // src0 + src1 + 1
extern const Operation OpSubOne;  // src0 - src1 - 1
extern const Operation OpMultiply;
extern const Operation OpMultiplySigned;
// Multiply and return the high word of double-word result.
extern const Operation OpMultiplyHigh;
extern const Operation OpMultiplyHighSigned;
extern const Operation OpDivide;           // ((src1 << size) | src0) / src2
extern const Operation OpRemainder;        // ((src1 << size) | src0) % src2
extern const Operation OpDivideSigned;     // ((src1 << size) | src0) / src2
extern const Operation OpRemainderSigned;  // ((src1 << size) | src0) % src2
extern const Operation OpOr;
extern const Operation OpXor;
extern const Operation OpAnd;
extern const Operation OpShiftRightArith;
extern const Operation OpShiftRight;
extern const Operation OpShiftLeft;
// dst = (src0 >> src2) | (src1 << (size - src2))
extern const Operation OpShiftRightDouble;
// dst = (src0 << src2) | (src1 >> (size - src2))
extern const Operation OpShiftLeftDouble;
extern const Operation OpRotateRight;
extern const Operation OpRotateLeft;
extern const Operation OpSignExtend;
// Duplicates source arg in the destination arg.
extern const Operation OpBroadcast;
// Applies dynamic offset in src1 (in bytes) to the register argument src0.
// The offset can cross multiple word registers within the same full vector
// register (kVectorRegWords words). The resulting value must be contained
// within the same word register (not be split across 2 word registers).
// If the offset is larger then a full vector register, the operation returns 0.
extern const Operation OpIndexRegister;
// src0 == src1 ? ~0ul : 0.
extern const Operation OpCompareEQ;
// Extracts top bit of every source byte and stores in consecutive low bits.
extern const Operation OpMoveMask;
// Returns the number of tailing 0 bits in the source arg.
// If the source arg is 0, returns word size and sets kFlagCarry.
extern const Operation OpCountTrailingZeros;
// Reverse bit order.
extern const Operation OpReverseBits;
// Counts number of set bits in the source arg.
extern const Operation OpPopulationCount;
// Convert integer to float.
extern const Operation OpConvertIntToFloat;
extern const Operation OpConvertFloatToInt;
extern const Operation OpConvertFloatToFloat;
extern const Operation OpAddFloat;
extern const Operation OpSubFloat;
extern const Operation OpMultiplyFloat;
extern const Operation OpDivideFloat;
// Zero either all or upper vector register depending on the value
// of the first immediate operand (0 and 1 respectively).
extern const Operation OpZeroVectorRegisters;
extern const Operation OpCRC32;

Word ShiftRightArith(Word val, uptr n);
Word ShiftRight(Word val, uptr n);
Word ShiftLeft(Word val, uptr n);

uptr ShiftVal(OpRef op, uptr val, uptr n);
uptr RotateRightVal(uptr val, uptr n, uptr size);

}  // namespace gwpsan SAN_LOCAL

#endif
