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

#include "gwpsan/core/operation.h"

#include <limits.h>
#include <math.h>
#include <stdint.h>

#if GWPSAN_X64
#include <emmintrin.h>
#endif

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/numeric.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/env.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/known_functions.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/origin.h"

namespace gwpsan {

const Instr& OpCtx::instr() const {
  SAN_CHECK(instr_);
  return *instr_;
}

void OpCtx::Syscall() {
  SAN_CHECK(env_);
  SAN_CHECK(ctx_);
  ArrayVector<MemAccess, 4> accesses;
  uptr nr = ExtractSyscallAccesses(*ctx_, accesses);
  if (!GetFlags().check_syscalls)
    accesses.reset();
  env_->Syscall(nr, accesses);
}

Word OpCtx::RaiseException() {
  SAN_CHECK(env_);
  SAN_LOG("the instruction raises an exception");
  env_->Exception();
  return {};
}

uptr Operation::ComputeFlags(const Instr& instr, Instr::Flags& flags,
                             uptr& untainted, const Word& res,
                             const OpArgs& src) const {
  uptr val = 0;
  uptr computed = 0;
  static_assert(kMaxInstrArgs == 3, "this function needs updating");
  const uptr src0 = src[0].val;
  const uptr src1 = src[1].val;
  const uptr src2 = src[2].val;
  switch (args_) {
  case 1:
    if (flags_fn1_)
      flags_fn1_(instr, flags, val, computed, res.val, src0);
    break;
  case 2:
    if (flags_fn2_)
      flags_fn2_(instr, flags, val, computed, res.val, src0, src1);
    break;
  case 3:
    if (flags_fn3_)
      flags_fn3_(instr, flags, val, computed, res.val, src0, src1, src2);
    break;
  }
  // If there are still any uncomputed bits, compute them using the default
  // meaning for flags.
  uptr remain = flags.compute & ~computed;
  if (remain & kFlagZero) {
    if (res.val == 0)
      val |= kFlagZero;
    // If the result has any non-0 initialized bits, the flag is initialized.
    if (res.val & ~res.meta.shadow())
      untainted |= kFlagZero;
  }
  if (remain & kFlagParity)
    if (!__builtin_parity(res.val & 0xff))
      val |= kFlagParity;
  if (remain & kFlagSign)
    if (res.val & SignBit(instr.dst()->size()))
      val |= kFlagSign;
  if (remain & kFlagCarry)
    if (res.val < src0)
      val |= kFlagCarry;
  if (remain & kFlagAuxCarry)
    if ((res.val & 0xf) < (src0 & 0xf))
      val |= kFlagAuxCarry;
  if (remain & kFlagOverflow)
    if (~(src0 ^ src1) & (src0 ^ res.val) & SignBit(instr.dst()->size()))
      val |= kFlagOverflow;
  return val;
}

const Operation OpNop("Nop", [](OpCtx& ctx) { return Word{}; });

const Operation OpException("Exception",
                            [](OpCtx& ctx) { return ctx.RaiseException(); });

const Operation OpSyscall("Syscall", [](OpCtx& ctx) {
  ctx.Syscall();
  return Word{};
});

const Operation OpIndexRegister("IndexRegister", [](OpCtx& ctx,
                                                    const Word& src0,
                                                    const Word& src1) {
  // It's handled right in CPUContext::Execute.
  SAN_WARN(1, "IndexRegister must not be called");
  return Word{};
});

const Operation OpMove("Move", [](OpCtx& ctx, const Word& src) { return src; });

namespace {
Word AddCarry(const Word& src0, const Word& src1, bool carry0) {
  // Start with bitwise or, then calculate worst-case uninit carry propagation.
  Meta meta = Meta::BitwiseOr(src0.meta, src1.meta);
  if (meta.shadow() != 0 && meta.shadow() != ~0ul) {
    bool carry = carry0;
    bool uninit = false;
    for (uptr bit = 1; bit << 1; bit <<= 1) {
      carry = carry + !!((src0.val | src0.meta.shadow()) & bit) +
                  !!((src1.val | src1.meta.shadow()) & bit) >=
              2;
      uninit = carry &&
               (uninit || ((src0.meta.shadow() | src1.meta.shadow()) & bit));
      if (uninit)
        meta.Set(bit << 1, meta.Simplest(Origin::Type::kAny, bit));
    }
  }
  return Word{src0.val + src1.val + carry0, move(meta)};
}
}  // namespace

const Operation OpAdd("Add",
                      [](OpCtx& ctx, const Word& src0, const Word& src1) {
                        return AddCarry(src0, src1, false);
                      });

const Operation OpAddOne(
    "AddOne",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      return AddCarry(src0, src1, true);
    },
    [](const Instr& instr, Instr::Flags& flags, uptr& val, uptr& computed,
       uptr res, uptr src0, uptr src1) {
      computed = kFlagCarry | kFlagAuxCarry;
      if (flags.compute & kFlagCarry)
        if (res <= src0)
          val |= kFlagCarry;
      if (flags.compute & kFlagAuxCarry)
        if ((res & 0xf) <= (src0 & 0xf))
          val |= kFlagAuxCarry;
    });

namespace {
Word SubBorrow(const Word& src0, const Word& src1, bool borrow0) {
  // Start with bitwise or, then calculate worst-case uninit borrow
  // propagation.
  Meta meta = Meta::BitwiseOr(src0.meta, src1.meta);
  if (meta.shadow() != 0 && meta.shadow() != ~0ul) {
    bool borrow = borrow0;
    bool uninit = false;
    for (uptr bit = 1; bit << 1; bit <<= 1) {
      // Assume for minuend uninits are 0s, while for subtrahend - 1s.
      int minuend = (src0.meta.shadow() & bit) ? 0 : !!(src0.val & bit);
      int subtrahend = borrow + !!((src1.val | src1.meta.shadow()) & bit);
      borrow = minuend < subtrahend;
      uninit = borrow &&
               (uninit || ((src0.meta.shadow() | src1.meta.shadow()) & bit));
      if (uninit)
        meta.Set(bit << 1, meta.Simplest(Origin::Type::kAny, bit));
    }
  }
  return Word{src0.val - src1.val - borrow0, move(meta)};
}
}  // namespace

const Operation OpSub(
    "Sub",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      return SubBorrow(src0, src1, false);
    },
    [](const Instr& instr, Instr::Flags& flags, uptr& val, uptr& computed,
       uptr res, uptr src0, uptr src1) {
      computed = kFlagCarry | kFlagAuxCarry | kFlagOverflow;
      if (flags.compute & kFlagCarry)
        if ((GWPSAN_X64 && (res > src0)) || (GWPSAN_ARM64 && (res <= src0)))
          val |= kFlagCarry;
      if (flags.compute & kFlagAuxCarry)
        if ((res & 0xf) > (src0 & 0xf))
          val |= kFlagAuxCarry;
      if (flags.compute & kFlagOverflow)
        if ((src0 ^ src1) & (src0 ^ res) & SignBit(instr.dst()->size()))
          val |= kFlagOverflow;
    });

const Operation OpSubOne(
    "SubOne",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      return SubBorrow(src0, src1, true);
    },
    [](const Instr& instr, Instr::Flags& flags, uptr& val, uptr& computed,
       uptr res, uptr src0, uptr src1) {
      computed = kFlagCarry | kFlagAuxCarry | kFlagOverflow;
      if (flags.compute & kFlagCarry)
        if (res >= src0)
          val |= kFlagCarry;
      if (flags.compute & kFlagAuxCarry)
        if ((res & 0xf) >= (src0 & 0xf))
          val |= kFlagAuxCarry;
      if (flags.compute & kFlagOverflow)
        if ((src0 ^ src1) & (src0 ^ res) & SignBit(instr.dst()->size()))
          val |= kFlagOverflow;
    });

namespace {

s128 MultiplySigned(const Instr& instr, uptr src0, uptr src1) {
  uptr sz = Bits(instr.src(0)->size());
  s128 val0 = s128{static_cast<sptr>(OpSignExtend(src0, sz).val)};
  s128 val1 = s128{static_cast<sptr>(OpSignExtend(src1, sz).val)};
  return val0 * val1;
}

template <bool kLow, bool kSigned>
void MultiplyFlags(const Instr& instr, Instr::Flags& flags, uptr& val,
                   uptr& computed, uptr res, uptr src0, uptr src1) {
  bool overflow = res != 0;
  if (kSigned) {
    // If kLow is true, this is x86 1-byte multiplication and the high part of
    // the result is in the second byte of the result.
    if (kLow) {
      overflow =
          static_cast<s16>(res) != static_cast<s16>(static_cast<s8>(res));
    } else {
      // Need to re-do the multiplication b/c overflow condition depends on
      // both high and low parts.
      s128 full_res = MultiplySigned(instr, src0, src1);
      overflow = full_res !=
                 static_cast<sptr>(
                     OpSignExtend(full_res, Bits(instr.src(0)->size())).val);
    }
  } else if (kLow) {
    overflow = (res >> kByteBits) != 0;
  }
  computed = kFlagCarry | kFlagOverflow;
  if ((flags.compute & kFlagCarry) && overflow)
    val |= kFlagCarry;
  if ((flags.compute & kFlagOverflow) && overflow)
    val |= kFlagOverflow;
}
}  // namespace

const Operation OpMultiply(
    "Multiply",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      // TODO(dvyukov): multiplication by a value with some number of 0 low bits
      // can be done more precisely from the shadow point of view: by first
      // shifting left and then multiplying. See MSan's handleMulByConstant
      // function.
      return Word{src0.val * src1.val, Meta::Blend(src0.meta, src1.meta)};
    },
    MultiplyFlags<true, false>);

const Operation OpMultiplySigned(
    "MultiplySigned",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      uptr res = MultiplySigned(ctx.instr(), src0.val, src1.val);
      return Word{res, Meta::Blend(src0.meta, src1.meta)};
    },
    MultiplyFlags<true, true>);

const Operation OpMultiplyHigh(
    "MultiplyHigh",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      uptr res =
          (u128{src0.val} * u128{src1.val}) >> Bits(ctx.instr().src(0)->size());
      return Word{res, Meta::Blend(src0.meta, src1.meta)};
    },
    MultiplyFlags<false, false>);

const Operation OpMultiplyHighSigned(
    "MultiplySignedHigh",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      uptr res = MultiplySigned(ctx.instr(), src0.val, src1.val) >>
                 Bits(ctx.instr().src(0)->size());
      return Word{res, Meta::Blend(src0.meta, src1.meta)};
    },
    MultiplyFlags<false, true>);

namespace {
template <bool unsign>
void CalcDivArgs(OpCtx& ctx, const Word& src0, const Word& src1,
                 const Word& src2, u128& divisible, u128& divisor) {
  uptr size = Bits(ctx.instr().dst()->size());
  divisible = (u128{src1.val} << size) | src0.val;
  divisor = src2.val;
  if (unsign)
    return;
  if (size != 64 && divisible & SignBit(BitSize(2 * size)))
    divisible |= ~((u128{1} << (2 * size)) - 1);
  if (divisor & SignBit(BitSize(size)))
    divisor |= ~((u128{1} << size) - 1);
}

template <bool unsign>
Word Divide(OpCtx& ctx, const Word& src0, const Word& src1, const Word& src2) {
  if (src2.val == 0)
    return ctx.RaiseException();
  u128 divisible, divisor;
  CalcDivArgs<unsign>(ctx, src0, src1, src2, divisible, divisor);
  uptr size = Bits(ctx.instr().dst()->size());
  u128 quotient = 0;
  bool overflow = false;
  if (unsign) {
    quotient = divisible / divisor;
    overflow = quotient >> size;
  } else {
    // Signed division of INT128_MIN by -1 is the only case when even 128-bit
    // division overflows.
    if (src0.val == 0 && static_cast<sptr>(src1.val) == INT64_MIN &&
        static_cast<sptr>(src2.val) == -1) {
      overflow = true;
    } else {
      quotient = static_cast<s128>(divisible) / static_cast<s128>(divisor);
      if (quotient & SignBit(BitSize(size))) {
        u128 high_mask = ~((u128{1} << size) - 1);
        overflow = (quotient & high_mask) != high_mask;
      } else {
        overflow = quotient >> size;
      }
    }
  }
  if (overflow)
    return ctx.RaiseException();
  Meta meta = Meta::Blend(Meta::Blend(src0.meta, src1.meta), src2.meta);
  return Word{static_cast<uptr>(quotient), move(meta)};
}

template <bool unsign>
Word Remainder(OpCtx& ctx, const Word& src0, const Word& src1,
               const Word& src2) {
  u128 divisible, divisor;
  CalcDivArgs<unsign>(ctx, src0, src1, src2, divisible, divisor);
  uptr remainder = 0;
  if (unsign)
    remainder = divisible % src2.val;
  else
    remainder = static_cast<s128>(divisible) % static_cast<s128>(divisor);
  Meta meta = Meta::Blend(Meta::Blend(src0.meta, src1.meta), src2.meta);
  return Word{remainder, meta};
}
}  // namespace

const Operation OpDivide("Divide", Divide<true>);
const Operation OpRemainder("Remainder", Remainder<true>);
const Operation OpDivideSigned("DivideSigned", Divide<false>);
const Operation OpRemainderSigned("RemainderSigned", Remainder<false>);

const Operation OpOr("Or", [](OpCtx& ctx, const Word& src0, const Word& src1) {
  return Word{src0.val | src1.val,
              Meta::BitwiseOr(src0.meta, src1.meta)
                  .Reset(~((src0.meta.shadow() & src1.meta.shadow()) |
                           (~src0.val & src1.meta.shadow()) |
                           (~src1.val & src0.meta.shadow())))};
});

const Operation OpXor("Xor", [](OpCtx& ctx, const Word& src0,
                                const Word& src1) {
  // Special case: need to produce an untainted value in this case.
  if (ctx.instr().src(0)->Equals<RegArg>(*ctx.instr().src(1)))
    return Word{};
  return Word{src0.val ^ src1.val, Meta::BitwiseOr(src0.meta, src1.meta)};
});

const Operation OpAnd("And", [](OpCtx& ctx, const Word& src0,
                                const Word& src1) {
  return Word{src0.val & src1.val,
              Meta::BitwiseOr(src0.meta, src1.meta)
                  .Reset(~((src0.meta.shadow() & src1.meta.shadow()) |
                           (src0.val & src1.meta.shadow()) |
                           (src1.val & src0.meta.shadow())))};
});

uptr ShiftVal(OpRef op, uptr val, uptr n) {
  n %= kWordBits;
  if (op == OpShiftRight)
    return val >> n;
  if (op == OpShiftLeft)
    return val << n;
  if (op == OpShiftRightArith) {
    bool sign = val & SignBit(kPtrSize);
    val >>= n;
    if (sign)
      val |= ~Bitmask(BitSize(kWordBits - n));
    return val;
  }
  SAN_BUG("unsupported shift op %s", op.Name());
}

namespace {
template <OpRef op>
Word ShiftOp(OpCtx& ctx, const Word& src0, const Word& src1) {
  uptr size = Bits(ctx.instr().src(0)->size());
  Word n = OpAnd(src1, size == kWordBits ? kWordBits - 1 : 31);
  uptr res = ShiftVal(op, src0.val, n.val);
  if (n.meta)
    return Word{res, Meta(n.meta.Simplest(Origin::Type::kAny))};
  return Word{res, Meta::Shift(op, src0.meta, n.val)};
}

template <OpRef op>
void ShiftFlags(const Instr& instr, Instr::Flags& flags, uptr& val,
                uptr& computed, uptr res, uptr src0, uptr src1) {
  // Affected shift flags depend on the shift value.
  BitSize size = instr.src(0)->size();
  src1 %= size == kPtrSize ? kWordBits : 32;
  if (src1 == 0) {
    flags.compute = 0;
    return;
  }
  uptr undef = kFlagAuxCarry;
  if (src1 > 1)
    undef |= kFlagOverflow;
  if (src1 > Bits(size))
    undef |= kFlagCarry;
  flags.undefined |= (undef & flags.compute);
  flags.compute &= ~undef;
  computed = kFlagCarry | kFlagOverflow;
  bool CF = false;
  bool OF = false;
  if (op == OpShiftLeft) {
    if (src1 <= Bits(size))
      CF = !!(src0 & (1ul << (Bits(size) - src1)));
    OF = !!(src0 & SignBit(size)) != !!(src0 & (1ul << (Bits(size) - 2)));
  } else if (op == OpShiftRight) {
    CF = !!(src0 & SignBit(BitSize(src1)));
    OF = !!(src0 & SignBit(size));
  } else if (op == OpShiftRightArith) {
    computed = kFlagCarry;
    CF = !!(src0 & SignBit(BitSize(src1)));
  } else {
    SAN_BUG("unsupported shift op %s", op.Name());
  }
  if ((flags.compute & kFlagCarry) && CF)
    val |= kFlagCarry;
  if ((flags.compute & kFlagOverflow) && OF)
    val |= kFlagOverflow;
}

Word ShiftWord(OpRef op, Word val, uptr n) {
  return Word{ShiftVal(op, val.val, n), Meta::Shift(op, val.meta, n)};
}
}  // namespace

Word ShiftRightArith(Word val, uptr n) {
  return ShiftWord(OpShiftRightArith, val, n);
}

Word ShiftRight(Word val, uptr n) {
  return ShiftWord(OpShiftRight, val, n);
}

Word ShiftLeft(Word val, uptr n) {
  return ShiftWord(OpShiftLeft, val, n);
}

const Operation OpShiftRightArith("ShiftRightArith", ShiftOp<OpShiftRightArith>,
                                  ShiftFlags<OpShiftRightArith>);

const Operation OpShiftRight("ShiftRight", ShiftOp<OpShiftRight>,
                             ShiftFlags<OpShiftRight>);

const Operation OpShiftLeft("ShiftLeft", ShiftOp<OpShiftLeft>,
                            ShiftFlags<OpShiftLeft>);

namespace {
template <OpRef op0, OpRef op1>
Word ShiftDoubleOp(OpCtx& ctx, const Word& src0, const Word& src1,
                   const Word& src2) {
  uptr size = Bits(ctx.instr().src(0)->size());
  Word n = OpAnd(src2, size == kWordBits ? kWordBits - 1 : 31);
  Word res = op0.invoke(ctx, {src0, n});
  if (n.val == 0)
    return res;
  return OpOr(move(res), op1.invoke(ctx, {src1, OpSub(size, n)}));
}

template <OpRef op>
void ShiftDoubleFlags(const Instr& instr, Instr::Flags& flags, uptr& val,
                      uptr& computed, uptr res, uptr src0, uptr src1,
                      uptr src2) {
  // Affected shift flags depend on the shift value.
  BitSize size = instr.src(0)->size();
  src2 &= size == kPtrSize ? kWordBits - 1 : 31;
  if (src2 == 0) {
    flags.compute = 0;
    return;
  }
  if (src2 > Bits(size)) {
    flags.undefined = flags.compute;
    flags.compute = 0;
    return;
  }
  flags.undefined |= kFlagAuxCarry;
  flags.compute &= ~kFlagAuxCarry;
  computed = kFlagCarry | kFlagOverflow;
  if (src2 > 1) {
    flags.undefined |= kFlagOverflow;
    flags.compute &= ~kFlagOverflow;
    computed &= ~kFlagOverflow;
  }
  if ((flags.compute & kFlagOverflow) &&
      ((res & SignBit(size)) ^ (src0 & SignBit(size))))
    val |= kFlagOverflow;
  if (op == OpShiftRight) {
    if (src0 & (1ull << (src2 - 1)))
      val |= kFlagCarry;
  } else {
    if (src0 & (1ull << (Bits(size) - src2)))
      val |= kFlagCarry;
  }
}
}  // namespace

const Operation OpShiftRightDouble("ShiftRightDouble",
                                   ShiftDoubleOp<OpShiftRight, OpShiftLeft>,
                                   ShiftDoubleFlags<OpShiftRight>);

const Operation OpShiftLeftDouble("ShiftLeftDouble",
                                  ShiftDoubleOp<OpShiftLeft, OpShiftRight>,
                                  ShiftDoubleFlags<OpShiftLeft>);

uptr RotateRightVal(uptr val, uptr n, uptr size) {
  n &= size - 1;
  SAN_LOG("RotateRightVal: val=%zx n=%zx size=%zx", val, n, size);
  if (n == 0)
    return val;
  return (val >> n) | (val << (size - n));
}

namespace {
template <OpRef op>
Word RotateOp(OpCtx& ctx, const Word& src0, const Word& src1) {
  uptr size = Bits(ctx.instr().src(0)->size());
  Word n = OpAnd(src1, size == kWordBits ? kWordBits - 1 : 31);
  if (op == OpRotateLeft)
    n = OpSub(size, n);
  Meta res = Meta::RotateRight(src0.meta, n.val, size);
  if (!res && n.meta)
    res = Meta::Blend(n.meta);
  return Word{RotateRightVal(src0.val, n.val, size), res};
}

template <OpRef op>
void RotateFlags(const Instr& instr, Instr::Flags& flags, uptr& val,
                 uptr& computed, uptr res, uptr src0, uptr src1) {
  // Affected shift flags depend on the shift value.
  BitSize size = instr.src(0)->size();
  src1 &= size == kPtrSize ? kWordBits - 1 : 31;
  if (src1 == 0) {
    flags.compute = 0;
    return;
  }
  computed = kFlagCarry | kFlagOverflow;
  if (src1 > 1) {
    flags.undefined |= kFlagOverflow;
    flags.compute &= ~kFlagOverflow;
    computed &= ~kFlagOverflow;
  }
  if (op == OpRotateRight) {
    if (res & SignBit(size))
      val |= kFlagCarry;
    if ((flags.compute & kFlagOverflow) &&
        (!!(res & SignBit(size - BitSize(1))) ^ !!(res & SignBit(size))))
      val |= kFlagOverflow;
  } else {
    if (res & 1)
      val |= kFlagCarry;
    if ((flags.compute & kFlagOverflow) &&
        (!!(res & 1) ^ !!(res & SignBit(size))))
      val |= kFlagOverflow;
  }
}
}  // namespace

const Operation OpRotateRight("RotateRight", RotateOp<OpRotateRight>,
                              RotateFlags<OpRotateRight>);

const Operation OpRotateLeft("RotateLeft", RotateOp<OpRotateLeft>,
                             RotateFlags<OpRotateLeft>);

const Operation OpSignExtend("SignExtend", [](OpCtx& ctx, const Word& src0,
                                              const Word& src1) {
  SAN_WARN(src1.meta);
  uptr res = 0;
  switch (src1.val) {
  case 8:
    res = static_cast<uptr>(static_cast<sptr>(static_cast<s8>(src0.val)));
    break;
  case 16:
    res = static_cast<uptr>(static_cast<sptr>(static_cast<s16>(src0.val)));
    break;
  case 32:
    res = static_cast<uptr>(static_cast<sptr>(static_cast<s32>(src0.val)));
    break;
  case 64:
    return src0;
  default:
    SAN_BUG("bad bitsize: %zu", src1.val);
  }
  Meta m = src0.meta;
  uptr sign_bit = SignBit(BitSize(src1.val));
  // Select sign bit and if it's tainted, mark top bits with its origin.
  uptr top = ~Bitmask(BitSize(src1.val));
  if (src0.meta.shadow() & sign_bit)
    m.Set(top, src0.meta.Simplest(Origin::Type::kAny, sign_bit));
  else
    m.Reset(top);
  return Word{res, m};
});

const Operation OpBroadcast("Broadcast", [](OpCtx& ctx, const Word& src) {
  Word res = src;
  switch (Bytes(ctx.instr().src(0)->size())) {
  case 1:
    res = OpOr(res, ShiftLeft(res, kByteBits));
    [[fallthrough]];
  case 2:
    res = OpOr(res, ShiftLeft(res, 2 * kByteBits));
    [[fallthrough]];
  default:
    return OpOr(res, ShiftLeft(res, 4 * kByteBits));
  }
});

const Operation OpCompareEQ("CompareEQ", [](OpCtx& ctx, const Word& src0,
                                            const Word& src1) {
  return Word{src0.val == src1.val ? ~0ul : 0,
              Meta::BitwiseOr(src0.meta, src1.meta)};
});

const Operation OpMoveMask("MoveMask", [](OpCtx& ctx, const Word& src) {
  Word res;
  for (uptr i = 0; i < kByteBits; i++)
    res = OpOr(res, ShiftRight(OpAnd(src, 1ul << (i * 8 + 7)), i * 8 + 7 - i));
  return res;
});

const Operation OpCountTrailingZeros(
    "CountTrailingZeros",
    [](OpCtx& ctx, const Word& src) {
      uptr res = 0;
      uptr val = src.val;
      for (uptr i = 0; i < kWordBits; i++) {
        if (val & 1)
          break;
        val >>= 1;
        res++;
      }
      // Set the whole result to the simplest origin of the bits we scanned.
      Meta meta = src.meta;
      if (res < kWordBits - 1)
        meta.Reset(~Bitmask(BitSize(res + 1)));
      return Word{res, Meta::Blend(meta)};
    },
    [](const Instr& instr, Instr::Flags& flags, uptr& val, uptr& computed,
       uptr res, uptr src) {
      computed = kFlagCarry;
      if ((flags.compute & kFlagCarry) && src == 0)
        val |= kFlagCarry;
    });

const Operation OpReverseBits("ReverseBits", [](OpCtx& ctx, const Word& src) {
  return Word{ReverseBitsVal(src.val), Meta::ReverseBits(src.meta)};
});

const Operation OpPopulationCount("PopulationCount", [](OpCtx& ctx,
                                                        const Word& src) {
  return Word{static_cast<uptr>(__builtin_popcountll(src.val)),
              Meta::Blend(src.meta)};
});

namespace {
double ToFloat(uptr val, ByteSize size) {
  if (size == ByteSize(4))
    return bit_cast<float>(static_cast<u32>(val));
  else
    return bit_cast<double>(val);
}

uptr FromFloat(double val, ByteSize size) {
  if (size == ByteSize(4))
    return bit_cast<u32>(static_cast<float>(val));
  else
    return bit_cast<uptr>(val);
}

template <typename T>
int ClassifyFloat(T val) {
  return __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL,
                              FP_ZERO, val);
}

void FloatFlags(const Instr& instr, Instr::Flags& flags, uptr& val,
                uptr& computed, uptr res, uptr src0, uptr src1) {
  if (!flags.compute)
    return;
  auto size = instr.size();
  auto class0 = ClassifyFloat(ToFloat(src0, size));
  auto class1 = ClassifyFloat(ToFloat(src1, size));
  if (flags.compute & kFlagSign) {
    // Note: this is currently tailored for MAXSD x86 instruction.
    computed |= kFlagSign;
    if (class0 == FP_NAN || class1 == FP_NAN ||
        (class0 == FP_ZERO && class1 == FP_ZERO) || ToFloat(res, size) < 0)
      val |= kFlagSign;
  }
  // Note: the following is tailored for [U]COMISS/D instructions.
  if (flags.compute & kFlagZero) {
    computed |= kFlagZero;
    if (class0 == FP_NAN || class1 == FP_NAN ||
        ToFloat(src0, size) == ToFloat(src1, size))
      val |= kFlagZero;
  }
  if (flags.compute & kFlagParity) {
    computed |= kFlagParity;
    if (class0 == FP_NAN || class1 == FP_NAN)
      val |= kFlagParity;
  }
  if (flags.compute & kFlagCarry) {
    computed |= kFlagCarry;
    if (class0 == FP_NAN || class1 == FP_NAN || ToFloat(res, size) > 0)
      val |= kFlagCarry;
  }
}
}  // namespace

const Operation OpConvertIntToFloat("ConvertIntToFloat", [](OpCtx& ctx,
                                                            const Word& src) {
  uptr res;
  if (ctx.instr().dst()->size() == ByteSize(4))
    res = bit_cast<u32>(static_cast<float>(static_cast<sptr>(src.val)));
  else
    res = bit_cast<uptr>(static_cast<double>(static_cast<sptr>(src.val)));
  return Word{res, Meta::Blend(src.meta)};
});

const Operation OpConvertFloatToInt("ConvertFloatToInt", [](OpCtx& ctx,
                                                            const Word& src,
                                                            const Word& trunc) {
  double val = ToFloat(src.val, ctx.instr().src(0)->size());
  if (ClassifyFloat(val) == FP_NAN)
    // TODO(dvyukov): what should we do if inputs were uninit?
    return ctx.RaiseException();
  sptr min_val = 0, max_val = 0;
  if (ctx.instr().dst()->size() == ByteSize(4))
    min_val = INT_MIN, max_val = INT_MAX;
  else
    min_val = LONG_MIN, max_val = LONG_MAX;
  if (val < min_val || val > max_val)
    return ctx.RaiseException();
  uptr res;
#if GWPSAN_X64
  // Rounding rules for the conversion depend on the instruction
  // (CVTSD2SI vs CVTTSD2SI) and control bits in MXCSR.
  // Mimicking them is tricky so for now we just reuse the same instructions.
  if (trunc.val)
    res = _mm_cvttsd_si64(_mm_set_sd(val));
  else
    res = _mm_cvtsd_si64(_mm_set_sd(val));
#else
    res = static_cast<uptr>(val);
#endif
  return Word{res, Meta::Blend(src.meta)};
});

const Operation OpConvertFloatToFloat(
    "ConvertFloatToFloat", [](OpCtx& ctx, const Word& src) {
      uptr res;
      if (ctx.instr().dst()->size() == ByteSize(4)) {
        SAN_WARN(ctx.instr().src(0)->size() != ByteSize(8));
        res = bit_cast<u32>(static_cast<float>(bit_cast<double>(src.val)));
      } else {
        SAN_WARN(ctx.instr().src(0)->size() != ByteSize(4));
        res =
            bit_cast<uptr>(double{bit_cast<float>(static_cast<u32>(src.val))});
      }
      return Word{res, Meta::Blend(src.meta)};
    });

const Operation OpAddFloat(
    "AddFloat",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      auto size = ctx.instr().size();
      return Word{
          FromFloat(ToFloat(src0.val, size) + ToFloat(src1.val, size), size),
          Meta::Blend(src0.meta, src1.meta)};
    },
    FloatFlags);

const Operation OpSubFloat(
    "SubFloat",
    [](OpCtx& ctx, const Word& src0, const Word& src1) {
      auto size = ctx.instr().size();
      return Word{
          FromFloat(ToFloat(src0.val, size) - ToFloat(src1.val, size), size),
          Meta::Blend(src0.meta, src1.meta)};
    },
    FloatFlags);

const Operation OpMultiplyFloat("MultiplyFloat", [](OpCtx& ctx,
                                                    const Word& src0,
                                                    const Word& src1) {
  auto size = ctx.instr().size();
  return Word{
      FromFloat(ToFloat(src0.val, size) * ToFloat(src1.val, size), size),
      Meta::Blend(src0.meta, src1.meta)};
});

const Operation OpDivideFloat("DivideFloat", [](OpCtx& ctx, const Word& src0,
                                                const Word& src1) {
  auto size = ctx.instr().size();
  return Word{
      FromFloat(ToFloat(src0.val, size) / ToFloat(src1.val, size), size),
      Meta::Blend(src0.meta, src1.meta)};
});

const Operation OpZeroVectorRegisters(
    "ZeroVectorRegisters", [](OpCtx& ctx, const Word& src) {
      // It's handled right in
      // CPUContext::Execute.
      SAN_WARN(1, "ZeroVectorRegisters must not be called");
      return Word{};
    });

const Operation OpCRC32("CRC32", [](OpCtx& ctx, const Word& src0,
                                    const Word& src1) {
  uptr res = 0;
  const uptr size_bytes = Bytes(ctx.instr().src(1)->size());
  switch (size_bytes) {
#if GWPSAN_X64
  case 1:
    res = __builtin_ia32_crc32qi(src0.val, src1.val);
    break;
  case 2:
    res = __builtin_ia32_crc32hi(src0.val, src1.val);
    break;
  case 4:
    res = __builtin_ia32_crc32si(src0.val, src1.val);
    break;
  case 8:
    res = __builtin_ia32_crc32di(src0.val, src1.val);
    break;
#endif
  default:
    SAN_WARN(1, "unsupported crc32 operand size: %zu", size_bytes);
  }
  return Word{res, Meta::Blend(src0.meta, src1.meta)};
});

}  // namespace gwpsan
