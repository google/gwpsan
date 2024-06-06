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

#ifndef GWPSAN_CORE_INSTRUCTION_H_
#define GWPSAN_CORE_INSTRUCTION_H_

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/type_id.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/origin.h"
#include "gwpsan/core/regset.h"

namespace gwpsan SAN_LOCAL {

// Arg is a base class for instruction arguments.
class Arg : public TypeId {
 public:
  virtual ~Arg() = default;
  bool operator==(const Arg&) const = default;

  Word Eval(Env& env, const CPUContext& ctx) const;
  void Store(Env& env, CPUContext& ctx, const Word& val) const;

  BitSize size() const {
    return size_;
  }

  void set_size(BitSize size) {
    size_ = size;
  }

  bool sign_extend() const {
    return sign_extend_;
  }

  void set_sign_extend(bool sign_extend) {
    sign_extend_ = sign_extend;
  }

  void set_required_alignment(ByteSize a) {
    SAN_DCHECK(a == 0 || IsPowerOfTwo(Bytes(a)), "a=%zu", Bytes(a));
    required_alignment_ = a;
  }

  bool IsValid(bool is_dst) const {
    return (size_ == ByteSize(1) || size_ == ByteSize(2) ||
            size_ == ByteSize(4) || size_ == ByteSize(8)) &&
           IsValidImpl(is_dst);
  }

  template <typename To>
  bool Equals(const Arg& other) const {
    const auto* this_typed = dyn_cast<To>(this);
    const auto* other_typed = dyn_cast<To>(&other);
    return this_typed && other_typed && *this_typed == *other_typed;
  }

  // Vectorize says if this arg should be vectorized with bitsize and changes
  // and if so, changes the arg size to 1 word.
  bool Vectorize(BitSize size = 0);
  // AdvanceBy changes this arg to refer to the next 'bits' bits
  // and returns this.
  virtual Arg* AdvanceBy(BitSize bits) = 0;
  LogBuf Dump() const;

 protected:
  template <typename Derived>
  explicit Arg(Derived* derived, BitSize size)
      : TypeId(derived)
      , size_(size) {}

  ByteSize required_alignment() const {
    return required_alignment_;
  }

 private:
  BitSize size_;
  bool sign_extend_ = false;
  // If a memory arg is not aligned to this, an exception is raised.
  ByteSize required_alignment_;

  virtual Word EvalImpl(Env& env, const CPUContext& ctx) const = 0;
  virtual void StoreImpl(Env& env, CPUContext& ctx, Word val) const = 0;
  virtual bool CanVectorize() const = 0;
  virtual bool IsValidImpl(bool is_dst) const = 0;
  virtual LogBuf DumpImpl() const = 0;
};

// Immidiate argument.
class ImmArg : public Arg {
 public:
  explicit ImmArg(uptr val, BitSize size = kPtrSize)
      : Arg(this, size)
      , val_(val) {}

  bool operator==(const ImmArg&) const = default;

  uptr val() const {
    return val_;
  }

 private:
  const uptr val_;

  Word EvalImpl(Env& env, const CPUContext& ctx) const override;
  void StoreImpl(Env& env, CPUContext& ctx, Word val) const override;
  bool CanVectorize() const override;
  Arg* AdvanceBy(BitSize bits) override;
  bool IsValidImpl(bool is_dst) const override;
  LogBuf DumpImpl() const override;
};

// Register argument.
class RegArg : public Arg {
 public:
  explicit RegArg(RegIdx reg, BitSize size = kPtrSize, BitSize offset = 0,
                  bool keep_rest = false)
      : Arg(this, size)
      , reg_(reg)
      , offset_(offset)
      , keep_rest_(keep_rest) {}

  bool operator==(const RegArg&) const = default;

  RegIdx reg() const {
    return reg_;
  }

  void set_reg(RegIdx reg) {
    reg_ = reg;
  }

  void set_offset(BitSize val) {
    offset_ = val;
  }

  void set_keep_rest(bool val) {
    keep_rest_ = val;
  }

  Arg* AdvanceBy(BitSize bits) override;

 private:
  RegIdx reg_;
  // Bit offset from the beginning of the full uptr register
  // (e.g. AH has 8 bit offset in RAX).
  BitSize offset_;
  // If set, keep the rest of the full register intact, otherwise zero
  // (e.g. store into EAX, but keep the high 4 bytes of RAX intact).
  bool keep_rest_;

  Word EvalImpl(Env& env, const CPUContext& ctx) const override;
  void StoreImpl(Env& env, CPUContext& ctx, Word val) const override;
  bool CanVectorize() const override;
  bool IsValidImpl(bool is_dst) const override;
  LogBuf DumpImpl() const override;
};

// Memory reference argument.
class MemArg : public Arg {
 public:
  MemArg(RegIdx seg_reg, RegIdx base_reg, RegIdx index_reg, BitSize index_shift,
         BitSize index_extend_size, bool index_extend_sign, Addr offset,
         BitSize size)
      : Arg(this, size)
      , seg_reg_(seg_reg)
      , base_reg_(base_reg)
      , index_reg_(index_reg)
      , index_shift_(index_shift)
      , index_extend_size_(index_extend_size)
      , index_extend_sign_(index_extend_sign)
      , offset_(offset) {}

  bool operator==(const MemArg&) const = default;

  // Denote evaluated but not dereferenced address (e.g. LEA arg).
  void address_arg() {
    address_arg_ = true;
  }

  void set_seg_reg(RegIdx reg) {
    seg_reg_ = reg;
  }

  Addr offset() const {
    return offset_;
  }

  void set_offset(Addr offset) {
    offset_ = offset;
  }

  bool IsRegDereference(RegIdx reg) const;
  Arg* AdvanceBy(BitSize bits) override;

 private:
  RegIdx seg_reg_;
  const RegIdx base_reg_;
  const RegIdx index_reg_;
  const BitSize index_shift_;
  const BitSize index_extend_size_;
  const bool index_extend_sign_;
  Addr offset_;
  bool address_arg_ = false;

  Word EvalImpl(Env& env, const CPUContext& ctx) const override;
  void StoreImpl(Env& env, CPUContext& ctx, Word val) const override;
  Word EvalAddr(const CPUContext& ctx) const;
  bool CheckAlignment(Env& env, const Word& addr) const;
  bool CanVectorize() const override;
  bool IsValidImpl(bool is_dst) const override;
  LogBuf DumpImpl() const override;
};

// Mask of kFlagZero/kFlagSign/... flags compressed to 1 byte.
// It's used to reduce size of Instr::Flags/Predicate to reduce stack
// space usage during instruction decoding.
class FlagsMask {
 public:
  constexpr FlagsMask(uptr v = 0)
      : v_(Compress(v)) {}

  FlagsMask& operator=(FlagsMask other) {
    v_ = other.v_;
    return *this;
  }

  void operator|=(FlagsMask other) {
    v_ |= other.v_;
  }

  void operator&=(FlagsMask other) {
    v_ &= other.v_;
  }

  operator uptr() const {
    return Decompress(v_);
  }

 private:
  u8 v_;

  enum Compressed {
    kZero = 1 << 0,
    kSign = 1 << 1,
    kOverflow = 1 << 2,
    kCarry = 1 << 3,
    kAuxCarry = 1 << 4,
    kParity = 1 << 5,
  };

  static constexpr u8 Compress(uptr v) {
    return ((v & kFlagZero) ? kZero : 0) | ((v & kFlagSign) ? kSign : 0) |
           ((v & kFlagOverflow) ? kOverflow : 0) |
           ((v & kFlagCarry) ? kCarry : 0) |
           ((v & kFlagAuxCarry) ? kAuxCarry : 0) |
           ((v & kFlagParity) ? kParity : 0);
  }

  static constexpr uptr Decompress(u8 v) {
    return ((v & kZero) ? kFlagZero : 0) | ((v & kSign) ? kFlagSign : 0) |
           ((v & kOverflow) ? kFlagOverflow : 0) |
           ((v & kCarry) ? kFlagCarry : 0) |
           ((v & kAuxCarry) ? kFlagAuxCarry : 0) |
           ((v & kParity) ? kFlagParity : 0);
  }
};

// Instr describes an abstract ISA instruction used for emulation/analysis.
// All instructions have 1 destination argument and 0-3 source operands.
class Instr {
 public:
  using ArgArray = Array<Arg*, kMaxInstrArgs>;

  Instr(uptr pc, OpRef op, Arg* dst, const ArgArray& src)
      : pc_(pc)
      , op_(op)
      , dst_(dst)
      , src_{src} {}

  uptr pc() const {
    return pc_;
  }

  OpRef op() const {
    return op_;
  }

  BitSize size() const {
    if (vector_size_ != 0)
      return vector_size_;
    return dst()->size();
  }

  Arg* dst() const {
    return dst_;
  }

  Arg* src(uptr i) const {
    return src_.at(i);
  }

  BitSize vector_size() const {
    return vector_size_;
  }

  // If set to a non-zero value, performs intra-word auto-vectorization based on
  // the provided `size` for each element.
  void set_vector_size(BitSize size) {
    SAN_CHECK(Bytes(size) == 0 || Bytes(size) == 1 || Bytes(size) == 2 ||
                  Bytes(size) == 4 || size == kPtrSize,
              "size=%zu", Bits(size));
    if (size == kPtrSize)
      vector_size_ = 0;
    else
      vector_size_ = size;
  }

  // Flags describes flags affected by the instruction.
  class Flags {
   public:
    // The following fields are bitmask of kFlag* constants.
    FlagsMask compute = 0;    // computes these flags from the result
    FlagsMask set = 0;        // sets these flags to 1
    FlagsMask reset = 0;      // resets these flags to 0
    FlagsMask undefined = 0;  // these flags are left undefined
    bool temp = false;        // if set, use kTEMPFLAGS instead of kFLAGS

    bool Empty() const;
    void CheckValid() const;
    LogBuf Dump() const;
  };

  Instr& Set(const Flags& flags);
  const Flags& flags() const {
    return flags_;
  }

  // Predicate describes execution predicate for conditional instructions.
  // If the predicate is not satisfied, the instruction is not executed.
  struct Predicate {
    // All of the following conditions on the flag register must be true.
    FlagsMask set = 0;      // these flags must be set
    FlagsMask reset = 0;    // these flags must not be set
    FlagsMask eq = 0;       // these 2 flags must be equal
    FlagsMask neq = 0;      // these 2 flags must not be equal
    bool inverted = false;  // inverts meaning of the whole predicate
    bool temp = false;      // if set, use kTEMPFLAGS instead of kFLAGS

    Predicate Inverted() const;
    void CheckValid() const;
    LogBuf Dump() const;
  };

  Instr& Set(const Predicate& pred);
  const Predicate& pred() const {
    return pred_;
  }

  template <typename... Args>
  Instr& SetUndef(Args&&... args) {
    undef_ = RegSet(args...);
    return *this;
  }

  template <typename... Args>
  Instr& SetUninit(Args&&... args) {
    uninit_ = RegSet(args...);
    return *this;
  }

  template <typename... Args>
  Instr& SetInit(Args&&... args) {
    init_ = RegSet(args...);
    return *this;
  }

  template <typename... Args>
  Instr& SetUses(Args&&... args) {
    uses_ = RegSet(args...);
    return *this;
  }

  const RegSet& undef() const {
    return undef_;
  }

  const RegSet& uninit() const {
    return uninit_;
  }

  const RegSet& init() const {
    return init_;
  }

  const RegSet& uses() const {
    return uses_;
  }

  LogBuf Dump() const;

 private:
  const uptr pc_ = 0;  // where it come from
  OpRef op_;
  Arg* const dst_;
  ArgArray src_;
  Flags flags_;
  Predicate pred_;
  BitSize vector_size_;

  // The following RegSet's capture implicit effects and assumptions of the
  // instruction that are not captured by source/destination arguments.
  // Undefined/implementation-defined register results.
  RegSet undef_;
  // Uninitialized register results (using these later is a bug).
  // Note: we can have all combinations of undef/uninit.
  // undef && !uninit is RDTSC result (we don't know it, but using it is OK).
  // !undef && uninit is callee-saved registers on CALL (we know their values,
  //     but using them within the function is not OK).
  // undef && uninit is BSF result on 0 input (we don't know it and it's not
  //     OK to use it).
  RegSet uninit_;
  // These are initialized by the instruction.
  RegSet init_;
  // These must be initialized when instruction starts (or it's a bug).
  RegSet uses_;
};

// InstrSequence represents a sequence of abstract instructions decoded
// from a single real instruction.
class InstrSequence {
 public:
  virtual uptr GetSequenceSize() const = 0;
  virtual const Instr& GetInstr(uptr i) const = 0;
  // Size of the decoded instruction.
  virtual uptr GetByteSize() const = 0;
  virtual bool IsAtomic() const = 0;

 protected:
  ~InstrSequence() = default;
};

}  // namespace gwpsan SAN_LOCAL

#endif
