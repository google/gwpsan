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

#ifndef GWPSAN_CORE_DECODER_H_
#define GWPSAN_CORE_DECODER_H_

#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/operation.h"

namespace gwpsan SAN_LOCAL {

// Base class for instruction decoders, which decode a single real instruction
// into several abstract ISA instructions (e.g. PUSH is decoded into move to
// memory + subtraction from RSP.
// Decoder also serves as a region memory allocator for decoded instructions
// and arguments (valid only for the life-time of the decoder object).
class InstrDecoder : public InstrSequence {
 public:
  // Decodes the instruction at address pc_copy as though it were located at
  // address pc. If the instruction is not copied (decoding instruction at its
  // actual address), pc_copy can be set to 0.
  explicit InstrDecoder(uptr pc, uptr pc_copy);
  bool Decode();

  uptr GetSequenceSize() const override {
    return instrs_.size();
  }

  const Instr& GetInstr(uptr i) const override {
    return *instrs_.at(i);
  }

  // Size of the decoded instruction.
  uptr GetByteSize() const override {
    return byte_size_;
  }

  // Tells if the instruction is known to be "atomic" (e.g. LOCK-prefixed).
  bool IsAtomic() const override {
    return is_atomic_;
  }

  // Returns opaque decoded instruction opcode (or 0 if it wasn't decoded)
  // and the opcode name.
  uptr GetOpcode(const char*& name) const {
    name = opcode_name_;
    return opcode_;
  }

  // Returns opaque decoded instruction opcode (or 0 if it wasn't decoded).
  uptr GetOpcode() const {
    return opcode_;
  }

  // Error handling:
  // The decoder is designed to not crash/CHECK-fail in any unexpected
  // situations (new/unsupported instructions, unexpected operand types,
  // unexpected number of operands in instructions, etc). Instead it returns
  // non-null error description on any failures.
  // However, in order to support fuzzing and unit-testing it also has
  // a notion of "hard" failures (something that must not happen at all
  // even during fuzzing).
  // Derived classes must use DECODE_FAIL/DECODE_UNIMPL macros declared below
  // to signal about hard failures and normal failures, correspondingly.
  const char* failed() const {
    return failed_ ? fail_message_ : nullptr;
  }

  bool hard_failed() const {
    return failed_hard_;
  }

  uptr pc() const {
    return pc_;
  }

 protected:
  // Emit one more decoded instruction.
  Instr& Emit(OpRef op = OpNop, Arg* dst = nullptr, Arg* src0 = nullptr,
              Arg* src1 = nullptr, Arg* src2 = nullptr);

  // Note that the instruction accesses memory at addr.
  // Currently this is needed to avoid crashes on unmapped memory in tests
  // and during fuzzing, but later this may be used for other purposes.
  // Does nothing if addr is not a MemArg as a convenience.
  void NoteMemoryAccess(Arg* addr);

  Arg* CopyArg(const Arg* arg);
  Arg* NewImmArg(uptr val, BitSize size = kPtrSize);
  Arg* NewRegArg(RegIdx reg, BitSize size = kPtrSize, BitSize offset = 0,
                 bool keep_rest = false);
  Arg* NewMemArg(RegIdx seg_reg, RegIdx base_reg, RegIdx index_reg,
                 BitSize index_shift, BitSize index_extend_size,
                 bool index_extend_sign, Addr offset, BitSize size);
  // NextWord returns a copy of the arg that refers to the next word.
  Arg* NextWord(const Arg* arg);
  // AdvanceBy returns a copy of the arg that refers to the 'bits' bits.
  Arg* AdvanceBy(const Arg* arg, BitSize bits);

  // Set byte size of the decoded instruction.
  void set_byte_size(uptr byte_size);
  // Set information about decoded instruction opcode.
  void set_opcode(uptr opcode, const char* opcode_name);

  void set_atomic(bool v) {
    is_atomic_ = v;
  }

  void Fail(bool hard, const char* msg, ...) SAN_FORMAT(3, 4);

  uptr pc_copy() const {
    return pc_copy_;
  }

  // This is to prevent "has virtual functions but non-virtual destructor"
  // warnings, it's not supposed to be destroyed via pointer to base type.
  virtual ~InstrDecoder() = default;

  // This is returned on any unexpected situations so that the code does not
  // crash on NULL derefs.
  ImmArg imm_fallback_;
  RegArg reg_fallback_;
  MemArg mem_fallback_;

 private:
  const uptr pc_;
  const uptr pc_copy_;
  uptr byte_size_ = 0;
  uptr opcode_ = 0;
  const char* opcode_name_ = nullptr;
  bool is_atomic_ = false;

  // Maximum number of instructions decoded from a single real instruction.
  // Normally we decode 1-3 instructions, but there are some notorious
  // exceptions.
  static constexpr uptr kMaxInstrs = 72;
  ArrayVector<Instr*, kMaxInstrs> instrs_;

  CachedArenaAllocator<InstrDecoder> alloc_;

  bool failed_ = false;
  bool failed_hard_ = false;
  char fail_message_[256];

  virtual void DecodeImpl() = 0;

  // Allocate region memory for instructions/arguments.
  template <typename T, typename... Args>
  T* New(Args&&... args) {
    auto* ret = alloc_.New<T>(forward<Args>(args)...);
    if (SAN_UNLIKELY(!ret)) {
      Fail(/*hard=*/true, "out of memory");
      return nullptr;
    }
    return ret;
  }

  void Vectorize();
  void VectorizeOne(const Instr& instr);
  template <typename T>
  Arg* TryCopyArg(const Arg* arg, T* fallback);

  InstrDecoder(const InstrDecoder&) = delete;
  InstrDecoder& operator=(const InstrDecoder&) = delete;
};

#define DECODE_UNIMPL(msg, ...) \
  Fail(false, "%s:%d: " msg, __FILE__, __LINE__, ##__VA_ARGS__)
#define DECODE_FAIL(msg, ...) \
  Fail(true, "%s:%d: " msg, __FILE__, __LINE__, ##__VA_ARGS__)

}  // namespace gwpsan SAN_LOCAL

#endif
