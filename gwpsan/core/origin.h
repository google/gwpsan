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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_ORIGIN_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_ORIGIN_H_

#include <ucontext.h>

#include "gwpsan/base/allocator.h"
#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/core_fwd.h"

namespace gwpsan SAN_LOCAL {

inline constexpr uptr kMaxInstrArgs = 3;

using OpArgs = Array<Word, kMaxInstrArgs>;

// Origins track where uninitialized/tainted values were created
// and how they reached the use/sink.
class Origin : public HeapAllocated {
 public:
  // Specifies type of the tracked bits in Meta.
  // The very first origin in a chain has a terminal type (anything other
  // than kChained), all subsequent origins have kChained type.
  // The whole chain has the terminal type of the first origin.
  enum class Type {
    kChained,         // all chained origins have this type
    kAny = kChained,  // used meta queries to select all terminal types
    kUninit,          // uninitialized bits (e.g. initial malloc contents)
    kTainted,         // user-tainted data for data-flow analysis
  };

  virtual Type type() const;
  virtual const InstructionOrigin* Instruction() const;
  virtual void Print() const = 0;

 protected:
  ~Origin() = default;
};

// Origin with memorized stack trace.
class OriginWithStack : public Origin {
 public:
  uptr pc() const {
    return stack_[0];
  }

 protected:
  OriginWithStack(const CPUContext& ctx);
  ~OriginWithStack() = default;

 private:
  static constexpr uptr kMaxStackSize = 8;
  ArrayVector<uptr, kMaxStackSize> stack_;
  int tid_ = 0;

  void Init(const ucontext_t* uctx, uptr pc);
  void Print() const final;
  virtual void PrintNoStack() const = 0;
};

// TaintOrigin captures where user explicitly tainted memory.
class TaintOrigin final : public Origin {
 public:
  TaintOrigin(Type type, const char* description);

 private:
  const Type type_;
  const uptr pc_;
  char description_[64];

  Type type() const override;
  void Print() const override;
};

// MallocOrigin captures where malloc created uninit memory.
class MallocOrigin final : public OriginWithStack {
 public:
  MallocOrigin(const CPUContext& ctx, uptr ptr, uptr size, uptr offset);

 private:
  const uptr ptr_;
  const uptr size_;
  const uptr offset_;

  Type type() const override;
  void PrintNoStack() const override;
};

// Undefined value created by an instruction
// (some instructions leave flags or other registers undefined).
class UndefinedResultOrigin final : public OriginWithStack {
 public:
  UndefinedResultOrigin(const CPUContext& ctx, RegIdx reg);

 private:
  const RegIdx reg_;

  Type type() const override;
  void PrintNoStack() const override;
};

// InstructionOrigin captures information about an instruction
// that was involved in tainted value processing.
class InstructionOrigin final : public OriginWithStack {
 public:
  InstructionOrigin(const CPUContext& ctx, uptr size);
  uptr next_pc() const;

 private:
  const uptr next_pc_;

  const InstructionOrigin* Instruction() const override;
  void PrintNoStack() const override;
};

// MemLoadOrigin captures information about a memory load that returned a
// tainted value.
class MemLoadOrigin final : public Origin {
 public:
  MemLoadOrigin(uptr addr, uptr val, bool tainted_addr = false);

 private:
  const uptr addr_;
  const uptr val_;
  const bool tainted_addr_;  // load through tainted address

  void Print() const override;
};

// MemStoreOrigin captures information about a tainted memory store.
class MemStoreOrigin final : public Origin {
 public:
  MemStoreOrigin(uptr addr);

 private:
  const uptr addr_;

  void Print() const override;
};

// RegLoadOrigin captures information about an instruction register source.
class RegLoadOrigin final : public Origin {
 public:
  RegLoadOrigin(RegIdx reg, uptr val);

 private:
  const RegIdx reg_;
  const uptr val_;

  void Print() const override;
};

// RegStoreOrigin captures information about an instruction register
// destination.
class RegStoreOrigin final : public Origin {
 public:
  RegStoreOrigin(RegIdx reg);

 private:
  const RegIdx reg_;

  void Print() const override;
};

// OpOrigin captures information about a data processing instruction (add/not).
class OpOrigin final : public Origin {
 public:
  OpOrigin(OpRef op, uptr res, const OpArgs& srcs);

 private:
  OpRef op_;
  const uptr res_;
  const Array<uptr, kMaxInstrArgs> srcs_;

  void Print() const override;
};

// OriginChain links multiple origins from source to sink together.
// Separation between Origin (a single operation) and OriginChain
// (sequence/tree of origins) allows to use the same origin in multiple
// nodes of the origin tree.
class OriginChain final : public HeapAllocated {
 public:
  explicit OriginChain(Origin* origin, OriginChain* prev = nullptr);
  void Print() const;

  Origin::Type type() const {
    return type_;
  }

  // Simpler selects origin chain that should be easier for user to understand.
  static OriginChain* Simpler(OriginChain* a, OriginChain* b);

 private:
  const OriginChain* prev_;
  const Origin* origin_;
  const Origin::Type type_;
  const uptr depth_;
  friend class MetaTest;
};

}  // namespace gwpsan SAN_LOCAL

#endif
