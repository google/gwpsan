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

#include "gwpsan/core/origin.h"

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/operation.h"
#include "gwpsan/core/report.h"

namespace gwpsan {

Origin::Type Origin::type() const {
  return Type::kChained;
}

const InstructionOrigin* Origin::Instruction() const {
  return nullptr;
}

OriginWithStack::OriginWithStack(const CPUContext& ctx) {
  stack_.emplace_back(ctx.reg(kPC).val);
  if (!GetFlags().origin_stacks)
    return;
  tid_ = GetTid();
  UnwindStack(stack_, ctx.uctx());
}

void OriginWithStack::Print() const {
  PrintNoStack();
  if (!GetFlags().origin_stacks) {
    Printf(" at %s\n", &DumpInstr(pc(), kDumpSource));
    return;
  }
  Printf("\nthread T%u at:\n", tid_);
  PrintStackTrace(stack_, "  ");
}

TaintOrigin::TaintOrigin(Type type, const char* description)
    : type_(type)
    , pc_(SAN_CALLER_PC()) {
  SAN_CHECK_NE(type, Origin::Type::kChained);
  if (description) {
    internal_strncpy(description_, description, sizeof(description_));
    description_[sizeof(description_) - 1] = 0;
  }
}

Origin::Type TaintOrigin::type() const {
  return type_;
}

void TaintOrigin::Print() const {
  Printf("\"%s\" at %s\n", description_, &DumpInstr(pc_, kDumpSource));
}

MallocOrigin::MallocOrigin(const CPUContext& ctx, uptr ptr, uptr size,
                           uptr offset)
    : OriginWithStack(ctx)
    , ptr_(ptr)
    , size_(size)
    , offset_(offset) {}

Origin::Type MallocOrigin::type() const {
  return Origin::Type::kUninit;
}

void MallocOrigin::PrintNoStack() const {
  Printf("Malloc(%zu)=0x%zx offset %zu created uninit", size_, ptr_, offset_);
}

UndefinedResultOrigin::UndefinedResultOrigin(const CPUContext& ctx, RegIdx reg)
    : OriginWithStack(ctx)
    , reg_(reg) {}

Origin::Type UndefinedResultOrigin::type() const {
  return Origin::Type::kUninit;
}

void UndefinedResultOrigin::PrintNoStack() const {
  Printf("Undefined instruction result created uninit in %s\n    %s",
         RegNames[reg_], &DumpInstr(pc(), kDumpAsm));
}

InstructionOrigin::InstructionOrigin(const CPUContext& ctx, uptr size)
    : OriginWithStack(ctx)
    , next_pc_(pc() + size) {}

uptr InstructionOrigin::next_pc() const {
  return next_pc_;
}

const InstructionOrigin* InstructionOrigin::Instruction() const {
  return this;
}

void InstructionOrigin::PrintNoStack() const {
  Printf("\ninstruction %s", &DumpInstr(pc(), kDumpAsm));
}

MemLoadOrigin::MemLoadOrigin(uptr addr, uptr val, bool tainted_addr)
    : addr_(addr)
    , val_(val)
    , tainted_addr_(tainted_addr) {}

void MemLoadOrigin::Print() const {
  Printf("    load from%s 0x%zx = 0x%zx\n",
         tainted_addr_ ? " tainted address" : "", addr_, val_);
}

MemStoreOrigin::MemStoreOrigin(uptr addr)
    : addr_(addr) {}

void MemStoreOrigin::Print() const {
  Printf("    store to 0x%zx\n", addr_);
}

RegLoadOrigin::RegLoadOrigin(RegIdx reg, uptr val)
    : reg_(reg)
    , val_(val) {}

void RegLoadOrigin::Print() const {
  Printf("    take %s = 0x%zx\n", RegNames[reg_], val_);
}

RegStoreOrigin::RegStoreOrigin(RegIdx reg)
    : reg_(reg) {}

void RegStoreOrigin::Print() const {
  Printf("    put %s\n", RegNames[reg_]);
}

namespace {
Array<uptr, kMaxInstrArgs> ArgsToVals(const OpArgs& srcs) {
  Array<uptr, kMaxInstrArgs> vals;
  for (int i = 0; i < srcs.size(); i++)
    vals[i] = srcs[i].val;
  return vals;
}
}  // namespace

OpOrigin::OpOrigin(OpRef op, uptr res, const OpArgs& srcs)
    : op_(op)
    , res_(res)
    , srcs_{ArgsToVals(srcs)} {}

void OpOrigin::Print() const {
  LogBuf buf;
  for (uptr i = 0; i < op_.ArgCount(); i++)
    buf.Append("%s0x%zx", i ? ", " : "", srcs_[i]);
  Printf("    %s(%s) -> 0x%zx\n", op_.Name(), &buf, res_);
}

namespace {
Origin::Type ChainType(Origin* origin, OriginChain* prev) {
  if (prev) {
    SAN_CHECK_EQ(origin->type(), Origin::Type::kChained);
    return prev->type();
  }
  SAN_CHECK_NE(origin->type(), Origin::Type::kChained);
  return origin->type();
}
}  // namespace

OriginChain::OriginChain(Origin* origin, OriginChain* prev)
    : prev_(prev)
    , origin_(origin)
    , type_(ChainType(origin, prev))
    , depth_(prev ? prev->depth_ + 1 : 0) {
  SAN_CHECK_NE(type_, Origin::Type::kChained);
}

void OriginChain::Print() const {
  // In the simplest form this could be simply:
  //   if (prev_) prev_->Print();
  // However, if we have a sequence of InstructionOrigins w/o any other
  // intervening origins, it means the data just stayed in a register
  // while we were executing instructions on other data. Printing all of these
  // instructions that haven't really touched the data is unnecessary and
  // distracts attention.
  // So instead we aggregate such instructions into blocks and print
  // a single line per block ("executed PC range PC1...PC2").
  if (prev_) {
    auto prev = prev_;
    struct PCRange {
      uptr start;
      uptr end;
    };
    Array<PCRange, 16> trace;
    uptr trace_size = 0;
    bool trace_overflow = false;
    if (origin_->Instruction()) {
      for (;;) {
        const auto* instr = prev->origin_->Instruction();
        if (!instr)
          break;
        uptr pc = instr->pc();
        uptr next_pc = instr->next_pc();
        if (trace_size && trace[trace_size - 1].start == next_pc)
          trace[trace_size - 1].start = pc;
        else if (trace_size < trace.size())
          trace[trace_size++] = {pc, pc};
        else
          trace_overflow = true;
        prev = prev->prev_;
      }
    }
    prev->Print();
    if (trace_size && (trace_size > 1 || trace[0].start != trace[0].end)) {
      Printf("\n");
      for (sptr i = trace_size - 1; i >= 0; i--) {
        Printf("execute: 0x%zx", trace[i].start);
        if (trace[i].end != trace[i].start)
          Printf("...0x%zx", trace[i].end);
        Printf(" %s\n", &DumpInstr(trace[i].start, kDumpModule));
      }
      if (trace_overflow)
        Printf("... more traces skipped ...\n");
    }
  }
  origin_->Print();
}

OriginChain* OriginChain::Simpler(OriginChain* a, OriginChain* b) {
  // This function is used when we extend a single tracked bit to the whole
  // resulting word. It's unclear what type we should prefer, for now we just
  // make it deterministic. It's also unlikely that a single word contains
  // tracked bits of different types, so potentially it does not matter much.
  Origin::Type ta = a ? a->type() : Origin::Type::kAny;
  Origin::Type tb = b ? b->type() : Origin::Type::kAny;
  if (ta != tb)
    return ta > tb ? a : b;
  uptr da = a ? a->depth_ : ~0ul;
  uptr db = b ? b->depth_ : ~0ul;
  return da <= db ? a : b;
}

}  // namespace gwpsan
