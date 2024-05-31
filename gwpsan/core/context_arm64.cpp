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

#include <linux/ptrace.h>
#include <signal.h>

#include "gwpsan/core/context.h"

namespace gwpsan {
namespace {
uptr GetTPIDR() {
  uptr val;
  asm("mrs %0, tpidr_el0" : "=r"(val));
  return val;
}
}  // namespace

bool CPUContext::Init() {
  features_ |= kFeatureInitialized;
  return true;
}

CPUContext::CPUContext(ucontext_t& uctx)
    : uctx_(&uctx) {
  const auto& mctx = uctx.uc_mcontext;
  regs_[kPC].val = mctx.pc;
  regs_[kSP].val = mctx.sp;
  regs_[kFLAGS].val = mctx.pstate;
  regs_[kLR].val = mctx.regs[30];
  for (int i = static_cast<int>(kX0); i <= static_cast<int>(kXLAST); ++i)
    regs_[i].val = mctx.regs[i - static_cast<int>(kX0)];
  const auto& simd = *reinterpret_cast<const fpsimd_context*>(mctx.__reserved);
  SAN_CHECK_EQ(simd.head.magic, FPSIMD_MAGIC);
  SAN_CHECK_EQ(simd.head.size, sizeof(fpsimd_context));
  for (int i = static_cast<int>(kQ0); i <= static_cast<int>(kQLAST); ++i)
    regs_[i].val =
        reinterpret_cast<const uptr*>(simd.vregs)[i - static_cast<int>(kQ0)];
  regs_[kTPIDR].val = GetTPIDR();
  // Reset SSBS since it's set as the result of hitting a breakpoint.
  regs_[kFLAGS].val &= ~0x00200000;
}

void CPUContext::ToUContextEnable() {}

void CPUContext::ToUContext(ucontext_t& uctx) const {
  auto& mctx = uctx.uc_mcontext;
  mctx.pc = regs_[kPC].val;
  mctx.sp = regs_[kSP].val;
  mctx.regs[30] = regs_[kLR].val;
  mctx.pstate = regs_[kFLAGS].val;
  for (int i = kX0; i <= kXLAST; ++i)
    mctx.regs[i - kX0] = regs_[i].val;
  auto& simd = *reinterpret_cast<fpsimd_context*>(mctx.__reserved);
  SAN_CHECK_EQ(simd.head.magic, FPSIMD_MAGIC);
  SAN_CHECK_EQ(simd.head.size, sizeof(fpsimd_context));
  for (int i = kQ0; i <= kQLAST; ++i)
    reinterpret_cast<uptr*>(simd.vregs)[i - kQ0] = regs_[i].val;
}

void CPUContext::InitUnemulated(const CPUContext& real) {
  // See comments in context_x86.cpp.
  SAN_CHECK_EQ(regs_[kFLAGS].val & ~kAllFlags, 0);
  regs_[kFLAGS].val |= real.regs_[kFLAGS].val & ~kAllFlags;
  for (auto reg : (RegIdx[]){kTPIDR}) {
    SAN_CHECK_EQ(regs_[reg].val, 0);
    regs_[reg] = real.regs_[reg];
  }
}

void CPUContext::SetupCallArch(uptr return_to) {
  regs_[kLR].val = return_to;
  // Setup TLS for MSan, libc calls, etc.
  regs_[kTPIDR].val = GetTPIDR();
}

uptr CPUContext::ReturnPC() const {
  return regs_[kLR].val;
}

LogBuf DumpBytesImpl(uptr addr, uptr size) {
  LogBuf buf;
  buf.Append("%08x", *reinterpret_cast<u32*>(addr));
  return buf;
}

void CPUContext::UpdateRegister(RegIdx reg, uptr val) {
  SAN_CHECK(uctx_);
  auto& mctx = uctx_->uc_mcontext;
  if (reg == kPC) {
    mctx.pc = val;
  } else if (reg == kSP) {
    mctx.sp = val;
  } else if (reg == kLR) {
    mctx.regs[30] = val;
  } else if (reg >= kX0 && reg <= kXLAST) {
    mctx.regs[reg - kX0] = val;
  } else {
    SAN_BUG("unsupported register %s", RegNames[reg]);
  }
  regs_[reg].val = val;
}

const char RegNames[kRegCount][kRegNameMaxLen] = {
    [kPC] = "PC",
    [kSP] = "SP",
    [kFLAGS] = "PSTATE",

    [kRZ] = "RZ",
    [kUNDEF] = "UNDEF",
    [kTEMP0] = "TEMP0",
    [kTEMP1] = "TEMP1",
    [kTEMP2] = "TEMP2",
    [kTEMP3] = "TEMP3",
    [kTEMP4] = "TEMP4",
    [kTEMP5] = "TEMP5",
    [kTEMP6] = "TEMP6",
    [kTEMP7] = "TEMP7",
    [kTEMP8] = "TEMP8",
    [kTEMP9] = "TEMP9",
    [kTEMP10] = "TEMP10",
    [kTEMP11] = "TEMP11",
    [kTEMP12] = "TEMP12",
    [kTEMP13] = "TEMP13",
    [kTEMP14] = "TEMP14",
    [kTEMP15] = "TEMP15",
    [kTEMPFLAGS] = "TFLAGS",

    [kLR] = "LR",
    [kTPIDR] = "TPIDR",

    [kX0] = "X0",
    [kX0 + 1] = "X1",
    [kX0 + 2] = "X2",
    [kX0 + 3] = "X3",
    [kX0 + 4] = "X4",
    [kX0 + 5] = "X5",
    [kX0 + 6] = "X6",
    [kX0 + 7] = "X7",
    [kX0 + 8] = "X8",
    [kX0 + 9] = "X9",
    [kX0 + 10] = "X10",
    [kX0 + 11] = "X11",
    [kX0 + 12] = "X12",
    [kX0 + 13] = "X13",
    [kX0 + 14] = "X14",
    [kX0 + 15] = "X15",
    [kX0 + 16] = "X16",
    [kX0 + 17] = "X17",
    [kX0 + 18] = "X18",
    [kX0 + 19] = "X19",
    [kX0 + 20] = "X20",
    [kX0 + 21] = "X21",
    [kX0 + 22] = "X22",
    [kX0 + 23] = "X23",
    [kX0 + 24] = "X24",
    [kX0 + 25] = "X25",
    [kX0 + 26] = "X26",
    [kX0 + 27] = "X27",
    [kX0 + 28] = "X28",
    [kX0 + 29] = "X29",

    [kQ0 + 0] = "Q0L",
    [kQ0 + 1] = "Q0H",
    [kQ0 + 2] = "Q1L",
    [kQ0 + 3] = "Q1H",
    [kQ0 + 4] = "Q2L",
    [kQ0 + 5] = "Q2H",
    [kQ0 + 6] = "Q3L",
    [kQ0 + 7] = "Q3H",
    [kQ0 + 8] = "Q4L",
    [kQ0 + 9] = "Q4H",
    [kQ0 + 10] = "Q5L",
    [kQ0 + 11] = "Q5H",
    [kQ0 + 12] = "Q6L",
    [kQ0 + 13] = "Q6H",
    [kQ0 + 14] = "Q7L",
    [kQ0 + 15] = "Q7H",
    [kQ0 + 16] = "Q8L",
    [kQ0 + 17] = "Q8H",
    [kQ0 + 18] = "Q9L",
    [kQ0 + 19] = "Q9H",
    [kQ0 + 20] = "Q10L",
    [kQ0 + 21] = "Q10H",
    [kQ0 + 22] = "Q11L",
    [kQ0 + 23] = "Q11H",
    [kQ0 + 24] = "Q12L",
    [kQ0 + 25] = "Q12H",
    [kQ0 + 26] = "Q13L",
    [kQ0 + 27] = "Q13H",
    [kQ0 + 28] = "Q14L",
    [kQ0 + 29] = "Q14H",
    [kQ0 + 30] = "Q15L",
    [kQ0 + 31] = "Q15H",
    [kQ0 + 32] = "Q16L",
    [kQ0 + 33] = "Q16H",
    [kQ0 + 34] = "Q17L",
    [kQ0 + 35] = "Q17H",
    [kQ0 + 36] = "Q18L",
    [kQ0 + 37] = "Q18H",
    [kQ0 + 38] = "Q19L",
    [kQ0 + 39] = "Q19H",
    [kQ0 + 40] = "Q20L",
    [kQ0 + 41] = "Q20H",
    [kQ0 + 42] = "Q21L",
    [kQ0 + 43] = "Q21H",
    [kQ0 + 44] = "Q22L",
    [kQ0 + 45] = "Q22H",
    [kQ0 + 46] = "Q23L",
    [kQ0 + 47] = "Q23H",
    [kQ0 + 48] = "Q24L",
    [kQ0 + 49] = "Q24H",
    [kQ0 + 50] = "Q25L",
    [kQ0 + 51] = "Q25H",
    [kQ0 + 52] = "Q26L",
    [kQ0 + 53] = "Q26H",
    [kQ0 + 54] = "Q27L",
    [kQ0 + 55] = "Q27H",
    [kQ0 + 56] = "Q28L",
    [kQ0 + 57] = "Q28H",
    [kQ0 + 58] = "Q29L",
    [kQ0 + 59] = "Q29H",
    [kQ0 + 60] = "Q30L",
    [kQ0 + 61] = "Q30H",
    [kQ0 + 62] = "Q31L",
    [kQ0 + 63] = "Q31H",
};

}  // namespace gwpsan
