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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_ARCH_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_ARCH_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

enum RegIdx {
  kPC,
  kSP,
  kFLAGS,
  kRZ,     // zero register
  kUNDEF,  // undefined and uninitialized value (must be used only as a source)
  // These registers can be used by our ISA,
  // but are not part of the real CPU architectural state.
  kTEMP0,
  kTEMP1,
  kTEMP2,
  kTEMP3,
  kTEMP4,
  kTEMP5,
  kTEMP6,
  kTEMP7,
  kTEMP8,
  kTEMP9,
  kTEMP10,
  kTEMP11,
  kTEMP12,
  kTEMP13,
  kTEMP14,
  kTEMP15,
  kTEMPFLAGS,
#if GWPSAN_X64
  kRBP,
  kRAX,
  kRBX,
  kRCX,
  kRDX,
  kRDI,
  kRSI,
  kR8,
  kR9,
  kR10,
  kR11,
  kR12,
  kR13,
  kR14,
  kR15,
  kFS,
  kGS,
  kK0,
  kK1,
  kK2,
  kK3,
  kK4,
  kK5,
  kK6,
  kK7,
  // Vector registers must be last (before kRegCount). See IsVectorReg().
  kXMM0,
  kXMMLAST = kXMM0 + 32 * 4 - 1,  // 32 x 4 registers including YMM
#elif GWPSAN_ARM64
  kLR,  // X30
  kTPIDR,
  kX0,
  kX1,
  kX2,
  kX3,
  kX4,
  kX5,
  kX6,
  kX7,
  kX8,
  kX9,
  kX10,
  kX11,
  kX12,
  kX29 = kX0 + 29,  // frame pointer
  kXLAST = kX29,
  kQ0,
  kQLAST = kQ0 + 32 * 2 - 1,  // 32 128-bit registers
#endif
  kRegCount,
};

#if GWPSAN_X64
// Function return value register.
inline constexpr RegIdx kResultReg = kRAX;
// Registers used to pass function arguments.
inline constexpr RegIdx kArgRegs[] = {kRDI, kRSI, kRDX, kRCX, kR8, kR9};
inline constexpr RegIdx kSyscallNumReg = kRAX;
inline constexpr RegIdx kSyscallArgRegs[] = {kRDI, kRSI, kRDX, kR10, kR8, kR9};
// Start of vector registers.
inline constexpr RegIdx kVectorRegStart = kXMM0;
inline constexpr uptr kVectorRegWords = 4;
static_assert(kRegCount - kVectorRegStart == 32 * kVectorRegWords);
inline constexpr uptr kMaxInstrLen = 15;
inline constexpr u8 kUndefinedInstruction[] = {0x0f, 0x0b};  // ud2
#elif GWPSAN_ARM64
inline constexpr RegIdx kResultReg = kX0;
inline constexpr RegIdx kArgRegs[] = {kX0, kX1, kX2, kX3, kX4, kX5};
inline constexpr RegIdx kSyscallNumReg = kX8;
inline constexpr RegIdx kSyscallArgRegs[] = {kX0, kX1, kX2, kX3, kX4, kX5};
inline constexpr RegIdx kVectorRegStart = kQ0;
inline constexpr uptr kVectorRegWords = 2;
inline constexpr uptr kMaxInstrLen = 4;
inline constexpr char kUndefinedInstruction[] = {0, 0, 0, 0};  // udf #0
#endif

#if GWPSAN_X64
inline constexpr uptr kFlagZero = 0x0040;      // ZF
inline constexpr uptr kFlagSign = 0x0080;      // SF
inline constexpr uptr kFlagOverflow = 0x0800;  // OF
inline constexpr uptr kFlagCarry = 0x0001;     // CF
inline constexpr uptr kFlagAuxCarry = 0x0010;  // AF
inline constexpr uptr kFlagParity = 0x0004;    // PF
inline constexpr uptr kFlagBranchJump = 0;
inline constexpr uptr kFlagBranchCall = 0;
#elif GWPSAN_ARM64
inline constexpr uptr kFlagZero = 0x40000000;      // ZF
inline constexpr uptr kFlagSign = 0x80000000;      // NF
inline constexpr uptr kFlagOverflow = 0x10000000;  // VF
inline constexpr uptr kFlagCarry = 0x20000000;     // CF
inline constexpr uptr kFlagAuxCarry = 0;
inline constexpr uptr kFlagParity = 0;
inline constexpr uptr kFlagBranchJump = 0x400;  // PSR_BTYPE_JC
inline constexpr uptr kFlagBranchCall = 0x800;  // PSR_BTYPE_C
#endif
inline constexpr uptr kAllFlags = kFlagZero | kFlagSign | kFlagOverflow |
                                  kFlagCarry | kFlagAuxCarry | kFlagParity |
                                  kFlagBranchJump | kFlagBranchCall;

// Avoid an array of char*, because it produces a relocation for each string
// (the final binary would be significantly larger). The trade-off are a few
// extra bytes at runtime.
inline constexpr uptr kRegNameMaxLen = 8;
extern const char RegNames[kRegCount][kRegNameMaxLen];

constexpr bool IsTempReg(int reg) {
  return reg >= kTEMP0 && reg <= kTEMPFLAGS;
}

constexpr bool IsGeneralTempReg(int reg) {
  return reg >= kTEMP0 && reg < kTEMPFLAGS;
}

constexpr bool IsVectorReg(int reg) {
  return reg >= kVectorRegStart && reg < kRegCount;
}

constexpr bool IsMaskReg(int reg) {
#if GWPSAN_X64
  return reg >= kK0 && reg <= kK7;
#else
  return false;
#endif
}

constexpr bool IsAVX512Reg(int reg) {
#if GWPSAN_X64
  return (IsVectorReg(reg) && ((reg - kXMM0) / kVectorRegWords) >= 16) ||
         IsMaskReg(reg);
#else
  return false;
#endif
}

}  // namespace gwpsan SAN_LOCAL

#endif
