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
#include <sys/auxv.h>
#include <unistd.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/sanitizer.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"

#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE (1 << 1)
#endif

namespace gwpsan {
namespace {
constexpr int kRegMap[][2] = {
    {kPC,    REG_RIP},
    {kSP,    REG_RSP},
    {kFLAGS, REG_EFL},
    {kRBP,   REG_RBP},
    {kRAX,   REG_RAX},
    {kRBX,   REG_RBX},
    {kRCX,   REG_RCX},
    {kRDX,   REG_RDX},
    {kRDI,   REG_RDI},
    {kRSI,   REG_RSI},
    {kR8,    REG_R8 },
    {kR9,    REG_R9 },
    {kR10,   REG_R10},
    {kR11,   REG_R11},
    {kR12,   REG_R12},
    {kR13,   REG_R13},
    {kR14,   REG_R14},
    {kR15,   REG_R15},
};

struct extended_fpstate {
  u64 xfeatures;
  u64 reserved[7];
  u64 ymmh[32];
};

bool avx_enabled;
bool fsgs_base_enabled;
// Offsets of the corresponding parts in the XSAVE area of mcontext_t.
uptr xsave_opmask_offset;
uptr xsave_zmm_hi256_offset;
uptr xsave_hi16_zmm_offset;

// Extended control register bits.
constexpr u64 kXFeatureYmm = 0x4;
constexpr u64 kXFeatureOpmask = 0x20;
constexpr u64 kXFeatureZmm = 0x40;
constexpr u64 kXFeatureZmm16 = 0x80;
constexpr u64 kXFeatureAVX512 = kXFeatureOpmask | kXFeatureZmm | kXFeatureZmm16;

struct cpuid_res {
  u32 eax, ebx, ecx, edx;
};

cpuid_res cpuid(u32 eax, u32 ecx = 0) {
  cpuid_res res = {
      .eax = eax,
      .ecx = ecx,
  };
  asm("cpuid"
      : "=a"(res.eax), "=b"(res.ebx), "=c"(res.ecx), "=d"(res.edx)
      : "0"(res.eax), "2"(res.ecx));
  return res;
}

u64 xgetbv(u32 xcr = 0) {
  u32 eax, edx;
  asm("xgetbv" : "=a"(eax), "=d"(edx) : "c"(xcr));
  return (static_cast<u64>(edx) << 32) | eax;
}

void GetFSAndGS(uptr& fs, uptr& gs) {
  if (fsgs_base_enabled) {
    asm("rdfsbase %0" : "=r"(fs));
    asm("rdgsbase %0" : "=r"(gs));
  } else {
    SAN_WARN_IF_ERR(sys_arch_prctl(ARCH_GET_FS, &fs));
    SAN_WARN_IF_ERR(sys_arch_prctl(ARCH_GET_GS, &gs));
  }
}

const u32* ext_fpstate_field(const mcontext_t& mctx) {
  // The field after _xmm is named differently in different versions of glibc
  // (padding or __glibc_reserved1).
  return reinterpret_cast<const u32*>(
      reinterpret_cast<const char*>(&mctx.fpregs->_xmm) +
      sizeof(mctx.fpregs->_xmm));
}

}  // namespace

bool CPUContext::Init() {
  fsgs_base_enabled = getauxval(AT_HWCAP2) & HWCAP2_FSGSBASE;
  const auto vendor_id = cpuid(0x0);
  char vendor[13] = {};
  internal_memcpy(&vendor[0], &vendor_id.ebx, 4);
  internal_memcpy(&vendor[4], &vendor_id.edx, 4);
  internal_memcpy(&vendor[8], &vendor_id.ecx, 4);
  if (!internal_strcmp(vendor, "GenuineIntel"))
    features_ |= kFeatureIntel;
  else if (!internal_strcmp(vendor, "AuthenticAMD"))
    features_ |= kFeatureAMD;
  const auto features = cpuid(0x1);
  u32 family = (features.eax >> 8) & 0xf;
  if (family == 0xf)
    family += (features.eax >> 20) & 0xff;
  u32 model = (features.eax >> 4) & 0xf;
  if (family >= 0x6)
    model += ((features.eax >> 16) & 0xf) << 4;
  u32 stepping = features.eax & 0xf;
  SAN_LOG("cpu init: vendor=%s family=%u model=%u stepping=%u", vendor, family,
          model, stepping);
  if (features.ecx & (1 << 27)) {  // OSXSAVE
    const u64 bv = xgetbv();
    // Check AVX feature.
    avx_enabled = (features.ecx & (1 << 28)) && (bv & kXFeatureYmm);
    // Check AVX512F extended feature.
    bool avx512_enabled = (cpuid(0x7).ebx & (1 << 16)) &&
                          ((bv & kXFeatureAVX512) == kXFeatureAVX512);
    if (avx512_enabled) {
      xsave_opmask_offset = cpuid(0xd, 5).ebx;
      xsave_zmm_hi256_offset = cpuid(0xd, 6).ebx;
      xsave_hi16_zmm_offset = cpuid(0xd, 7).ebx;
      features_ |= kFeatureAVX512;
    }
    if (cpuid(0xd, 1).eax & 0x2)
      features_ |= kFeatureXSAVEC;
  }
  SAN_LOG(
      "cpu init: fsgs_base=%d avx=%d avx512=%d xsavec=%d xsave_opmask=%lx "
      "xsave_zmm_hi256=%lx xsave_hi16_zmm=%lx",
      fsgs_base_enabled, avx_enabled, !!(features_ & kFeatureAVX512),
      !!(features_ & kFeatureXSAVEC), xsave_opmask_offset,
      xsave_zmm_hi256_offset, xsave_hi16_zmm_offset);
  features_ |= kFeatureInitialized;
  return true;
}

CPUContext::CPUContext(ucontext_t& uctx)
    : uctx_(&uctx) {
  const auto& mctx = uctx.uc_mcontext;
  for (auto map : kRegMap)
    regs_[map[0]].val = mctx.gregs[map[1]];
  if (mctx.fpregs) {
    for (uptr i = 0; i < 16; i++) {
      regs_[kXMM0 + 4 * i].val =
          reinterpret_cast<uptr*>(mctx.fpregs->_xmm)[2 * i];
      regs_[kXMM0 + 4 * i + 1].val =
          reinterpret_cast<uptr*>(mctx.fpregs->_xmm)[2 * i + 1];
    }
    const auto& ext = *reinterpret_cast<extended_fpstate*>(mctx.fpregs + 1);
    if (ext_fpstate_field(mctx)[12] == FP_XSTATE_MAGIC1) {
      // The context is allocated by the kernel on the stack and can overlap
      // with some leftover uninit data. BreakManager unpoisons
      // sizeof(ucontext_t), but not the extended parts. We need to unpoison
      // any additional parts we use.
      MSAN_UNPOISON_MEMORY_REGION(&ext, sizeof(ext));
      if (avx_enabled && (ext.xfeatures & kXFeatureYmm)) {
        for (uptr i = 0; i < 16; i++) {
          regs_[kXMM0 + 4 * i + 2].val = ext.ymmh[2 * i];
          regs_[kXMM0 + 4 * i + 3].val = ext.ymmh[2 * i + 1];
        }
      }
      if (features_ & kFeatureAVX512) {
        if (ext.xfeatures & kXFeatureOpmask) {
          const auto* opmask = reinterpret_cast<u64*>(
              reinterpret_cast<char*>(mctx.fpregs) + xsave_opmask_offset);
          MSAN_UNPOISON_MEMORY_REGION(opmask, 8 * sizeof(uptr));
          for (uptr i = 0; i < 8; i++)
            regs_[kK0 + i].val = opmask[i];
        }
        if (ext.xfeatures & kXFeatureZmm) {
          SAN_UNUSED const auto* zmmhi = reinterpret_cast<u64*>(
              reinterpret_cast<char*>(mctx.fpregs) + xsave_zmm_hi256_offset);
          // TODO(dvyukov): copy to context and MSAN_UNPOISON_MEMORY_REGION.
        }
        if (ext.xfeatures & kXFeatureZmm16) {
          const auto* hi16_zmm = reinterpret_cast<u64*>(
              reinterpret_cast<char*>(mctx.fpregs) + xsave_hi16_zmm_offset);
          MSAN_UNPOISON_MEMORY_REGION(hi16_zmm, 16 * 8 * sizeof(uptr));
          for (uptr i = 0; i < 16; i++) {
            for (uptr j = 0; j < kVectorRegWords; j++)
              regs_[kXMM0 + (i + 16) * kVectorRegWords + j].val =
                  hi16_zmm[i * 8 + j];
          }
        }
      }
    }
  }
  GetFSAndGS(regs_[kFS].val, regs_[kGS].val);
  // Reset RF since it's set as the result of hitting a breakpoint.
  regs_[kFLAGS].val &= ~X86_EFLAGS_RF;
}

void CPUContext::ToUContextEnable() {
  // The XSAVE area of mcontext_t may or may not contain particular portions
  // of data based on their use by the current thread. For example, kernel won't
  // save ZMM registers if the thread never used them.
  // As the result if we got mcontext_t w/o, say, ZMM registers in a signal
  // handler, but then we want to shove ZMM registers into it in ToUContext,
  // there is no way to do this (kernel did not even allocate space for ZMM
  // registers).
  // To resolve this, we trigger use of all required features below so that
  // kernel will save them in mcontext_t and we can update them in ToUContext.
  if (avx_enabled)
    // This should enable kXFeatureYmm.
    asm volatile("vbroadcastsd (%rsp), %ymm0");
  if (features_ & kFeatureAVX512) {
    // This should enable kXFeatureZmm.
    asm volatile("vpbroadcastq %rsp, %zmm0");
    // This should enable kXFeatureZmm16.
    asm volatile("vpbroadcastq %rsp, %zmm16");
    // This should enable kXFeatureOpmask.
    asm volatile("kmovq %rsp, %k7");
  }
}

void CPUContext::ToUContext(ucontext_t& uctx) const {
  auto& mctx = uctx.uc_mcontext;
  for (auto map : kRegMap)
    mctx.gregs[map[1]] = regs_[map[0]].val;
  SAN_CHECK(mctx.fpregs);
  for (uptr i = 0; i < 16; i++) {
    reinterpret_cast<uptr*>(mctx.fpregs->_xmm)[2 * i] =
        regs_[kXMM0 + 4 * i].val;
    reinterpret_cast<uptr*>(mctx.fpregs->_xmm)[2 * i + 1] =
        regs_[kXMM0 + 4 * i + 1].val;
  }
  SAN_CHECK_EQ(ext_fpstate_field(mctx)[12], FP_XSTATE_MAGIC1);
  auto& ext = *reinterpret_cast<extended_fpstate*>(mctx.fpregs + 1);
  if (avx_enabled) {
    // Should be enabled by ToUContextEnable.
    SAN_CHECK(ext.xfeatures & kXFeatureYmm);
    for (uptr i = 0; i < 16; i++) {
      ext.ymmh[2 * i] = regs_[kXMM0 + 4 * i + 2].val;
      ext.ymmh[2 * i + 1] = regs_[kXMM0 + 4 * i + 3].val;
    }
  }
  if (features_ & kFeatureAVX512) {
    // Should be enabled by ToUContextEnable.
    SAN_CHECK(ext.xfeatures & kXFeatureOpmask);
    SAN_CHECK(ext.xfeatures & kXFeatureZmm);
    SAN_CHECK(ext.xfeatures & kXFeatureZmm16);
    auto* opmask = reinterpret_cast<u64*>(reinterpret_cast<char*>(mctx.fpregs) +
                                          xsave_opmask_offset);
    for (uptr i = 0; i < 8; i++)
      opmask[i] = regs_[kK0 + i].val;
    auto* hi16_zmm = reinterpret_cast<u64*>(
        reinterpret_cast<char*>(mctx.fpregs) + xsave_hi16_zmm_offset);
    for (uptr i = 0; i < 16; i++) {
      for (uptr j = 0; j < kVectorRegWords; j++)
        hi16_zmm[i * 8 + j] = regs_[kXMM0 + (i + 16) * kVectorRegWords + j].val;
    }
  }
}

void CPUContext::InitUnemulated(const CPUContext& real) {
  // Copy all unknown flags from real (we don't understand/emulate them).
  regs_[kFLAGS].val &= kAllFlags;
  regs_[kFLAGS].val |= real.regs_[kFLAGS].val & ~kAllFlags;
  // Copy FS/GS because we don't restore them before executing an instruction
  // for real, but we get non-0 values back from the real context.
  for (auto reg : (RegIdx[]){kFS, kGS}) {
    SAN_CHECK_EQ(regs_[reg].val, 0);
    regs_[reg] = real.regs_[reg];
  }
}

void CPUContext::SetupCallArch(uptr return_to) {
  auto& sp = regs_[kSP].val;
  sp -= 8;
  *reinterpret_cast<uptr*>(sp) = return_to;
  // Setup TLS for MSan, libc calls, etc.
  GetFSAndGS(regs_[kFS].val, regs_[kGS].val);
}

uptr CPUContext::ReturnPC() const {
  uptr res = 0;
  NonFailingLoad(Addr(regs_[kSP].val), Sizeof(res), &res);
  return res;
}

LogBuf DumpBytesImpl(uptr addr, uptr size) {
  LogBuf buf;
  for (uptr i = 0; i < min(size, kMaxInstrLen); i++)
    buf.Append("%s%02x", buf.Empty() ? "" : " ",
               reinterpret_cast<u8*>(addr)[i]);
  return buf;
}

void CPUContext::UpdateRegister(RegIdx reg, uptr val) {
  SAN_CHECK(uctx_);
  for (auto map : kRegMap) {
    if (reg != map[0])
      continue;
    uctx_->uc_mcontext.gregs[map[1]] = val;
    regs_[reg].val = val;
    return;
  }
  SAN_BUG("unsupported register %s", RegNames[reg]);
}

const char RegNames[kRegCount][kRegNameMaxLen] = {
    [kPC] = "RIP",
    [kSP] = "RSP",
    [kFLAGS] = "RFLAGS",

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

    [kRBP] = "RBP",
    [kRAX] = "RAX",
    [kRBX] = "RBX",
    [kRCX] = "RCX",
    [kRDX] = "RDX",
    [kRDI] = "RDI",
    [kRSI] = "RSI",
    [kR8] = "R8",
    [kR9] = "R9",
    [kR10] = "R10",
    [kR11] = "R11",
    [kR12] = "R12",
    [kR13] = "R13",
    [kR14] = "R14",
    [kR15] = "R15",
    [kFS] = "FS",
    [kGS] = "GS",

    // Generated with https://go.dev/play/p/1uMnYbKI1c8
    [kXMM0 + 0] = "XMM0L",
    [kXMM0 + 1] = "XMM0H",
    [kXMM0 + 2] = "YMM0L",
    [kXMM0 + 3] = "YMM0H",
    [kXMM0 + 4] = "XMM1L",
    [kXMM0 + 5] = "XMM1H",
    [kXMM0 + 6] = "YMM1L",
    [kXMM0 + 7] = "YMM1H",
    [kXMM0 + 8] = "XMM2L",
    [kXMM0 + 9] = "XMM2H",
    [kXMM0 + 10] = "YMM2L",
    [kXMM0 + 11] = "YMM2H",
    [kXMM0 + 12] = "XMM3L",
    [kXMM0 + 13] = "XMM3H",
    [kXMM0 + 14] = "YMM3L",
    [kXMM0 + 15] = "YMM3H",
    [kXMM0 + 16] = "XMM4L",
    [kXMM0 + 17] = "XMM4H",
    [kXMM0 + 18] = "YMM4L",
    [kXMM0 + 19] = "YMM4H",
    [kXMM0 + 20] = "XMM5L",
    [kXMM0 + 21] = "XMM5H",
    [kXMM0 + 22] = "YMM5L",
    [kXMM0 + 23] = "YMM5H",
    [kXMM0 + 24] = "XMM6L",
    [kXMM0 + 25] = "XMM6H",
    [kXMM0 + 26] = "YMM6L",
    [kXMM0 + 27] = "YMM6H",
    [kXMM0 + 28] = "XMM7L",
    [kXMM0 + 29] = "XMM7H",
    [kXMM0 + 30] = "YMM7L",
    [kXMM0 + 31] = "YMM7H",
    [kXMM0 + 32] = "XMM8L",
    [kXMM0 + 33] = "XMM8H",
    [kXMM0 + 34] = "YMM8L",
    [kXMM0 + 35] = "YMM8H",
    [kXMM0 + 36] = "XMM9L",
    [kXMM0 + 37] = "XMM9H",
    [kXMM0 + 38] = "YMM9L",
    [kXMM0 + 39] = "YMM9H",
    [kXMM0 + 40] = "XMM10L",
    [kXMM0 + 41] = "XMM10H",
    [kXMM0 + 42] = "YMM10L",
    [kXMM0 + 43] = "YMM10H",
    [kXMM0 + 44] = "XMM11L",
    [kXMM0 + 45] = "XMM11H",
    [kXMM0 + 46] = "YMM11L",
    [kXMM0 + 47] = "YMM11H",
    [kXMM0 + 48] = "XMM12L",
    [kXMM0 + 49] = "XMM12H",
    [kXMM0 + 50] = "YMM12L",
    [kXMM0 + 51] = "YMM12H",
    [kXMM0 + 52] = "XMM13L",
    [kXMM0 + 53] = "XMM13H",
    [kXMM0 + 54] = "YMM13L",
    [kXMM0 + 55] = "YMM13H",
    [kXMM0 + 56] = "XMM14L",
    [kXMM0 + 57] = "XMM14H",
    [kXMM0 + 58] = "YMM14L",
    [kXMM0 + 59] = "YMM14H",
    [kXMM0 + 60] = "XMM15L",
    [kXMM0 + 61] = "XMM15H",
    [kXMM0 + 62] = "YMM15L",
    [kXMM0 + 63] = "YMM15H",
    [kXMM0 + 64] = "XMM16L",
    [kXMM0 + 65] = "XMM16H",
    [kXMM0 + 66] = "YMM16L",
    [kXMM0 + 67] = "YMM16H",
    [kXMM0 + 68] = "XMM17L",
    [kXMM0 + 69] = "XMM17H",
    [kXMM0 + 70] = "YMM17L",
    [kXMM0 + 71] = "YMM17H",
    [kXMM0 + 72] = "XMM18L",
    [kXMM0 + 73] = "XMM18H",
    [kXMM0 + 74] = "YMM18L",
    [kXMM0 + 75] = "YMM18H",
    [kXMM0 + 76] = "XMM19L",
    [kXMM0 + 77] = "XMM19H",
    [kXMM0 + 78] = "YMM19L",
    [kXMM0 + 79] = "YMM19H",
    [kXMM0 + 80] = "XMM20L",
    [kXMM0 + 81] = "XMM20H",
    [kXMM0 + 82] = "YMM20L",
    [kXMM0 + 83] = "YMM20H",
    [kXMM0 + 84] = "XMM21L",
    [kXMM0 + 85] = "XMM21H",
    [kXMM0 + 86] = "YMM21L",
    [kXMM0 + 87] = "YMM21H",
    [kXMM0 + 88] = "XMM22L",
    [kXMM0 + 89] = "XMM22H",
    [kXMM0 + 90] = "YMM22L",
    [kXMM0 + 91] = "YMM22H",
    [kXMM0 + 92] = "XMM23L",
    [kXMM0 + 93] = "XMM23H",
    [kXMM0 + 94] = "YMM23L",
    [kXMM0 + 95] = "YMM23H",
    [kXMM0 + 96] = "XMM24L",
    [kXMM0 + 97] = "XMM24H",
    [kXMM0 + 98] = "YMM24L",
    [kXMM0 + 99] = "YMM24H",
    [kXMM0 + 100] = "XMM25L",
    [kXMM0 + 101] = "XMM25H",
    [kXMM0 + 102] = "YMM25L",
    [kXMM0 + 103] = "YMM25H",
    [kXMM0 + 104] = "XMM26L",
    [kXMM0 + 105] = "XMM26H",
    [kXMM0 + 106] = "YMM26L",
    [kXMM0 + 107] = "YMM26H",
    [kXMM0 + 108] = "XMM27L",
    [kXMM0 + 109] = "XMM27H",
    [kXMM0 + 110] = "YMM27L",
    [kXMM0 + 111] = "YMM27H",
    [kXMM0 + 112] = "XMM28L",
    [kXMM0 + 113] = "XMM28H",
    [kXMM0 + 114] = "YMM28L",
    [kXMM0 + 115] = "YMM28H",
    [kXMM0 + 116] = "XMM29L",
    [kXMM0 + 117] = "XMM29H",
    [kXMM0 + 118] = "YMM29L",
    [kXMM0 + 119] = "YMM29H",
    [kXMM0 + 120] = "XMM30L",
    [kXMM0 + 121] = "XMM30H",
    [kXMM0 + 122] = "YMM30L",
    [kXMM0 + 123] = "YMM30H",
    [kXMM0 + 124] = "XMM31L",
    [kXMM0 + 125] = "XMM31H",
    [kXMM0 + 126] = "YMM31L",
    [kXMM0 + 127] = "YMM31H",

    [kK0] = "K0",
    [kK1] = "K1",
    [kK2] = "K2",
    [kK3] = "K3",
    [kK4] = "K4",
    [kK5] = "K5",
    [kK6] = "K6",
    [kK7] = "K7",
};

}  // namespace gwpsan
