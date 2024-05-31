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

#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/report.h"
#include "gwpsan/core/semantic_metadata.h"
#include "gwpsan/unified/tool.h"

namespace gwpsan SAN_LOCAL {
namespace {

DEFINE_METRIC(lmsan_init_ok, 0, "Initialization succeeded");
DEFINE_METRIC(lmsan_init_fail, 0, "Initialization failed");
DEFINE_METRIC(lmsan_stack_spray, 0, "Number of sprayed stack frames");
DEFINE_METRIC(lmsan_heap_spray, 0, "Number of sprayed heap blocks");
DEFINE_METRIC(lmsan_detected, 0, "Detected uses of uninit values");

// The tool detects uses of uninit values by spraying stack frames and uninit
// heap blocks with a special 8-byte pattern and then checking presence of
// this pattern in value uses.
//
// TODO(dvyukov): currently we use a constant pattern, but ideally we use
// a dynamic pattern that encodes function and offset within the frame.
//
// TODO(dvyukov): we need compiler metainfo for reliable stack spraying.
// We need to know what functions is safe/makes sense to spray and also
// size of the stack frame. The pass also not mark functions for checking
// if -ftrivial-auto-var-init is used, or all vars are init in the source code.
//
// TODO(dvyukov): we could also check if the pattern is used in comparison
// operations and report or taint the result.
//
// TODO(dvyukov): potentially we could make malloc itself spray heap blocks,
// it should be simpler and more reliable. However, pattern checking may be
// more complex for dynamic patterns (the dynamic pattern will probably need
// some const prefix that we can check in the tool).
struct LightMemorySanitizer final : public Tool {
  LightMemorySanitizer(bool& ok)
      : Tool("lmsan") {}

  // The magic pattern we use for spraying/checking.
  using Granule = u64;
  static constexpr Granule kMagic = 0xe2df3a8821323db3;

  void OnMalloc(const CPUContext& ctx, uptr ptr, uptr size,
                bool uninit) override {
    if (!uninit)
      return;
    metric_lmsan_heap_spray.LossyAdd(1);
    Spray(ptr, size);
  }

  bool IsInteresting(const CPUContext& ctx) override {
    return IsSuitableFunctionStart(ctx);
  }

  bool Check(CPUContext& ctx) override {
    if (!IsSuitableFunctionStart(ctx))
      return false;
    metric_lmsan_stack_spray.LossyAdd(1);
    // If we want to spray dynamic origins that describe the function
    // and offsets within the stack frame, then we need to know precise
    // frame size in order to not spray the frame of the next called function.
    constexpr uptr kSize = 256;
    uptr sp = ctx.reg(kSP).val;
    uptr size = min<uptr>(kSize, sp - RoundDownTo(sp - 1, kPageSize));
    Spray(sp - size, size);
    return false;
  }

  bool IsInteresting(const CPUContext& ctx, const MemAccess& access) override {
    return Verify(access);
  }

  bool Check(const CPUContext& ctx, const MemAccess& access) override {
    if (!Verify(access))
      return false;
    ReportPrinter printer("use-of-uninit", metric_lmsan_detected, ctx.uctx());
    printer.CurrentStack();
    return true;
  }

  void Spray(uptr ptr, uptr size) {
    if (SAN_WARN(!IsAligned(ptr, sizeof(Granule)), "ptr=0x%zx size=%zu", ptr,
                 size))
      return;
    SAN_LOG("spraying [0x%zx-0x%zx) (%zu)", ptr, ptr + size, size);
    for (uptr i = 0; i < size / sizeof(Granule); i++)
      reinterpret_cast<Granule*>(ptr)[i] = kMagic;
  }

  bool IsSuitableFunctionStart(const CPUContext& ctx) {
    uptr pc = ctx.reg(kPC).val;
    if (!IsFunctionStart(pc))
      return false;
    // Additionally check the standard function prologue:
    //   55          push   %rbp
    //   48 89 e5    mov    %rsp,%rbp
    // Otherwise it's theoretically possible that the function jumps back
    // to the first instruction after initializing some stack variables,
    // but we will spray them again.
    int code = 0;
    NonFailingLoad(Addr(pc), Sizeof(code), &code);
    return !GWPSAN_X64 || code == 0xe5894855;
  }

  // Verifies that the accessed range does not contain our kMagic.
  bool Verify(const MemAccess& access) {
    // Ignore memory accesses that are not "use", e.g. plain copies.
    // We only check accesses that are known to be a "use",
    // e.g. memory passed to syscalls and to functions like memcmp.
    if (!access.is_use) {
      SAN_LOG("access not a use");
      return false;
    }
    SAN_LOG("checking for magic bytes");
    uptr pos = Bytes(access.addr);
    const uptr end = Bytes(access.addr + access.size);
    while (pos < end) {
      constexpr uptr kBufSize = 64;
      char buf[kBufSize];
      const uptr n = min(kBufSize, end - pos);
      if (n < sizeof(Granule))
        break;
      if (!NonFailingLoad(Addr(pos), ByteSize(n), buf))
        break;
      for (uptr i = 0; i + sizeof(Granule) <= n;) {
        void* p = internal_memchr(&buf[i], static_cast<u8>(kMagic),
                                  n - i - sizeof(Granule) + 1);
        if (!p)
          break;
        if (*reinterpret_cast<Granule*>(p) == kMagic)
          return true;
        i = static_cast<char*>(p) - buf + 1;
      }
      pos += n;
    }
    return false;
  }
};

}  // namespace

constinit const ToolDesc kLmsanTool = {
    .name = "lmsan",
    .enabled = &Flags::lmsan,
    .init_ok = metric_lmsan_init_ok,
    .init_fail = metric_lmsan_init_fail,
    // Currently we piggy-back on UAR metadata to detect first instruction
    // of a function for stack spraying. Ideally we use own metadata.
    .semantic_flags = kSemanticUAR,
    .make_unique = TryMakeUniqueGlobal<LightMemorySanitizer, Tool>,
};

}  // namespace gwpsan SAN_LOCAL
