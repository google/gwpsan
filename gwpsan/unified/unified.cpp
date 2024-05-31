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

#include "gwpsan/unified/unified.h"

#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/env.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/known_functions.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/semantic_metadata.h"
#include "gwpsan/core/store_buffer.h"
#include "gwpsan/unified/tool.h"

namespace gwpsan {

DEFINE_METRIC(gwpsan_tools, 0, "Number of tools enabled");
DEFINE_METRIC(gwpsan_init_ok, 0, "Initialization succeeded");
DEFINE_METRIC(gwpsan_init_fail, 0, "Initialization failed");
DEFINE_METRIC_ARRAY(ArchDecoder::kMaxOpcodes, decoding_failures,
                    "Number of times an instruction wasn't decoded",
                    ArchDecoder::OpcodeName);
DEFINE_METRIC(insns_checked, 0, "Instructions checked");
DEFINE_METRIC(insns_non_emulatable, 0, "Non-emulatable instructions checked");
DEFINE_METRIC(emulation_looped, 0, "Emulation stopped due to a loop");

namespace {

class EnvCallback final : public Env::Callback {
 public:
  using AccessArray = ArrayVector<MemAccess, 8>;
  AccessArray& accesses() {
    return accesses_;
  }

  void Reset(uptr pc) {
    pc_ = pc;
    accesses_.reset();
  }

  bool IsNonEmulatable() const {
    return non_emulatable_;
  }

 private:
  uptr pc_ = 0;
  bool non_emulatable_ = false;
  ArrayVector<MemAccess, 8> accesses_;  // current instruction accesses
  StoreBuffer buffer_;

  Word Load(Addr addr, ByteSize size, uptr val) override {
    val = buffer_.Forward(addr, size, val);
    if (accesses_.size() < accesses_.capacity())
      accesses_.emplace_back(MemAccess{.pc = pc_,
                                       .addr = addr,
                                       .size = size,
                                       .val = {val},
                                       .is_read = true});
    return {val};
  }

  void Store(Addr addr, ByteSize size, const Word& val) override {
    buffer_.Store(addr, size, val.val);
    if (accesses_.size() < accesses_.capacity())
      accesses_.emplace_back(MemAccess{
          .pc = pc_, .addr = addr, .size = size, .val = val, .is_write = true});
  }

  void Syscall(uptr nr, Span<MemAccess> accesses) override {
    non_emulatable_ = true;
    for (const auto& access : accesses) {
      if (accesses_.size() < accesses_.capacity())
        accesses_.emplace_back(access);
    }
  }

  void Exception() override {
    non_emulatable_ = true;
  }
};

bool Execute(Env& env, CPUContext& ctx) {
  const uptr pc = ctx.reg(kPC).val;
  // Need to safely copy code because our emulation may mispredict
  // and then we will try to execute a random address, or JITed code may be
  // mprotected concurrently for modifications.
  char code_copy[2 * kMaxInstrLen] = {};
  uptr pc_copy = reinterpret_cast<uptr>(code_copy);
  NonFailingLoad(Addr(pc), ByteSize(kMaxInstrLen), code_copy);
  auto dec = MakeUniqueGlobal<ArchDecoder>(pc, pc_copy);
  if (!dec->Decode()) {
    metric_decoding_failures.LossyAdd(dec->GetOpcode(), 1);
    // As above, don't pass the real PC to be read and instead use the copy.
    SAN_LOG_IF(GetFlags().log_failures, "decoding failed: %s\n%s",
               &DumpInstr(pc, pc_copy, kDumpAll), dec->failed());
    return false;
  }
  ctx.Execute(env, *dec);
  return true;
}

struct ToolScope {
  ToolScope(Tool*& current, UniquePtr<Tool>& tool)
      : current(current)
      , tool(tool.get()) {
    SAN_CHECK(!current || current == tool.get());
    prev = current;
    current = tool.get();
  }
  ~ToolScope() {
    current = prev;
  }
  Tool*& current;
  Tool* tool;
  Tool* prev;
};
}  // namespace

UnifiedTool::UnifiedTool(bool& ok) {
  SemanticFlags needed = 0;
  for (auto* desc : kAllTools)
    needed |= desc->Enabled() ? desc->semantic_flags : 0;
  if (!InitSemanticMetadata(needed)) {
    ok = false;
    metric_gwpsan_init_fail.ExclusiveAdd(1);
    return;
  }

  u64 failed_tools = 0;
  ArrayVector<UniquePtr<Tool>, kToolCount> tools;
  for (auto* desc : kAllTools) {
    if (!desc->Enabled())
      continue;
    if (!HasSemanticMetadata(desc->semantic_flags)) {
      SAN_LOG("failed to initialize %s: no metadata", desc->name);
      desc->init_fail.ExclusiveAdd(0, 1);
      failed_tools++;
      continue;
    }
    auto tool = desc->make_unique();
    if (!tool) {
      SAN_LOG("failed to initialize %s", desc->name);
      desc->init_fail.ExclusiveAdd(0, 1);
      failed_tools++;
      continue;
    }
    SAN_LOG("initialized %s", desc->name);
    desc->init_ok.ExclusiveAdd(0, 1);
    tools_.emplace_back(move(tool));
  }

  if (failed_tools) {
    // If must_init=true, there can be no failed tools ...
    SAN_CHECK(!GetFlags().must_init);
    // ... otherwise, if at least one of the requested tools has been enabled,
    // continue and start sampling.
    if (tools_.empty()) {
      ok = false;
      metric_gwpsan_init_fail.ExclusiveAdd(1);
      return;
    }
  }

  // At least one requested tool has been enabled, start sampling.  We'll also
  // start sampling if no tool has been requested (to test only timers firing).
  if (!mgr()->Sample(Microseconds(GetFlags().sample_interval_usec))) {
    ok = false;
    metric_gwpsan_init_fail.ExclusiveAdd(1);
    return;
  }

  metric_gwpsan_init_ok.ExclusiveAdd(1);
  metric_gwpsan_tools.Set(tools_.size());
}

UnifiedTool::~UnifiedTool() {
  BeginDestructor();
}

void UnifiedTool::EndFork(int pid) {
  if (!pid) {
    // POSIX timers are not inherited on fork(). Restart sampling.
    SAN_WARN(!mgr()->Sample(Microseconds(GetFlags().sample_interval_usec)));
  }
}

BreakManager::Config UnifiedTool::GetBreakManagerConfig() {
  BreakManager::Config cfg = {};
  for (auto* desc : kAllTools) {
    if (!desc->Enabled())
      continue;
    cfg.mode |= desc->config.mode;
    cfg.max_breakpoints =
        max(cfg.max_breakpoints, desc->config.max_breakpoints);
  }
  return cfg;
}

bool UnifiedTool::OnTimer() {
  if (current_tool_)
    return false;
  resume_thread_ = kNoThread;
  peek_instructions_ = GetFlags().peek_instructions;
  return true;
}

bool UnifiedTool::OnBreak(const Breakpoint::Info& bpinfo, uptr hit_count) {
  resume_thread_ = kNoThread;
  return current_tool_;
}

uptr UnifiedTool::OnEmulate(const CPUContext& ctx) {
  // Since we don't enable uninit tracking, there should be no heap allocations.
  // If we later need uninit tracking, we can create a HeapAllocatorLifetime
  // here (we don't persist anything beyond this function).
  NoHeapAllocationsScope no_allocations;
  // These are too large for stack.
  // Note: in some cases we may recurse into this function (tsan)
  // and re-initialize and re-use these objects. This is safe because tools
  // return true from the Check callback whenever they unlock the break manager
  // mutex and allow recursion. In such case we return from the outer function
  // without using these static objects again. This is additionally enforced
  // using emulate_seq_ variable.
  static constinit OptionalBase<EnvCallback> cb;
  static constinit OptionalBase<CPUContext> emulated_ctx;
  cb.emplace();
  emulated_ctx.emplace(ctx);
  const uptr emulate_seq = ++emulate_seq_;
  Env env(Env::kModeImmutable, &*cb);
  Tool* throttled = tools_.size() > 1 ? throttled_tool_ : nullptr;
  throttled_tool_ = nullptr;
  auto filter = [this, throttled](UniquePtr<Tool>& tool) -> bool {
    return (current_tool_ && tool.get() != current_tool_) ||
           tool.get() == throttled;
  };
  const uptr start_pc = ctx.reg(kPC).val;
  if (resume_pc_ == start_pc && resume_thread_ == CurrentThread()) {
    if (malloc_size_) {
      // We resumed on return from a malloc.
      // Now we have both requested size and return value.
      uptr ptr = ctx.reg(kResultReg).val;
      SAN_LOG("intercepted malloc(%zu)=0x%zx uninit=%d", malloc_size_, ptr,
              malloc_uninit_);
      for (auto& tool : tools_)
        tool->OnMalloc(ctx, ptr, malloc_size_, malloc_uninit_);
    }
  }
  resume_pc_ = 0;
  resume_thread_ = kNoThread;
  malloc_size_ = 0;
  for (; peek_instructions_; peek_instructions_--) {
    if (SAN_WARN(emulate_seq != emulate_seq_))
      return 0;
    metric_insns_checked.LossyAdd(1);
    const uptr current_pc = emulated_ctx->reg(kPC).val;
    cb->Reset(current_pc);
    if (GetFlags().check_mem_funcs &&
        IsMemAccessFunc(*emulated_ctx, cb->accesses()))
      resume_pc_ = emulated_ctx->ReturnPC();
    uptr malloc_size = 0;
    bool malloc_uninit = false;
    if (GetFlags().check_malloc &&
        IsMallocPC(*emulated_ctx, malloc_size, malloc_uninit)) {
      // For malloc we need precise context at both malloc start and return
      // to intercept both size argument and return value. So first we request
      // stop at the function start, and then when we are at the function
      // start we request stop on return from the malloc.
      // Alternatively we could intercept only return reliably and then
      // use malloc_usable_size() to obtain the (rounded up) size.
      // It's unclear what is better. With malloc_usable_size() we would
      // get only rounded up size, not the actual size user asked for.
      resume_pc_ = current_pc;
      if (current_pc == start_pc) {
        resume_pc_ = emulated_ctx->ReturnPC();
        malloc_size_ = malloc_size;
        malloc_uninit_ = malloc_uninit;
      }
    }
    for (auto& tool : tools_) {
      if (filter(tool))
        continue;
      ToolScope scope(current_tool_, tool);
      if (tool->IsInteresting(*emulated_ctx)) {
        SAN_LOG("%s: instruction is interesting", tool->name);
        if (current_pc != start_pc)
          return current_pc;
        if (tool->Check(*emulated_ctx)) {
          throttled_tool_ = tool.get();
          return 0;
        }
      }
    }
    if (!Execute(env, *emulated_ctx))
      return 0;
    for (const auto& access : MergeAccesses(cb->accesses())) {
      SAN_LOG("checking %s", &access.ToString());
      for (auto& tool : tools_) {
        if (filter(tool))
          continue;
        ToolScope scope(current_tool_, tool);
        if (tool->IsInteresting(*emulated_ctx, access)) {
          SAN_LOG("%s: access is intersting", tool->name);
          if (current_pc != start_pc)
            return current_pc;
          if (tool->Check(ctx, access)) {
            throttled_tool_ = tool.get();
            return 0;
          }
        }
      }
    }
    // Stop emulation (1) if we reached an instruction we can't emulate
    // (e.g. a syscall); or (2) if we reached the start PC, because we won't
    // be able to request a breakpoint on an N-th iteration of the loop;
    // or (3) if we recursed (current_tool_ is set), in such case we check
    // only one instruction and return.
    if (cb->IsNonEmulatable()) {
      metric_insns_non_emulatable.LossyAdd(1);
      return 0;
    }
    if (emulated_ctx->reg(kPC).val == start_pc) {
      metric_emulation_looped.LossyAdd(1);
      return 0;
    }
    if (current_tool_)
      return 0;
    if (resume_pc_) {
      resume_thread_ = CurrentThread();
      return resume_pc_;
    }
  }
  return 0;
}

void UnifiedTool::OnThreadExit() {
  for (auto& tool : tools_)
    tool->OnThreadExit();
}

UnifiedTool::ThreadID UnifiedTool::CurrentThread() {
  // A cheaper than GetTid way to get thread id.
  static SAN_THREAD_LOCAL const bool id = false;
  return &id;
}

}  // namespace gwpsan
