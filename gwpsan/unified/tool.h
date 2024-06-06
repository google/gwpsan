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

#ifndef GWPSAN_UNIFIED_TOOL_H_
#define GWPSAN_UNIFIED_TOOL_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/semantic_metadata.h"

namespace gwpsan SAN_LOCAL {

// Tool interface for the UnifiedTool.
class Tool {
 public:
  // IsInteresting says if the given context or memory access is interesting
  // for the tool. The tool must not yet do any actual checking in this method.
  // If the tool says yes, a matching Check call is expected to follow.
  virtual bool IsInteresting(const CPUContext& ctx) {
    return false;
  }
  virtual bool IsInteresting(const CPUContext& ctx, const MemAccess& access) {
    return false;
  }

  // Check does actual checking of the context or memory access.
  // The tool must return true if it did any expensive checking or
  // unlocked the break manager mutex.
  // The tool may change the context and the underlying ucontext_t
  // for checking purposes, then execution will resume with the changed context.
  virtual bool Check(CPUContext& ctx) {
    return false;
  }
  virtual bool Check(const CPUContext& ctx, const MemAccess& access) {
    return false;
  }

  virtual void OnMalloc(const CPUContext& ctx, uptr ptr, uptr size,
                        bool uninit) {}

  virtual void OnThreadExit() {}

  virtual ~Tool() = default;

  const char* const name;

 protected:
  Tool(const char* name)
      : name(name) {}

  BreakManager& mgr() {
    return BreakManager::singleton().value();
  }

  Tool(const Tool&) = delete;
  Tool& operator=(const Tool&) = delete;
};

// Meta information about a tool.
struct ToolDesc {
  const char* name;
  bool Flags::*enabled;
  MetricRef& init_ok;
  MetricRef& init_fail;
  SemanticFlags semantic_flags;
  BreakManager::Config config;
  UniquePtr<Tool> (*make_unique)();

  bool Enabled() const {
    return GetFlags().*enabled;
  }
};

extern const ToolDesc kTsanTool;
extern const ToolDesc kUarTool;
extern const ToolDesc kLmsanTool;

inline constexpr const ToolDesc* kAllTools[] = {&kTsanTool, &kUarTool,
                                                &kLmsanTool};
inline constexpr uptr kToolCount = SAN_ARRAY_SIZE(kAllTools);

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_UNIFIED_TOOL_H_
