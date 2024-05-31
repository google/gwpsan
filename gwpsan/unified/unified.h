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

#ifndef THIRD_PARTY_GWP_SANITIZERS_UNIFIED_UNIFIED_H_
#define THIRD_PARTY_GWP_SANITIZERS_UNIFIED_UNIFIED_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/unified/tool.h"

namespace gwpsan SAN_LOCAL {

// The top-level tool that dispatches callbacks to each individual tool.
class UnifiedTool final : protected BreakManager::Callback {
 public:
  UnifiedTool(bool& ok);
  ~UnifiedTool();

  // Reinitialize state after fork().
  void EndFork(int pid);

  // Return ideal break manager configuration based on the requested tools.
  static BreakManager::Config GetBreakManagerConfig();

 private:
  using ThreadID = const void*;
  static constexpr ThreadID kNoThread = nullptr;
  static ThreadID CurrentThread();

  bool OnTimer() override;
  bool OnBreak(const Breakpoint::Info& bpinfo, uptr hit_count) override;
  uptr OnEmulate(const CPUContext& ctx) override;
  void OnThreadExit() override;

  ArrayVector<UniquePtr<Tool>, kToolCount> tools_;
  // Needed for tools that unlock the break manager mutex and want to handle
  // nested events (tsan). Current tool is set for the outer event,
  // then if it's set we ignore timer events and direct all other events
  // (watchpoints) to this tool only.
  Tool* current_tool_ = nullptr;
  // Tool that has done expensive checking that aborts emulation last
  // (e.g. tsan stalls). This tool will be skipped during the next timer
  // sample to achieve some notion of fairness between tools.
  Tool* throttled_tool_ = nullptr;
  // Use to "resume" emulation after we returned non-0 PC from OnEmulate.
  // When we get the next OnEmulate we can check that we received it
  // on the expected thread/pc.
  uptr resume_pc_ = 0;
  ThreadID resume_thread_ = kNoThread;
  uptr peek_instructions_ = 0;
  uptr emulate_seq_ = 0;
  uptr malloc_size_ = 0;
  bool malloc_uninit_ = false;
};

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_UNIFIED_UNIFIED_H_
