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

#include <string.h>

#include "absl/flags/flag.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/init.h"

// We need to define the flag so that the app flag parsing does not fail
// on the unknown flag. But we parse it manually, since we need it much earlier.
ABSL_FLAG(bool, gwpsan_arm_watchpoints, false,
          "Arm all watchpoints (but they will never fire)");

namespace gwpsan {
namespace {

// Poor man's command line parsing.
// For some targets command line is the only way to pass arguments.
void ParseCmdLine(bool& arm_watchpoints) {
  const uptr kBufSize = 64 << 20;
  char* buf = Mmap(kBufSize);
  SAN_CHECK(buf);
  auto res = ReadFile("/proc/self/cmdline", {buf, kBufSize});
  SAN_CHECK(!!res);
  SAN_CHECK_LT(res.val(), kBufSize - 1);
  const char* kArmWatchpoints = "-gwpsan_arm_watchpoints";
  if (memmem(buf, res.val(), kArmWatchpoints, strlen(kArmWatchpoints)))
    arm_watchpoints = true;
  Munmap(buf, kBufSize);
}

void ctor() {
  SAN_CHECK(Init());
  bool arm_watchpoints = false;
  ParseCmdLine(arm_watchpoints);
  auto& mgr = *BreakManager::singleton().try_emplace();
  if (arm_watchpoints) {
    static int watched[BreakManager::kMaxBreakpoints];
    for (auto& w : watched)
      SAN_CHECK(mgr.Watch({Breakpoint::Type::kReadWrite, &w, Sizeof(w)}));
  }
  SAN_LOG("breakmanager perf test: arm_watchpoints=%d", arm_watchpoints);
}

__attribute__((section(".preinit_array"), used)) void (*preinit)(void) = ctor;

}  // namespace
}  // namespace gwpsan
