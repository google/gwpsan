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

#include "gwpsan/core/init.h"

#include "gwpsan/base/bazel.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/metric_collection.h"
#include "gwpsan/base/module_list.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/string.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/flags.h"

extern "C" SAN_WEAK_IMPORT void _cgo_panic();
extern "C" SAN_WEAK_IMPORT void ruby_init();
extern "C" SAN_WEAK_IMPORT void wasm_runtime_init();
extern "C" SAN_WEAK_IMPORT void __tsan_init();
extern "C" SAN_WEAK_IMPORT void gwpsan_user_opt_out();
extern "C" SAN_WEAK_IMPORT void gwpsan_early_log();

namespace gwpsan {
namespace {
bool inited;

bool IsSeccompEnabled() {
  MallocVector<char> buf;
  buf.resize(4 << 10);
  auto res = ReadFile("/proc/self/status", buf);
  if (!res) {
    SAN_LOG("read(/proc/self/status) failed (%d), assuming sandbox", res.err());
    return true;
  }
  constexpr char kSeccompLine[] = "Seccomp:\t";
  const char* seccomp = internal_strstr(buf.data(), kSeccompLine);
  return seccomp && seccomp[sizeof(kSeccompLine) - 1] != '0';
}

// Returns reason if the target we are linked into is incompatible with gwpsan.
const char* IsIncompatible() {
  // Check all static opt out conditional as early as possible
  // to have minimal effect when not enabled.
  if (gwpsan_user_opt_out)
    return "user opted out";

  // Go runtime overrides our signal handler and panics on any signal.
  // It may be possible to cooperate with the Go runtime but it's not
  // immediately obvious how. There are some mentions of forwarding,
  // ignores, the rules for cgo are different, and there are different way
  // to build Go/C programs (cgo or Go shared libraries are loaded into C).
  // Here are some details:
  // https://pkg.go.dev/os/signal
  // https://github.com/golang/go/blob/master/src/runtime/signal_unix.go
  //
  // For now we just detect that we are linked into a Go binary and refuse
  // to initialize to not fail all Go tests.
  // Note: use of the _cgo_panic symbol is mostly arbitrary.
  if (_cgo_panic)
    return "Go binary";

  // Ruby has own stack overflow check that fails under gwp-uar:
  // https://github.com/ruby/ruby/blob/671cfc20000db024f2aeaf602b1a77895c819abc/vm_core.h#L1788-L1795
  if (ruby_init)
    return "Ruby binary";

  // WASM does strange things with stack, see
  // STACK_OVERFLOW_CHECK_GUARD_PAGE_COUNT macro uses.
  if (wasm_runtime_init)
    return "WebAssembly Micro Runtime binary";

  // TSan runtime requires that all signals are routed through its runtime and
  // delays them until returning from the runtime, however, because we rely on
  // synchronous SIGTRAP, this does not work. Disabling TSan instrumentation for
  // all of GWPSan code doesn't work either, because we still rely on some
  // external dependencies (such as DynamoRIO), that are instrumented and would
  // then lead to false positive data race reports because TSan doesn't see
  // where we initialized some datastructures passed to external libraries.
  // Allow linking GWPSan, but just never enable with TSan enabled.
  if (__tsan_init)
    return "running under TSan";

  // A seccomp filter is likely to prohibit calls we need.
  // Notably we need perf_event_open for tsan and sched_get_priority_min
  // for uar (via pthread_getattr_np).
  if (IsSeccompEnabled())
    return "seccomp filter is enabled";

  return nullptr;
}

void LogMetric(const MetricRef& m) {
  auto sum = m.Sum();
  if (!sum)
    return;
  Printf("  %s: %lld\t# %s\n", m.name(), sum, m.desc());
  if (m.size() > 1) {
    for (uptr i = 0; i < m.size(); ++i) {
      if (m.value(i))
        Printf("    %s: %lld\n", m.name(i), m.value(i));
    }
  }
}

SAN_DESTRUCTOR void CoreDtor() {
  if (!inited) {
    // If never initialized, it may be unsafe to do anything else on
    // destruction. Stop here.
    return;
  }

  if (GetFlags().log_metrics) {
    Printf("gwpsan metrics:\n");
    CollectMetrics(LogMetric);
  }
  // Don't fail in test mode, or all our tests will fail.
  if (!GetFlags().test_mode && BazelReportedWarning()) {
    Printf("gwpsan found a bug in a subprocess, dying\n");
    Die();
  }
}

volatile bool unpaused = false;

extern "C" SAN_USED void gwpsan_unpause() {
  unpaused = true;
}

bool DoInitFlags() {
  if (!InitFlags()) {
    Printf("gwpsan: flags init failed\n");
    return false;
  }

  if (GetFlags().pause_on_start) {
    Printf(
        "gwpsan: pausing on start:\n\tgdb -p %d\n\tcall "
        "(void()())gwpsan_unpause()\n",
        GetPid());
    while (!unpaused)
      Sleep(Milliseconds(100));
  }
  return true;
}

bool InitImpl() {
  if (!InitModuleList() || !CPUContext::Init() || !ArchDecoder::Init() ||
      !Breakpoint::Init() || !BreakManager::Init() || !InitNonFailing()) {
    SAN_LOG("init failed");
    return false;
  }
  SAN_LOG("init done");
  inited = true;
  return true;
}

}  // namespace

bool Init() {
  SAN_CHECK(!inited);

  // Enable early logging if requested by user.
  log_enabled = !!gwpsan_early_log;

  if (const char* incompatible_reason = IsIncompatible()) {
    SAN_LOG("detected incompatible binary: %s", incompatible_reason);
    return false;
  }

  log_enabled = false;

  if (!DoInitFlags())
    return false;

  if (!GetFlags().sample_interval_usec && !GetFlags().dump) {
    SAN_LOG("not enabling due to disabled sampling");
    return false;
  }

  if (const char* filter = GetFlags().process_filter) {
    char process[256];
    ReadProcessName(process);
    if (!MatchStr(process, filter)) {
      SAN_LOG("not enabling due to process filter: %s", process);
      return false;
    }
  }

  return InitImpl();
}

bool ForceInit() {
  return DoInitFlags() && InitImpl();
}

}  // namespace gwpsan
