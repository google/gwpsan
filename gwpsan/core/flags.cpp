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

#include "gwpsan/core/flags.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/flags.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/breakmanager.h"

// InitFlags triggers the -Wframe-larger-than=512 warning in some build
// configurations. We could make the descs variable static, but that will
// consume additional memory for the whole program execution. Since this
// function is executed on the main thread outside of signal handlers
// we can safely ignore the warning.
#pragma clang diagnostic ignored "-Wframe-larger-than"

// Can be used by the tested program to provide default values for flags.
// Can be overridden with GWPSAN_OPTIONS env var.
extern "C" SAN_WEAK_EXPORT const char* gwpsan_default_flags() {
  return "";
}

namespace gwpsan {

// Can be overriden to specify what tools to enable. This is for gwpsan-internal
// usage only; users should override gwpsan_default_flags() or simply set
// GWPSAN_OPTIONS instead.
SAN_WEAK_IMPORT const char* DefaultFlags() {
  return "";
}

constinit Flags dont_use_flags{
    .log = log_enabled,
    .log_path = log_path,
    .pause_on_die = pause_on_die,
    .error_code = die_error_code,
    .abort_on_error = abort_on_die,
};

bool InitFlags() {
  Flags& flags = dont_use_flags;
  // clang-format off
  const FlagDesc descs[] = {
    {&log_enabled, "log",
      "Enable logging."},
    {&log_path, "log_path",
      "Write logs and reports to the specified file.PID instead of stderr."},
    {&flags.pause_on_start, "pause_on_start",
      "Pause on start to connect gdb."},
    {&pause_on_die, "pause_on_die",
      "Pause instead of dying to connect gdb."},
    {&flags.log_failures, "log_failures",
      "Print decoding errors and context mismatches during emulation."},
    {&flags.log_metrics, "log_metrics",
      "Print all metrics on program exit."},
    {&flags.halt_on_error, "halt_on_error",
      "All bugs detected are fatal and will cause _exit($error_code) call."},
    {&flags.error_code, "error_code",
      "Exit code to use with halt_on_error."},
    {&flags.abort_on_error, "abort_on_error",
      "All bugs detected are fatal and will cause abort() call."},
    {&flags.origin_stacks, "origin_stacks",
      "Capture and print stack traces for some origins."
      " Currently this mode is intended for debugging only."},
    {&flags.must_init, "must_init",
       "Abort if the tool initialization fails."
       " Useful for running tests and catching initialization failures."},
    {&flags.test_mode, "test_mode",
      "Don't require full breakpoint support (SIGTRAP, kernel traps)."
      " Intended for testing, can lead to false positives and crashes."},
    {&flags.process_filter, "process_filter",
      "Only check processes that match a pattern in the binary name."
      " Metacharacters ^ and $ match the beginning or end;"
      " multiple patterns can be separated by |."},
    {&flags.tsan, "tsan",
      "Enable data-race detection."},
    {&flags.tsan_report_atomic_races, "tsan_report_atomic_races",
      "Detect data races between atomic and non-atomic accesses."},
    {&flags.tsan_delay_usec, "tsan_delay_usec",
      "Stall thread delay in microseconds."},
    {&flags.tsan_skip_watch, "tsan_skip_watch",
      "Number of memory accesses to skip before another watchpoint is set up."},
    {&flags.uar, "uar",
      "Enable use-after-return detection."},
    {&flags.uar_check_every_nth_thread, "uar_check_every_nth_thread",
      "Check every n-th thread."},
    {&flags.lmsan, "lmsan",
      "Enable light-weight uninitialized value detection."},
    {&flags.sample_interval_usec, "sample_interval_usec",
      "Sample interval in microseconds."},
    {&flags.sample_after_fork, "sample_after_fork",
      "Continue sampling after a fork() call."},
    {&flags.peek_instructions, "peek_instructions",
      "Number of instructions prefetched to find an analyzable interesting"
      " instruction on each timer sample."},
    {&flags.check_mem_funcs, "check_mem_funcs",
      "Check arguments of mem/str* functions."},
    {&flags.check_syscalls, "check_syscalls",
      "Check arguments of known system calls."},
    {&flags.check_malloc, "check_malloc",
      "Analyze malloc calls."},
    {&flags.dump, "dump",
      "=metadata: dump sanitizer metadata in the binary and exit.\n"
      "=instructions: decode all instructions in the binary and dump"
      " information about them."},
  };
  // clang-format on
  char buf[400];  // should be enough for everyone
  internal_strncpy(buf, DefaultFlags(), sizeof(buf));
  SAN_CHECK(ParseFlagsFromStr(buf, descs));
  internal_strncpy(buf, gwpsan_default_flags(), sizeof(buf));
  SAN_CHECK(ParseFlagsFromStr(buf, descs));
  if (!ParseFlagsFromEnv("GWPSAN_OPTIONS", descs))
    return false;
  flags.log |= flags.log_path != nullptr;
  flags.halt_on_error |= flags.abort_on_error;
  return true;
}

SAN_USED ScopedTestFlagMutator::ScopedTestFlagMutator()
    : original_(GetFlags()) {}

SAN_USED ScopedTestFlagMutator::~ScopedTestFlagMutator() {
  if (dont_use_flags.sample_interval_usec != original_.sample_interval_usec) {
    // CHECK ok: ScopedTestFlagMutator should only be used in tests.
    SAN_CHECK(BreakManager::singleton()->Sample(
        Microseconds(original_.sample_interval_usec)));
  }
  // Have to memcpy because it contains references,
  // which also means we don't save/restore values of reference flags.
  // Will need to do something else if we ever need to change reference flags.
  internal_memcpy(&dont_use_flags, &original_, sizeof(dont_use_flags));
}

SAN_USED Flags* ScopedTestFlagMutator::operator->() {
  return &dont_use_flags;
}

SAN_USED void ScopedTestFlagMutator::SetSampleInterval(Duration v) {
  dont_use_flags.sample_interval_usec = Micros(v);
  SAN_CHECK(BreakManager::singleton()->Sample(v));
}

}  // namespace gwpsan
