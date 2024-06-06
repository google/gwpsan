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

#ifndef GWPSAN_CORE_FLAGS_H_
#define GWPSAN_CORE_FLAGS_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"

namespace gwpsan SAN_LOCAL {

struct Flags {
  bool help = false;
  bool& log;
  const char*& log_path;
  bool pause_on_start;
  bool& pause_on_die;
  bool log_failures = false;
  bool log_metrics = false;
  bool halt_on_error = false;
  int& error_code;
  bool& abort_on_error;
  bool origin_stacks = false;
  bool must_init = false;
  bool test_mode = false;
  const char* process_filter = nullptr;
  uptr heap_size_mb = 10;
  const char* dump = nullptr;
  // GWP-TSan
  bool tsan = false;
  bool tsan_report_atomic_races = false;
  uptr tsan_delay_usec = 100;
  uptr tsan_skip_watch = 3;
  // GWP-UAR
  bool uar = false;
  uptr uar_check_every_nth_thread = 1;
  // GWP-LMSan.
  bool lmsan = false;
  // Unified (GWPSan)
  uptr sample_interval_usec = 0;
  bool sample_after_fork = true;
  uptr peek_instructions = 20;
  bool check_mem_funcs = true;
  bool check_syscalls = true;
  bool check_malloc = false;
};

bool InitFlags();

SAN_ALWAYS_INLINE const Flags& GetFlags() {
  extern Flags dont_use_flags;
  return dont_use_flags;
}

// ScopedTestFlagMutator can be used in tests to temporary change flags as:
//
//  ScopedTestFlagMutator flags;
//  flags->tsan_report_atomic_races = false;
//  ... flags restores original values when goes out of scope
//
class ScopedTestFlagMutator {
 public:
  ScopedTestFlagMutator();
  ~ScopedTestFlagMutator();
  Flags* operator->();
  void SetSampleInterval(Duration v);

 private:
  const Flags original_;

  ScopedTestFlagMutator(const ScopedTestFlagMutator&) = delete;
  void operator=(const ScopedTestFlagMutator&) = delete;
};

}  // namespace gwpsan SAN_LOCAL

#endif
