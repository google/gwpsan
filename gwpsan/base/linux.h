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

// Helpers and definitions not yet found in Linux UAPI headers distributed with
// most Linux distributions. We should eventually be able to remove this header.

#ifndef GWPSAN_BASE_LINUX_H_
#define GWPSAN_BASE_LINUX_H_

#include <linux/perf_event.h>
#include <signal.h>
#include <unistd.h>

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

#ifndef TRAP_PERF
inline constexpr int TRAP_PERF = 6;
#endif
#ifndef TRAP_PERF_FLAG_ASYNC
inline constexpr u32 TRAP_PERF_FLAG_ASYNC = (1u << 0);
#endif
#ifndef PERF_EVENT_IOC_MODIFY_ATTRIBUTES
#define PERF_EVENT_IOC_MODIFY_ATTRIBUTES _IOW('$', 11, struct perf_event_attr*)
#endif
#ifndef PERF_ATTR_SIZE_VER7
inline constexpr uptr PERF_ATTR_SIZE_VER7 = 128;
#endif

union perf_event_attr_v7 {
 public:
  ::perf_event_attr attr;
  struct {
    char v7_padding[PERF_ATTR_SIZE_VER7 - sizeof(u64)];
    u64 sig_data;
  };

  // These bitfields may not be defined in older kernel headers.

  void set_inherit_thread() {
    bits() |= 0x0800000000;
  }
  void set_remove_on_exec() {
    bits() |= 0x1000000000;
  }
  void set_sigtrap() {
    bits() |= 0x2000000000;
  }

 private:
  u64& bits() {
    return *reinterpret_cast<u64*>(&attr.read_format + 1);
  }
};

// si_perf_* is not defined in older kernel headers.
struct SigInfoPerf {
  unsigned long data;
  u32 type;
  u32 flags;

  bool async() const {
    return flags & TRAP_PERF_FLAG_ASYNC;
  }
};

inline const SigInfoPerf& GetSigInfoPerf(const siginfo_t& siginfo) {
  return reinterpret_cast<const SigInfoPerf&>(siginfo.si_addr_lsb);
}

struct kernel_timespec {
  s64 tv_sec;
  long long tv_nsec;
};

struct linux_dirent64 {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_LINUX_H_
