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

#ifndef GWPSAN_CORE_BREAKPOINT_H_
#define GWPSAN_CORE_BREAKPOINT_H_

#include <errno.h>
#include <signal.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"

namespace gwpsan SAN_LOCAL {

class Breakpoint {
 public:
  // Types of memory accesses to break on.
  enum class Type {
    kCode,
    kWriteOnly,
    kReadWrite,
  };

  struct Info {
    Type type = Type::kCode;
    Addr addr;
    ByteSize size;

    bool operator==(const Info& other) const {
      return type == other.type && addr == other.addr && size == other.size;
    }
    bool operator!=(const Info& other) const {
      return !(*this == other);
    }
  };

  using Mode = u32;
  // Break on memory accesses in the current thread only.
  // Otherwise all new child threads will break as well.
  static constexpr Mode kModePerThread = 1 << 0;
  // Break on memory accesses in the kernel if supported.
  // This requires either perf_event_paranoid sysctl set to 0
  // (echo -n 0 | sudo tee /proc/sys/kernel/perf_event_paranoid),
  // or CAP_PERFMON or CAP_SYS_ADMIN, additionally LSMs can prohibit this.
  static constexpr Mode kModeEnableKernel = 1 << 1;
  // Require breaking on memory accesses in the kernel.
  static constexpr Mode kModeRequireKernel = 1 << 2;

  // Init breakpoint subsystem.
  // Must be called once before any breakpoints are initialized.
  static bool Init();
  // Says if the specified kModeRequire* modes are supported.
  static bool Supported(Breakpoint::Mode mode);

  Breakpoint();
  ~Breakpoint();

  // Init() is a delayed ctor and must be called before Enable(). If `force` is
  // true, will reinitialize even if already initialized.  Returns false if the
  // specified mode is not supported by the kernel.
  bool Init(Mode mode, bool force = false);

  // Returns true if initialized.
  bool Inited() const;

  // Close is an optional early dtor.
  void Close();

  // For Code type use size = 0.
  [[nodiscard]] Result<bool> Enable(Info bpinfo);
  void Disable();
  bool Enabled() const;
  // Number of times the breakpoint was hit since last Enable.
  uptr HitCount() const;

  // MatchInfo captures signal info used to identify the breakpoint that
  // produced the signal.
  class MatchInfo {
   public:
    MatchInfo();
    MatchInfo& operator=(const MatchInfo& other);
    bool operator==(const MatchInfo& other) const;

    uptr addr() const {
      return addr_;
    }

    bool is_async() const {
      return is_async_;
    }

   private:
    int sig_;
    int code_;
    uptr addr_;
    unsigned long data_;
    bool is_async_;

    friend class Breakpoint;
    MatchInfo(int sig, int code, uptr addr, unsigned long data, bool is_async);
  };

  static MatchInfo ExtractMatchInfo(int sig, const siginfo_t& siginfo);

  // If the signal identified by `minfo` was triggered by this breakpoint,
  // returns true.
  // Note: in threaded mode it's possible that one thread re-enables
  // the breakpoint for a different address, but another thread concurrently
  // receives a signal for the old address.
  bool Match(const MatchInfo& minfo) const;

  const Info& bpinfo() const {
    return bpinfo_;
  }

 private:
  Mode mode_ = 0;
  Result<int> fd_{static_cast<uptr>(-EEXIST)};
  Info bpinfo_;
  uptr reuse_count_ = 0;
  mutable uptr hit_count_ = 0;

  uptr SignalContext() const;

  Breakpoint(const Breakpoint&) = delete;
  Breakpoint& operator=(const Breakpoint&) = delete;
};

}  // namespace gwpsan SAN_LOCAL

#endif
