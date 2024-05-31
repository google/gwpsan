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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_ENV_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_ENV_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/meta.h"

namespace gwpsan SAN_LOCAL {

// Env stubs memory subsystem (loads and stores).
class Env {
 public:
  using Mode = u32;
  // Don't do actual stores to memory.
  static constexpr Mode kModeImmutable = 1 << 0;
  // Don't load from memory and return zeros.
  static constexpr Mode kModeZero = 1 << 1;
  // Track uninitialized values and create origins in CPUContext.
  static constexpr Mode kUninitTracking = 1 << 2;

  class Callback {
   public:
    virtual Word Load(Addr addr, ByteSize size, uptr val) {
      return {val};
    }
    virtual void Store(Addr addr, ByteSize size, const Word& val) {}
    // If FilterAccess returns false, the real memory access won't be done
    // (loads return 0, stores are ignored).
    virtual bool FilterAccess(Addr addr, ByteSize size) {
      return true;
    }
    virtual void Syscall(uptr nr, Span<MemAccess> accesses) {}
    virtual void Exception() {}
    virtual void ReportUninit(const CPUContext& ctx, const OriginChain* origin,
                              RegIdx reg, uptr flags) {}

   protected:
    ~Callback() = default;
  };

  explicit Env(Mode mode, Callback* cb = nullptr);

  Word Load(Addr addr, ByteSize size);
  void Store(Addr addr, ByteSize size, const Word& val);
  void Syscall(uptr nr, Span<MemAccess> accesses);
  void Exception();

  // Called on use of uninitialized value.
  void ReportUninit(const CPUContext& ctx, const OriginChain* origin,
                    RegIdx reg, uptr flags);

  void set_current_instruction(Origin* origin) {
    // Start of a new instruction execution.
    current_instruction_ = origin;
    exception_raised_ = false;
  }

  bool exception_raised() const {
    return exception_raised_;
  }

  bool uninit_tracking() const {
    return mode_ & kUninitTracking;
  }

 private:
  const Mode mode_;
  Callback* const cb_;
  Origin* current_instruction_ = nullptr;
  bool exception_raised_ = false;

  Env(const Env&) = delete;
  Env& operator=(const Env&) = delete;
};

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_CORE_ENV_H_
