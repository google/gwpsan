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

#include "gwpsan/core/env.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/meta.h"

namespace gwpsan {

Env::Env(Mode mode, Callback* cb)
    : mode_(mode)
    , cb_(cb) {}

Word Env::Load(Addr addr, ByteSize size) {
  Word val;
  if (!(mode_ & kModeZero) && (!cb_ || cb_->FilterAccess(addr, size))) {
    if (!NonFailingLoad(addr, size, &val.val))
      Exception();
  }
  if (cb_) {
    val = cb_->Load(addr, size, val.val);
    if (current_instruction_)
      val.meta.Chain(current_instruction_);
  }
  SAN_LOG("load%zu 0x%zx->0x%zx[%zx]", *size, *addr, val.val,
          val.meta.shadow());
  return val;
}

void Env::Store(Addr addr, ByteSize size, const Word& val) {
  SAN_LOG("store%zu 0x%zx<-0x%zx[%zx]", *size, *addr, val.val,
          val.meta.shadow());
  if (cb_)
    cb_->Store(addr, size, val);
  if (!(mode_ & kModeImmutable) && (!cb_ || cb_->FilterAccess(addr, size))) {
    if (!NonFailingStore(addr, size, &val.val))
      Exception();
  }
}

void Env::Syscall(uptr nr, Span<MemAccess> accesses) {
  if (cb_)
    cb_->Syscall(nr, accesses);
}

void Env::Exception() {
  SAN_WARN(exception_raised_);
  SAN_LOG("an exception is raised");
  exception_raised_ = true;
  if (cb_)
    cb_->Exception();
}

void Env::ReportUninit(const CPUContext& ctx, const OriginChain* origin,
                       RegIdx reg, uptr flags) {
  if (cb_)
    cb_->ReportUninit(ctx, origin, reg, flags);
}

}  // namespace gwpsan
