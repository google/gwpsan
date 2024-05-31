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

#include "gwpsan/core/breakpoint.h"

#include <errno.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/linux.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/base/units.h"

namespace gwpsan {
namespace {
perf_event_attr_v7 AttrInit(uptr ctx, Breakpoint::Mode mode,
                            Breakpoint::Info bpinfo) {
  perf_event_attr_v7 mattr;
  internal_memset(&mattr, 0, sizeof(mattr));
  auto& attr = mattr.attr;
  attr.type = PERF_TYPE_BREAKPOINT;
  attr.sample_period = 1;
  attr.disabled = bpinfo.addr == 0;
  attr.inherit = !(mode & Breakpoint::kModePerThread);
  if (attr.inherit)
    mattr.set_inherit_thread();
  mattr.set_remove_on_exec();
  mattr.set_sigtrap();
  mattr.sig_data = ctx;
  attr.size = sizeof(mattr);
  attr.exclude_kernel = !(
      mode & (Breakpoint::kModeEnableKernel | Breakpoint::kModeRequireKernel));
  attr.exclude_hv = 1;
  // Breakpoints always have precise IP, so precise_ip>1 is not needed
  // (setting precise_ip=3 fails on some CPUs even for breakpoints).
  attr.precise_ip = 0;
  attr.watermark = 1;
  attr.wakeup_watermark = 1;
  attr.bp_addr = Bytes(bpinfo.addr);
  switch (bpinfo.type) {
  case Breakpoint::Type::kCode:
    attr.bp_type = HW_BREAKPOINT_X;
    // Kernel wants sizeof(uptr) for code breakpoints.
    bpinfo.size = Sizeof<uptr>();
    break;
  case Breakpoint::Type::kWriteOnly:
    attr.bp_type = HW_BREAKPOINT_W;
    break;
  case Breakpoint::Type::kReadWrite:
    attr.bp_type = HW_BREAKPOINT_RW;
    break;
  }
  const uptr size_bytes = Bytes(bpinfo.size);
  switch (size_bytes) {
  case 1:
    attr.bp_len = HW_BREAKPOINT_LEN_1;
    break;
  case 2:
    attr.bp_len = HW_BREAKPOINT_LEN_2;
    break;
  case 4:
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    break;
  case 8:
    attr.bp_len = HW_BREAKPOINT_LEN_8;
    break;
  default:
    SAN_WARN(1, "bad breakpoint size: %zu", size_bytes);
  }
  return mattr;
}

SAN_NOINLINE Result<int> PerfEventOpen(uptr ctx, Breakpoint::Mode mode) {
  Breakpoint::Info bpinfo = {Breakpoint::Type::kWriteOnly, 0, kPtrSize};
  auto attr = AttrInit(ctx, mode, bpinfo);
  auto res = sys_perf_event_open(&attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
  if (!res)
    SAN_LOG("perf_event_open for mode 0x%x failed: %d",
            static_cast<unsigned>(mode), res.err());
  return res;
}

bool inited;
// List of environment-supported modes.
Breakpoint::Mode supported_modes;
// List of all "require" modes.
constexpr Breakpoint::Mode kRequireModes = Breakpoint::kModeRequireKernel;
}  // namespace

bool Breakpoint::Init() {
  SAN_CHECK(!inited);
  auto fd = PerfEventOpen(0, 0);
  if (!fd)
    return false;
  inited = true;
  sys_close(fd.val());

  // Probe for monitoring kernel events.
  // TODO(dvyukov, elver): kernel breakpoints can be created on Arm64,
  // but they don't actually fire.
  if (!GWPSAN_ARM64) {
    fd = PerfEventOpen(0, kModeRequireKernel);
    if (!!fd) {
      sys_close(fd.val());
      supported_modes |= kModeRequireKernel;
    }
  }

  SAN_LOG("breakpoint support:%s",
          supported_modes & kModeRequireKernel ? " kernel" : "");
  return true;
}

bool Breakpoint::Supported(Breakpoint::Mode mode) {
  SAN_CHECK(inited);
  SAN_CHECK_EQ(mode & ~kRequireModes, 0);
  return (mode & supported_modes) == mode;
}

Breakpoint::Breakpoint() {}

Breakpoint::~Breakpoint() {
  Close();
}

bool Breakpoint::Init(Mode mode, bool force) {
  SAN_CHECK(inited);
  if (!force)
    SAN_CHECK(!Inited());
  Mode required = mode & kRequireModes;
  if ((required & supported_modes) != required)
    return false;
  if (mode & kModeRequireKernel)
    mode |= kModeEnableKernel;
  else if ((supported_modes & kModeRequireKernel) == 0)
    mode &= ~kModeEnableKernel;
  mode_ = mode;
  fd_ = PerfEventOpen(0, mode_);
  return !!fd_;
}

bool Breakpoint::Inited() const {
  return !!fd_;
}

void Breakpoint::Close() {
  if (!fd_)
    return;
  if (!sys_close(fd_.val()))
    SAN_BUG("breakpoint close failed");
  fd_ = Result<int>(-EEXIST);
}

Result<bool> Breakpoint::Enable(Info bpinfo) {
  SAN_CHECK(Inited());
  SAN_CHECK(bpinfo.type != Type::kCode || bpinfo.size == 0);
  SAN_WARN(!bpinfo.addr);
  // Note: order of writes and the syscall is importnat.
  // The syscall serves as a compiler fence, so that in the signal handler
  // we see the writes.
  bpinfo_ = bpinfo;
  reuse_count_++;
  hit_count_ = 0;
  auto attr = AttrInit(SignalContext(), mode_, bpinfo);
  // Note: this may fail w/o kernel commit 26c6ccdf5c06. It claims to cleanup
  // things, but actually enables modifying disabled attribute.
  auto res = sys_ioctl(fd_.val(), PERF_EVENT_IOC_MODIFY_ATTRIBUTES, &attr);
  if (!res) {
    Disable();
    return res.CastError<bool>();
  }
  return Result<bool>(true);
}

void Breakpoint::Disable() {
  if (!bpinfo_.addr)
    return;
  // Note: order of the syscall and writes is important.
  // The syscall serves as a compiler fence, so that in the signal handler
  // we don't see the writes.
  SAN_WARN_IF_ERR(sys_ioctl(fd_.val(), PERF_EVENT_IOC_DISABLE, 0));
  bpinfo_ = {};
}

bool Breakpoint::Enabled() const {
  return bpinfo_.addr != 0;
}

uptr Breakpoint::HitCount() const {
  return hit_count_;
}

Breakpoint::MatchInfo::MatchInfo()
    : sig_()
    , code_()
    , addr_()
    , data_()
    , is_async_() {}

Breakpoint::MatchInfo::MatchInfo(int sig, int code, uptr addr,
                                 unsigned long data, bool is_async)
    : sig_(sig)
    , code_(code)
    , addr_(addr)
    , data_(data)
    , is_async_(is_async) {}

Breakpoint::MatchInfo& Breakpoint::MatchInfo::operator=(
    const MatchInfo& other) {
  sig_ = other.sig_;
  code_ = other.code_;
  addr_ = other.addr_;
  data_ = other.data_;
  is_async_ = other.is_async_;
  return *this;
}

bool Breakpoint::MatchInfo::operator==(const MatchInfo& other) const {
  return sig_ == other.sig_ && code_ == other.code_ && addr_ == other.addr_ &&
         data_ == other.data_ && is_async_ == other.is_async_;
}

Breakpoint::MatchInfo Breakpoint::ExtractMatchInfo(int sig,
                                                   const siginfo_t& siginfo) {
  const auto& ctx = GetSigInfoPerf(siginfo);
  return MatchInfo(sig, siginfo.si_code,
                   reinterpret_cast<uptr>(siginfo.si_addr), ctx.data,
                   ctx.async());
}

bool Breakpoint::Match(const MatchInfo& minfo) const {
  if (!Inited() || !bpinfo_.addr)
    return false;
  if (minfo.sig_ != SIGTRAP || minfo.code_ != TRAP_PERF ||
      minfo.data_ != SignalContext())
    return false;
  hit_count_++;
  return true;
}

uptr Breakpoint::SignalContext() const {
  // A breakpoint may fire in another thread when it was already reused
  // for a different address. We also don't know the real access addr/type/size
  // (they are not in siginfo_t), we can only use what's stored in this object.
  // Gwpsan is generally tolerant to stray breakpoints, but this may cause
  // UnwindInstruction failures (since we will try to unwind using a wrong
  // access address) and some tests may fail.
  // To avoid this we also add the reuse count into the signal context,
  // which is passed back from the kernel.
  // Note: modyfying sig_data requires kernel commit 3c25fc97f5590
  // ("perf: Copy perf_event_attr::sig_data on modification").
  return reinterpret_cast<uptr>(this) + (reuse_count_ << (kWordBits - 8));
}

}  // namespace gwpsan
