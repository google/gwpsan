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

#include "gwpsan/base/log.h"

#include <fcntl.h>
#include <stdarg.h>

#include "gwpsan/base/bazel.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/module_list.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/syscall.h"

namespace gwpsan {

LogBuf::LogBuf() {
  buf_ = pos_ = Freelist<kSize>::Alloc();
  buf_[0] = 0;
}

LogBuf::LogBuf(const LogBuf& other) {
  buf_ = Freelist<kSize>::Alloc();
  uptr size = other.pos_ - other.buf_;
  internal_memcpy(buf_, other.buf_, size);
  buf_[size < kSize ? size : kSize - 1] = 0;
  pos_ = buf_ + size;
}

LogBuf::LogBuf(LogBuf&& other) {
  buf_ = other.buf_;
  pos_ = other.pos_;
  other.buf_ = other.pos_ = nullptr;
}

LogBuf::~LogBuf() {
  if (buf_)
    Freelist<kSize>::Free(buf_);
}

LogBuf& LogBuf::Append(const char* format, ...) {
  // Update position in the case something was written manually.
  pos_ += internal_strlen(pos_);
  uptr remain = buf_ + kSize - pos_;
  if (remain == 0)
    return *this;
  va_list args;
  va_start(args, format);
  pos_ += VSPrintf(pos_, remain, format, args);
  va_end(args);
  return *this;
}

LogFile::LogFile() {
  if (!log_path)
    return;
  LogBuf buf;
  buf.Append("%s.%d", log_path, GetPid());
  auto fd = sys_openat(AT_FDCWD, &buf, O_WRONLY | O_APPEND | O_CREAT, 0600);
  if (SAN_WARN_IF_ERR(fd)) {
    log_path = nullptr;
    return;
  }
  fd_ = fd.val();
}

LogFile::~LogFile() {
  if (fd_ >= 0)
    sys_close(fd_);
}

void Logf(const char* msg, ...) {
  va_list args;
  va_start(args, msg);
  LogBuf buf;
  uptr len = VSPrintf(&buf, LogBuf::kSize, msg, args);
  va_end(args);
  sys_write(LogFile().fd(), &buf, len);
  BazelOnPrint({&buf, len});
}

LogBuf DumpModuleImpl(uptr pc) {
  LogBuf buf;
  if (const auto* mod = FindModule(pc))
    buf.Append("(%s+0x%zx)", mod->name, pc - mod->pc_offset);
  return buf;
}

// These are provided as stubs, so that base can use them elsewhere and link;
// core code may override this with something better.

SAN_WEAK_LOCAL LogBuf DumpInstr(uptr pc, DumpWhat what) {
  return DumpModuleImpl(pc);
}

SAN_WEAK_LOCAL LogBuf DumpInstr(uptr pc, uptr pc_copy, DumpWhat what) {
  return DumpModuleImpl(pc);
}

bool log_enabled;
const char* log_path;

}  // namespace gwpsan
