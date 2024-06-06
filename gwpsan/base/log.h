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

#ifndef GWPSAN_BASE_LOG_H_
#define GWPSAN_BASE_LOG_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/span.h"

namespace gwpsan SAN_LOCAL {

#define SAN_LOG_IF(cond, msg, ...)                                             \
  do {                                                                         \
    if (SAN_UNLIKELY(cond))                                                    \
      Logf("[gwpsan][T%7u " __FILE_NAME__ ":" SAN_STRINGIFY(__LINE__) "] " msg \
                                                                      "\n",    \
           GetTid(), ##__VA_ARGS__);                                           \
  } while (0)

#define SAN_LOG(msg, ...) SAN_LOG_IF(log_enabled, msg, ##__VA_ARGS__)

extern bool log_enabled;
extern const char* log_path;

void Logf(const char* msg, ...) SAN_FORMAT(1, 2);

// LogBuf allows to use helper functions when logging/printing objects.
// The intended use is as follows:
//
// LogBuf Foo::Dump() {
//   LogBuf buf;
//   return buf.Append("x=%d y=%d", x_, y_);
// }
//
// SAN_LOG/Printf("foo: %s", &foo.Dump());
class LogBuf {
 public:
  static constexpr uptr kSize = 1024;

  LogBuf();
  LogBuf(const LogBuf& other);
  LogBuf(LogBuf&& other);
  ~LogBuf();

  LogBuf& Append(const char* format, ...) SAN_FORMAT(2, 3);

  char* operator&() {
    return buf_;
  }

  bool Empty() const {
    return buf_[0] == 0;
  }

  Span<char> Remain() {
    pos_ += internal_strlen(pos_);
    return {pos_, static_cast<uptr>(buf_ + kSize - pos_)};
  }

 private:
  char* buf_;
  char* pos_;

  LogBuf& operator=(const LogBuf&) = delete;
};

// LogFile encapsulates opening (for appending) and closing of the log_path
// if passed as flags. If log_path is not passed, then fd() returns stderr fd.
class LogFile {
 public:
  LogFile();
  ~LogFile();

  // By default log to stderr.
  int fd() const {
    return fd_ < 0 ? 2 : fd_;
  }

 private:
  int fd_ = -1;
  LogFile(const LogFile&) = delete;
  LogFile& operator=(const LogFile&) = delete;
};

// DumpWhat bitmask describes what information about the pc DumpInstr dumps.
using DumpWhat = uptr;
// Dump numeric PC value.
inline constexpr DumpWhat kDumpPC = 1 << 0;
// Dump disassembled instruction.
inline constexpr DumpWhat kDumpAsm = 1 << 1;
// Dump raw instruction bytes.
inline constexpr DumpWhat kDumpBytes = 1 << 2;
// Dump module+offset.
inline constexpr DumpWhat kDumpModule = 1 << 3;
// Info useful in decoder errors.
inline constexpr DumpWhat kDumpRaw = kDumpAsm | kDumpBytes;
// Info useful for end users.
// TODO(dvyukov): add source:line info here.
inline constexpr DumpWhat kDumpSource = kDumpPC | kDumpModule;
inline constexpr DumpWhat kDumpAll =
    kDumpPC | kDumpAsm | kDumpBytes | kDumpModule;

LogBuf DumpInstr(uptr pc, DumpWhat what);
LogBuf DumpInstr(uptr pc, uptr pc_copy, DumpWhat what);

// Not intented to be used outside of DumpInstr implementation.
LogBuf DumpModuleImpl(uptr pc);
LogBuf DumpBytesImpl(uptr addr, uptr size);

}  // namespace gwpsan SAN_LOCAL

#endif
