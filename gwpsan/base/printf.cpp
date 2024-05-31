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

#include "gwpsan/base/printf.h"

#include <stdarg.h>

#include "gwpsan/base/array.h"
#include "gwpsan/base/bazel.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/fault_inject.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/base/unwind.h"

namespace gwpsan {
constinit OptionalBase<PrintfCallback> printf_callback;

namespace {

enum NumFormat {
  kNumNegative = 1 << 0,
  kNumSign = 1 << 1,
  kNumZeroPadded = 1 << 2,
  kNumHex = 1 << 3,
  kNumUppercase = 1 << 4,
};

void AppendChar(char*& pos, const char* end, char c) {
  if (pos < end)
    *pos++ = c;
}

void AppendNumber(char*& pos, const char* end, u64 val, int min_len,
                  u32 flags) {
  Array<char, 30> digits;
  min_len = min<int>(min_len, digits.size());
  if ((flags & kNumSign) && min_len)
    --min_len;
  char sign = flags & kNumNegative ? '-' : '+';
  if ((flags & kNumSign) && (flags & kNumZeroPadded))
    AppendChar(pos, end, sign);
  u64 base = (flags & kNumHex) ? 16 : 10;
  int n = 0;
  do {
    digits.at(n++) = val % base;
    val /= base;
  } while (val > 0);
  for (int i = n; i < min_len; i++)
    AppendChar(pos, end, (flags & kNumZeroPadded) ? '0' : ' ');
  if ((flags & kNumSign) && !(flags & kNumZeroPadded))
    AppendChar(pos, end, sign);
  for (n--; n >= 0; n--) {
    char digit = digits[n];
    digit = digit < 10 ? '0' + digit
                       : ((flags & kNumUppercase) ? 'A' : 'a') + digit - 10;
    AppendChar(pos, end, digit);
  }
}

void AppendString(char*& pos, const char* end, int width, const char* s) {
  s = s ?: "<null>";
  int n = 0;
  for (; *s; s++, n++)
    AppendChar(pos, end, *s);
  for (; width < -n; n++)
    AppendChar(pos, end, ' ');
}
}  // namespace

uptr VSPrintf(char* const buf, uptr len, const char* format, va_list args) {
  SAN_CHECK(buf && len && format);
  char* pos = buf;
  char* end = buf + len;
  SAN_CHECK_GT(end, buf);
  const char* cur = format;
  for (; *cur; cur++) {
    if (*cur != '%') {
      AppendChar(pos, end, *cur);
      continue;
    }
    cur++;
    bool left_justified = *cur == '-';
    cur += left_justified;
    bool have_plus = *cur == '+';
    cur += have_plus;
    u32 flags = have_plus ? kNumSign : 0;
    flags |= *cur == '0' ? kNumZeroPadded : 0;
    int width = 0;
    while (*cur >= '0' && *cur <= '9')
      width = width * 10 + *cur++ - '0';
    bool have_z = (*cur == 'z');
    cur += have_z;
    bool have_l = cur[0] == 'l' && cur[1] != 'l';
    cur += have_l;
    bool have_ll = cur[0] == 'l' && cur[1] == 'l';
    cur += have_ll * 2;
    const bool have_length = have_z || have_l || have_ll;
    const bool have_flags = width || have_length;
    SAN_CHECK(*cur == 's' || !left_justified);
    switch (*cur) {
    case 'd': {
      s64 val = have_ll  ? va_arg(args, s64)
                : have_z ? va_arg(args, sptr)
                : have_l ? va_arg(args, long)
                         : va_arg(args, int);
      flags |= val < 0 ? (kNumNegative | kNumSign) : 0;
      AppendNumber(pos, end, val >= 0 ? val : -val, width, flags);
      break;
    }
    case 'u':
    case 'x':
    case 'X': {
      u64 val = have_ll  ? va_arg(args, u64)
                : have_z ? va_arg(args, uptr)
                : have_l ? va_arg(args, unsigned long)
                         : va_arg(args, unsigned);
      flags |= (*cur != 'u' ? kNumHex : 0) | (*cur == 'X' ? kNumUppercase : 0);
      AppendNumber(pos, end, val, width, flags);
      break;
    }
    case 'p': {
      SAN_CHECK(!have_flags);
      AppendChar(pos, end, '0');
      AppendChar(pos, end, 'x');
      AppendNumber(pos, end, va_arg(args, uptr), 12, kNumHex | kNumZeroPadded);
      break;
    }
    case 's': {
      SAN_CHECK(!have_length);
      SAN_CHECK(!width || left_justified);
      AppendString(pos, end, left_justified ? -width : width,
                   va_arg(args, char*));
      break;
    }
    case 'c': {
      SAN_CHECK(!have_flags);
      AppendChar(pos, end, va_arg(args, int));
      break;
    }
    case '%': {
      SAN_CHECK(!have_flags);
      AppendChar(pos, end, '%');
      break;
    }
    default:
      SAN_WARN(1, "unknown format specifier: %c", *cur);
    }
  }
  AppendChar(pos, end, 0);
  SAN_CHECK_LE(pos, end);
  end[-1] = 0;
  return pos - buf - 1;
}

uptr SPrintf(char* buf, uptr len, const char* format, ...) {
  va_list args;
  va_start(args, format);
  len = VSPrintf(buf, len, format, args);
  va_end(args);
  return len;
}

SAN_NOINLINE void VPrintf(const char* format, va_list args) {
  LogBuf buf;
  uptr len = VSPrintf(&buf, LogBuf::kSize, format, args);
  if (!len)
    return;
  sys_write(2, &buf, len);
  if (log_path)
    sys_write(LogFile().fd(), &buf, len);
  if (printf_callback)
    (*printf_callback)({&buf, len});
  BazelOnPrint({&buf, len});
}

void Printf(const char* format, ...) {
  va_list args;
  va_start(args, format);
  VPrintf(format, args);
  va_end(args);
}

SAN_NOINLINE void PrintStackTrace(const Span<const uptr>& trace,
                                  const char* prefix) {
  if (trace.empty()) {
    Printf("(no stack)\n");
    return;
  }
  char sym[256];
  for (int i = 0; i < trace.size(); i++) {
    sym[0] = 0;
    Symbolize(trace[i], sym, sizeof(sym), true);
    // If symbolization added filename:#line, find the separation point for
    // checking the special functions below.
    const char* func_sym = internal_strrchr(sym, ' ');
    if (func_sym)
      func_sym++;
    else
      func_sym = sym;  // No filename.
    // Stop at well-known entry points. There is little point in dumping
    // libc/libc++/libstdc++ guts in every report.
    if (!internal_strcmp(func_sym, "start_thread") ||
        !internal_strcmp(func_sym, "std::__u::__thread_proxy<>()") ||
        !internal_strcmp(func_sym, "std::__u::__thread_execute<>()") ||
        !internal_strcmp(func_sym, "std::__msan::__thread_proxy<>()") ||
        !internal_strcmp(func_sym, "std::__msan::__thread_execute<>()") ||
        !internal_strcmp(func_sym, "std::thread::_Invoker<>::_M_invoke<>()"))
      break;
    Printf("%s#%d: %s %s\n", prefix, i, &DumpInstr(trace[i], kDumpModule), sym);
    if (!internal_strcmp(func_sym, "main"))
      break;
  }
}

SAN_NOINLINE void PrintCurrentStackTrace() {
  Array<uptr, 32> stack;
  PrintStackTrace(RawUnwindStack(stack));
}

void BugImpl(const char* msg, ...) {
  ScopedFaultInjectDisable fault_inject_disable;
  va_list args;
  va_start(args, msg);
  VPrintf(msg, args);
  va_end(args);
  PrintCurrentStackTrace();
  Die();
}

void WarnImpl(const char* msg, ...) {
  ScopedFaultInjectDisable fault_inject_disable;
  va_list args;
  va_start(args, msg);
  VPrintf(msg, args);
  va_end(args);
  PrintCurrentStackTrace();
  if (GWPSAN_DEBUG)
    Die();
}

}  // namespace gwpsan
