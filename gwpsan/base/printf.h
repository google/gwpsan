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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_PRINTF_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_PRINTF_H_

#include <stdarg.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/span.h"

namespace gwpsan SAN_LOCAL {

// These functions always zero-terminate the buffer
// and return the number of bytes written.
void VPrintf(const char* format, va_list args);
uptr SPrintf(char* buf, uptr len, const char* format, ...) SAN_FORMAT(3, 4);
uptr VSPrintf(char* buf, uptr len, const char* format, va_list args);

using PrintfCallback = FunctionRef<void(const Span<const char>&)>;
// Set optional Printf() callback, called for every Printf() invocation.
inline void SetPrintfCallback(const Optional<PrintfCallback>& cb) {
  extern OptionalBase<PrintfCallback> printf_callback;
  printf_callback = cb;
}

void PrintStackTrace(const Span<const uptr>& trace, const char* prefix = "");
void PrintCurrentStackTrace();

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_PRINTF_H_
