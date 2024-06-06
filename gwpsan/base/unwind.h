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

#ifndef GWPSAN_BASE_UNWIND_H_
#define GWPSAN_BASE_UNWIND_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/span.h"

namespace gwpsan SAN_LOCAL {

// Unwinds the current stack w/o skipping our runtime frames.
// Intended for debugging/bug reports in gwpsan itself.
Span<const uptr> RawUnwindStack(Span<uptr> storage);

// Unwind the stack starting from the frame pointer 'fp'.
uptr RawUnwindStack(Span<uptr> storage, const void* fp);

// Symbolizes pc and stores the result into the buf.
// If add_src, may also add source:line info if available.
void Symbolize(uptr pc, char* buf, int buf_size, bool add_src);

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_UNWIND_H_
