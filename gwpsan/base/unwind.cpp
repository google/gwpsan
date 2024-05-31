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

#include "gwpsan/base/unwind.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/env.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/weak_imports.h"

namespace gwpsan {
// It may read stack redzones and uninits.
SAN_NOINSTR uptr RawUnwindStack(Span<uptr> storage, const void* fp) {
  struct Frame {
    Frame* next;
    void* pc;
  };
  Frame f;
  uptr n = 0;
  // Strictly speaking we don't need kPageSize checks, since we use
  // non-failing loads, but since frame pointers realistically may be bogus
  // the additional check may speed up things.
  for (; reinterpret_cast<sptr>(fp) > kPageSize && n < storage.size() &&
         NonFailingLoad(fp, Sizeof(f), &f) &&
         reinterpret_cast<sptr>(f.pc) > kPageSize;
       fp = f.next) {
    storage[n++] = reinterpret_cast<uptr>(__builtin_extract_return_addr(f.pc));
  }
  return n;
}

Span<const uptr> RawUnwindStack(Span<uptr> storage) {
  auto size = RawUnwindStack(storage, __builtin_frame_address(0));
  return {storage.data(), size};
}

void Symbolize(unsigned long pc, char* buf, int buf_size, bool add_src) {
  constexpr char kUnknown[] = "(unknown)";
  if (!absl::Symbolize) {
    internal_strncpy(buf, kUnknown, buf_size);
    return;
  }
  if (!absl::Symbolize(reinterpret_cast<void*>(pc), buf, buf_size)) {
    internal_strncpy(buf, kUnknown, buf_size);
    return;
  }
  if (add_src)
    return;
  // Try to remove the file:line info, if present.
  // Note that the symbol name can contain both spaces
  // (in "anonymous namespace") and colons (as namespace separator).
  // For simplicity we currently assume that the file name does not contain
  // spaces, so the first space is the potential separator between file:line
  // and the symbol name.
  const char* src = buf;
  while (*src && *src != ' ')
    src++;
  if (!*src || src == buf || (src[-1] < '0' || src[-1] > '9'))
    return;
  src++;
  while ((*buf++ = *src++)) {}
}
}  // namespace gwpsan
