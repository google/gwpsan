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

#include "gwpsan/base/common.h"

namespace gwpsan {
namespace {
template <uptr kBlockSize>
SAN_ALWAYS_INLINE void MemsetTail(u8* dst, int c, uptr n) {
  if (n >= kBlockSize) {
    __builtin_memset_inline(dst, c, kBlockSize);
    n -= kBlockSize;
    dst += kBlockSize;
  }
  if constexpr (kBlockSize > 1)
    MemsetTail<kBlockSize / 2>(dst, c, n);
}
}  // namespace

SAN_NOINLINE void* internal_memset(void* s, int c, uptr n) {
  u8* dst = static_cast<u8*>(s);
  constexpr uptr kBlockSize = 128;
  for (; n >= kBlockSize; n -= kBlockSize, dst += kBlockSize) {
    __builtin_memset_inline(dst, c, kBlockSize);
    // Without this clang still emits a call to memset:
    // https://github.com/llvm/llvm-project/issues/56876
    SAN_BARRIER();
  }
  MemsetTail<kBlockSize>(dst, c, n);
  return s;
}

namespace {
template <uptr kBlockSize>
SAN_ALWAYS_INLINE void MemcpyTail(u8* dst, const u8* src, uptr n) {
  if (n >= kBlockSize) {
    __builtin_memcpy_inline(dst, src, kBlockSize);
    n -= kBlockSize;
    dst += kBlockSize;
    src += kBlockSize;
  }
  if constexpr (kBlockSize > 1)
    MemcpyTail<kBlockSize / 2>(dst, src, n);
}
}  // namespace

SAN_NOINLINE void* internal_memcpy(void* d, const void* s, uptr n) {
  const u8* src = static_cast<const u8*>(s);
  u8* dst = static_cast<u8*>(d);
  constexpr uptr kBlockSize = 128;
  for (; n >= kBlockSize; n -= kBlockSize, dst += kBlockSize, src += kBlockSize)
    __builtin_memcpy_inline(dst, src, kBlockSize);
  MemcpyTail<kBlockSize>(dst, src, n);
  return d;
}

SAN_NOINLINE void* internal_memchr(const void* s, int c, uptr n) {
  const u8* t = static_cast<const u8*>(s);
  for (uptr i = 0; i < n; ++i, ++t) {
    if (*t == c)
      return const_cast<u8*>(t);
  }
  return nullptr;
}

SAN_NOINLINE int internal_memcmp(const void* s1, const void* s2, uptr n) {
  const u8* t1 = static_cast<const u8*>(s1);
  const u8* t2 = static_cast<const u8*>(s2);
  for (uptr i = 0; i < n; ++i, ++t1, ++t2) {
    if (*t1 != *t2)
      return *t1 < *t2 ? -1 : 1;
  }
  return 0;
}

SAN_NOINLINE int internal_strcmp(const char* s1, const char* s2) {
  for (;;) {
    unsigned c1 = *s1;
    unsigned c2 = *s2;
    if (c1 != c2)
      return (c1 < c2) ? -1 : 1;
    if (c1 == 0)
      return 0;
    s1++;
    s2++;
  }
}

SAN_NOINLINE char* internal_strchr(const char* s, int c) {
  for (; *s; s++) {
    if (*s == c)
      return const_cast<char*>(s);
  }
  return nullptr;
}

SAN_NOINLINE char* internal_strrchr(const char* s, int c) {
  const char* res = nullptr;
  for (uptr i = 0; s[i]; i++) {
    if (s[i] == c)
      res = s + i;
  }
  return const_cast<char*>(res);
}

SAN_NOINLINE uptr internal_strlen(const char* s) {
  uptr i = 0;
  for (; s[i]; i++) {}
  return i;
}

SAN_NOINLINE char* internal_strncpy(char* dst, const char* src, uptr n) {
  uptr i;
  for (i = 0; i < n && src[i]; i++)
    dst[i] = src[i];
  internal_memset(dst + i, 0, n - i);
  return dst;
}

SAN_NOINLINE char* internal_strstr(const char* str, const char* what) {
  uptr len1 = internal_strlen(str);
  uptr len2 = internal_strlen(what);
  if (len1 < len2)
    return nullptr;
  for (uptr pos = 0; pos <= len1 - len2; pos++) {
    if (!internal_memcmp(str + pos, what, len2))
      return const_cast<char*>(str + pos);
  }
  return nullptr;
}

// These are exposed for internalized libraries (see e.g. msan:libmsan_private).
extern "C" {
SAN_LOCAL SAN_USED void* gwpsan_memcpy(void* dest, const void* src, uptr n) {
  return internal_memcpy(dest, src, n);
}

SAN_LOCAL SAN_USED void* gwpsan_memset(void* s, int c, uptr n) {
  return internal_memset(s, c, n);
}
}  // extern "C"

}  // namespace gwpsan
