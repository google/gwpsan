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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_SANITIZER_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_SANITIZER_H_

#include "gwpsan/base/common.h"

// Provides ASAN_POISON_MEMORY_REGION and ASAN_UNPOISON_MEMORY_REGION.
#include <sanitizer/asan_interface.h>  // IWYU pragma: export
#if GWPSAN_INSTRUMENTED_MSAN
#include <sanitizer/msan_interface.h>  // IWYU pragma: export
#define MSAN_POISON_MEMORY_REGION(addr, size) \
  __msan_allocated_memory((addr), (size))
#define MSAN_UNPOISON_MEMORY_REGION(addr, size) __msan_unpoison((addr), (size))
#define MSAN_CHECK_MEMORY_REGION(addr, size) \
  __msan_check_mem_is_initialized((addr), (size))
#define MSAN_COPY_MEMORY_REGION(dst, src, size) \
  __msan_copy_shadow((dst), (src), (size))
#else
#define MSAN_POISON_MEMORY_REGION(addr, size)
#define MSAN_UNPOISON_MEMORY_REGION(addr, size)
#define MSAN_CHECK_MEMORY_REGION(addr, size)
#define MSAN_COPY_MEMORY_REGION(dst, src, size)
#endif

namespace gwpsan {

// Return true if `addr` is shadow memory of compiler-based sanitizer.
inline bool IsSanitizerShadow(uptr addr) {
#if GWPSAN_INSTRUMENTED_MSAN
  // Constants from MSan runtime in compiler-rt/lib/msan/msan.h.
  constexpr uptr kShadowRanges[][2] =
#if GWPSAN_ARM64  // clang-format off
    {
        {0x0100000000000ULL, 0x0200000000000ULL},
        {0x0300000000000ULL, 0x0400000000000ULL},
        {0x0400000000000ULL, 0x0600000000000ULL},
        {0x0600000000000ULL, 0x0800000000000ULL},
        {0x0B00000000000ULL, 0x0C00000000000ULL},
        {0x0C00000000000ULL, 0x0D00000000000ULL},
        {0x0D00000000000ULL, 0x0E00000000000ULL},
    };
#elif GWPSAN_X64
    {
        {0x010000000000ULL, 0x100000000000ULL},
        {0x110000000000ULL, 0x200000000000ULL},
        {0x200000000000ULL, 0x300000000000ULL},
        {0x300000000000ULL, 0x400000000000ULL},
        {0x500000000000ULL, 0x510000000000ULL},
        {0x600000000000ULL, 0x610000000000ULL},
    };
#else  // clang-format on
#error "Unsupported platform"
#endif
  for (int i = 0; i < SAN_ARRAY_SIZE(kShadowRanges); i++) {
    if (addr >= kShadowRanges[i][0] && addr < kShadowRanges[i][1])
      return true;
  }
#endif  // GWPSAN_INSTRUMENTED_MSAN

  return false;
}

}  // namespace gwpsan

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_SANITIZER_H_
