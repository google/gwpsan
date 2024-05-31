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

#include "gwpsan/core/unwind_instruction.h"

#include <string.h>
#include <sys/mman.h>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/core/arch.h"

namespace gwpsan {
namespace {

TEST(UnwindInstruction, CopyPreceedingCode) {
  // Map 3 pages, first is inaccessible.
  // This allows to test both boundary between accessible pages,
  // and accessible and inaccessible page.
  void* mem = mmap(nullptr, 3 * kPageSize, PROT_READ | PROT_WRITE,
                   MAP_ANON | MAP_PRIVATE, -1, 0);
  ASSERT_NE(mem, MAP_FAILED);
  memset(mem, 0x42, 3 * kPageSize);
  ASSERT_EQ(0, mprotect(mem, kPageSize, PROT_NONE));
  // Test boundary between accessible pages.
  // Here we must always copy kMaxInstrLen bytes.
  for (uptr off = 0; off < 2 * kMaxInstrLen; off++) {
    u8* code = static_cast<u8*>(mem) + 2 * kPageSize - kMaxInstrLen - off;
    for (uptr i = 0; i < kMaxInstrLen; i++)
      code[i] = i + 1;
    u8 buf[kMaxInstrLen + 2] = {};
    uptr copied = CopyPreceedingCode(
        reinterpret_cast<uptr>(code) + kMaxInstrLen, buf + 1);
    ASSERT_EQ(copied, kMaxInstrLen);
    ASSERT_EQ(buf[0], 0);
    for (uptr i = 0; i < kMaxInstrLen; i++)
      ASSERT_EQ(buf[i + 1], i + 1);
    ASSERT_EQ(buf[kMaxInstrLen + 1], 0);
  }
  // Test boundary between accessible and inaccessible page.
  for (uptr off = 0; off < kMaxInstrLen; off++) {
    const uptr inaccessible = kMaxInstrLen - off;
    u8* code = static_cast<u8*>(mem) + kPageSize - inaccessible;
    for (uptr i = 0; i < off; i++)
      code[inaccessible + i] = i + 1;
    u8 buf[kMaxInstrLen + 2] = {};
    uptr copied = CopyPreceedingCode(
        reinterpret_cast<uptr>(code) + kMaxInstrLen, buf + 1);
    ASSERT_EQ(copied, off);
    for (uptr i = 0; i < inaccessible + 1; i++)
      ASSERT_EQ(buf[i], 0);
    for (uptr i = 0; i < off; i++)
      ASSERT_EQ(buf[inaccessible + i + 1], i + 1);
    ASSERT_EQ(buf[kMaxInstrLen + 1], 0);
  }
  ASSERT_EQ(0, munmap(mem, 3 * kPageSize));
}

}  // namespace
}  // namespace gwpsan
