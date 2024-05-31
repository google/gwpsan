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

#include "gwpsan/base/env.h"

#include <sys/mman.h>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"

namespace gwpsan {
namespace {

TEST(NonFailing, Fails) {
  char* mem = static_cast<char*>(
      mmap(nullptr, 6 * kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0));
  ASSERT_NE(mem, MAP_FAILED);
  ASSERT_EQ(0, mprotect(mem + kPageSize, kPageSize, PROT_READ | PROT_WRITE));
  ASSERT_EQ(0, mprotect(mem + 2 * kPageSize, kPageSize, PROT_READ));
  ASSERT_EQ(0, mprotect(mem + 3 * kPageSize, kPageSize, PROT_WRITE));
  ASSERT_EQ(0, mprotect(mem + 4 * kPageSize, kPageSize, PROT_READ | PROT_EXEC));
  ASSERT_EQ(0, munmap(mem + 5 * kPageSize, kPageSize));

  char tmp[100];
  // Some clearly invalid addresses.
  EXPECT_FALSE(NonFailingLoad(nullptr, ByteSize(1), tmp));
  EXPECT_FALSE(NonFailingStore(nullptr, ByteSize(2), tmp));
  EXPECT_FALSE(
      NonFailingLoad(Addr(reinterpret_cast<void*>(-1)), ByteSize(1), tmp));
  EXPECT_FALSE(
      NonFailingStore(Addr(reinterpret_cast<void*>(-1)), ByteSize(2), tmp));
  EXPECT_FALSE(NonFailingLoad(Addr(reinterpret_cast<void*>(0x8181000000000000)),
                              ByteSize(2), tmp));
  EXPECT_FALSE(NonFailingStore(
      Addr(reinterpret_cast<void*>(0x8181000000000000)), ByteSize(3), tmp));
  EXPECT_FALSE(NonFailingLoad(Addr(reinterpret_cast<void*>(0x5555000000000000)),
                              ByteSize(4), tmp));
  EXPECT_FALSE(NonFailingStore(
      Addr(reinterpret_cast<void*>(0x5555000000000000)), ByteSize(5), tmp));
  // Our mapped pages.
  EXPECT_FALSE(NonFailingLoad(Addr(mem), ByteSize(6), tmp));
  EXPECT_FALSE(NonFailingStore(Addr(mem), ByteSize(7), tmp));
  EXPECT_TRUE(NonFailingLoad(Addr(mem + kPageSize), ByteSize(8), tmp));
  EXPECT_TRUE(NonFailingStore(Addr(mem + kPageSize), ByteSize(9), tmp));
  EXPECT_TRUE(NonFailingLoad(Addr(mem + 2 * kPageSize), ByteSize(8), tmp));
  EXPECT_FALSE(NonFailingStore(Addr(mem + 2 * kPageSize), ByteSize(9), tmp));
  // PROT_WRITE implies PROT_READ on both x86 and arm64.
  EXPECT_TRUE(NonFailingLoad(Addr(mem + 3 * kPageSize), ByteSize(4), tmp));
  EXPECT_TRUE(NonFailingStore(Addr(mem + 3 * kPageSize), ByteSize(8), tmp));
  EXPECT_TRUE(NonFailingLoad(Addr(mem + 4 * kPageSize), ByteSize(4), tmp));
  EXPECT_FALSE(NonFailingStore(Addr(mem + 4 * kPageSize), ByteSize(8), tmp));
  // Unmapped page.
  EXPECT_FALSE(NonFailingStore(Addr(mem + 5 * kPageSize), ByteSize(8), tmp));

  munmap(mem, 5 * kPageSize);
}

}  // namespace
}  // namespace gwpsan
