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

#include "gwpsan/core/meta.h"

#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/operation.h"
#include "gwpsan/core/origin.h"

namespace gwpsan {

class MetaTest : public testing::Test {
 protected:
  const Origin* GetOrigin(const OriginChain* val) {
    return val ? val->origin_ : nullptr;
  }

  uptr OriginDepth(const OriginChain* val) {
    return val ? val->depth_ : ~0ul;
  }

 private:
  HeapAllocatorLifetime alloc_lifetime_;
};

namespace {
OriginChain* ChainOfDepth(uptr n) {
  auto* chain = new OriginChain(new MallocOrigin(CPUContext(), 0, 0, 0));
  for (uptr i = 0; i < n; i++)
    chain = new OriginChain(new MemLoadOrigin(i, i), chain);
  return chain;
}

TEST_F(MetaTest, Ctors) {
  Meta m0;
  m0.Print(Origin::Type::kAny);
  EXPECT_EQ(m0.shadow(), 0);
  EXPECT_EQ(m0.Simplest(Origin::Type::kAny), nullptr);

  Origin* origin = new MallocOrigin(CPUContext(), 1, 2, 3);
  Meta m1(origin);
  m1.Print(Origin::Type::kAny);
  EXPECT_EQ(m1.shadow(), ~0ul);
  EXPECT_EQ(GetOrigin(m1.Simplest(Origin::Type::kAny)), origin);

  m0 = m1;
  EXPECT_EQ(m0.shadow(), ~0ul);
  EXPECT_EQ(GetOrigin(m0.Simplest(Origin::Type::kAny)), origin);
}

TEST_F(MetaTest, SetReset) {
  Origin* origin = new MallocOrigin(CPUContext(), 1, 2, 3);
  Meta m(origin);
  m.Reset(0xffff00ul);
  EXPECT_EQ(m.shadow(), 0xffffffffff0000fful);
  m.Reset(0xff00000000ul);
  EXPECT_EQ(m.shadow(), 0xffffff00ff0000fful);
  // This is a longer chain, so Simplest must return the first one.
  auto* chain1 = ChainOfDepth(2);
  m.Set(0xf000ul, chain1);
  EXPECT_EQ(m.shadow(), 0xffffff00ff00f0fful);
  EXPECT_EQ(GetOrigin(m.Simplest(Origin::Type::kAny)), origin);
  EXPECT_EQ(GetOrigin(m.Simplest(Origin::Type::kAny, 0xf)), origin);
  EXPECT_EQ(m.Simplest(Origin::Type::kAny, 0xf000), chain1);
  EXPECT_EQ(m.Simplest(Origin::Type::kAny, 0xf00), nullptr);

  m.Reset(~0ul);
  EXPECT_EQ(m.shadow(), 0);
  EXPECT_EQ(m.Simplest(Origin::Type::kAny), nullptr);
  auto* chain2 = ChainOfDepth(1);
  m.Set(0xf0ul, chain2);
  EXPECT_EQ(m.shadow(), 0xf0ul);
  EXPECT_EQ(m.Simplest(Origin::Type::kAny), chain2);
}

TEST_F(MetaTest, BitwiseOr) {
  // Some bits will come from m0, some from m1, some from both, some are zero.
  Meta m0, m1;
  auto* chain1 = ChainOfDepth(1);
  auto* chain2 = ChainOfDepth(2);
  auto* chain3 = ChainOfDepth(3);
  auto* chain4 = ChainOfDepth(4);
  auto* chain5 = ChainOfDepth(5);
  m0.Set(0xf0f0000000000000ul, chain1);
  m1.Set(0xf000ff0000000000ul, chain2);
  m0.Set(0x0000000ff0000000ul, chain3);
  m1.Set(0x00000000f0000000ul, chain2);
  m0.Set(0x000000000000f000ul, chain3);
  m1.Set(0x00000000000fff00ul, chain4);
  m0.Set(0x00000000000000f0ul, chain4);
  m1.Set(0x00000000000000f0ul, chain5);
  m0.Set(0x000000000000000ful, chain5);
  m1.Set(0x000000000000000ful, chain4);
  // Check the resulting shadow.
  Meta m = Meta::BitwiseOr(m0, m1);
  EXPECT_EQ(m.shadow(), 0xf0f0ff0ff00ffffful);
  // Now check individual parts and their origins.
  auto check = [&](uptr mask, OriginChain* chain) {
    Meta m2 = m;
    m2.Reset(~mask);
    EXPECT_EQ(m2.shadow(), mask);
    EXPECT_EQ(m2.Simplest(Origin::Type::kAny), chain);
  };
  check(0xf000000000000000ul, chain1);
  check(0x00f0000000000000ul, chain1);
  check(0x0000ff0000000000ul, chain2);
  check(0x0000000f00000000ul, chain3);
  check(0x00000000f0000000ul, chain2);
  check(0x00000000000f0f00ul, chain4);
  check(0x000000000000f000ul, chain3);
  check(0x00000000000000f0ul, chain4);
  check(0x000000000000000ful, chain4);
}

TEST_F(MetaTest, Shift) {
  Meta m1 = Meta::Shift(OpShiftLeft, Meta(), 10);
  EXPECT_EQ(m1.shadow(), 0);
  Meta m2 = Meta::Shift(OpShiftLeft,
                        Meta(new MallocOrigin(CPUContext(), 0, 0, 0)), 16);
  EXPECT_EQ(m2.shadow(), 0xffffffffffff0000ul);
  Meta m3 = Meta::Shift(OpShiftRight,
                        Meta(new MallocOrigin(CPUContext(), 0, 0, 0)), 8);
  EXPECT_EQ(m3.shadow(), 0x00fffffffffffffful);
  Meta m4;
  m4.Set(0xf000000000000000ul, ChainOfDepth(1));
  m4.Set(0x000a000000000000ul, ChainOfDepth(1));
  m4.Set(0x00000000000b0000ul, ChainOfDepth(1));
  m4.Set(0x000000000000000cul, ChainOfDepth(1));
  Meta m5 = Meta::Shift(OpShiftLeft, m4, 8);
  EXPECT_EQ(m5.shadow(), 0x0a0000000b000c00ul);
  Meta m6 = Meta::Shift(OpShiftRight, m4, 8);
  EXPECT_EQ(m6.shadow(), 0x00f00a0000000b00ul);
}

TEST_F(MetaTest, ReverseBits) {
  Meta m;
  m.Set(0xa000000000000000ul, ChainOfDepth(1));
  m.Set(0x000b000000000000ul, ChainOfDepth(2));
  m.Set(0x000000000000000cul, ChainOfDepth(3));
  m = Meta::ReverseBits(m);
  EXPECT_EQ(m.shadow(), 0x300000000000d005ul);
  auto check = [&](uptr mask, uptr depth) {
    Meta m2 = m;
    m2.Reset(~mask);
    EXPECT_EQ(m2.shadow(), mask);
    EXPECT_EQ(OriginDepth(m2.Simplest(Origin::Type::kAny)), depth);
  };
  check(0x3000000000000000ul, 3);
  check(0x000000000000d000ul, 2);
  check(0x0000000000000005ul, 1);
}

void Dump(const char* name, const std::vector<MemAccess>& accesses) {
  Printf("%s:", name);
  for (const auto& a : accesses)
    Printf(" %s", &a.ToString());
  Printf("\n");
}

TEST(MergeMemAccesses, Test) {
  struct Test {
    std::vector<MemAccess> in;
    std::vector<MemAccess> out;
  };
  // clang-format off
  Test tests[] = {
    // Merge accesses to the same memory.
    {{
      MemAccess{0, Addr(0x100), ByteSize(10), {}, true, false, false},
      MemAccess{0, Addr(0x100), ByteSize(10), {}, false, true, false},
    }, {
      MemAccess{0, Addr(0x100), ByteSize(10), {}, true, true, false},
    }},
    {{
      MemAccess{0, Addr(0x100), ByteSize(10), {}, true, false, false},
      MemAccess{0, Addr(0x100), ByteSize(20), {}, false, true, false},
      MemAccess{0, Addr(0x100), ByteSize(10), {}, true, false, true},
    }, {
      MemAccess{0, Addr(0x100), ByteSize(10), {}, true, false, true},
      MemAccess{0, Addr(0x100), ByteSize(20), {}, false, true, false},
    }},
    // Merge adjacent accesses of the same type.
    {{
      MemAccess{0, Addr(0x100), ByteSize(4), {}, true, false, false},
      MemAccess{0, Addr(0x104), ByteSize(4), {}, true, false, false},
      MemAccess{0, Addr(0x108), ByteSize(4), {}, true, false, false},
    }, {
      MemAccess{0, Addr(0x100), ByteSize(12), {}, true, false, false},
    }},
    {{
      MemAccess{0, Addr(0x100), ByteSize(10), {}, true, false, false},
      MemAccess{0, Addr(0x102), ByteSize(14), {}, true, false, false},
    }, {
      MemAccess{0, Addr(0x100), ByteSize(16), {}, true, false, false},
    }},
    {{
      MemAccess{0, Addr(0x100), ByteSize(10), {}, true, false, false},
      MemAccess{0, Addr(0x102), ByteSize(8), {}, true, false, false},
    }, {
      MemAccess{0, Addr(0x100), ByteSize(10), {}, true, false, false},
    }},
    // Different types shouldn't be merged.
    {{
      MemAccess{0, Addr(0x100), ByteSize(4), {}, true, false, false},
      MemAccess{0, Addr(0x104), ByteSize(4), {}, false, true, false},
    }},
    // Merge both size and type.
    {{
      MemAccess{0, Addr(0x100), ByteSize(1), {}, true, false, false},
      MemAccess{0, Addr(0x101), ByteSize(1), {}, true, false, false},
      MemAccess{0, Addr(0x100), ByteSize(1), {}, false, true, false},
      MemAccess{0, Addr(0x101), ByteSize(1), {}, false, true, false},
    }, {
      MemAccess{0, Addr(0x100), ByteSize(2), {}, true, true, false},
    }},
    {{
      MemAccess{0, Addr(0x100), ByteSize(1), {}, true, false, false},
      MemAccess{0, Addr(0x100), ByteSize(1), {}, false, true, false},
      MemAccess{0, Addr(0x101), ByteSize(1), {}, true, false, false},
      MemAccess{0, Addr(0x101), ByteSize(1), {}, false, true, false},
    }, {
      MemAccess{0, Addr(0x100), ByteSize(2), {}, true, true, false},
    }},
  };
  // clang-format on
  for (auto& test : tests) {
    if (test.out.empty())
      test.out = test.in;
    Dump("input ", test.in);
    test.in.resize(MergeAccesses(test.in).size());
    Dump("output", test.in);
    Dump("expect", test.out);
    if (test.in != test.out)
      ADD_FAILURE();
  }
}

}  // namespace
}  // namespace gwpsan
