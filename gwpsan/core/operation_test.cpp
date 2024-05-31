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

#include "gwpsan/core/operation.h"

#include <ios>

#include "gtest/gtest.h"
#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/instruction.h"
#include "gwpsan/core/meta.h"
#include "gwpsan/core/origin.h"

namespace gwpsan {
namespace {

TEST(Operation, TableTest) {
  HeapAllocatorLifetime alloc_lifetime;
  struct Test {
    OpRef op;
    uptr val0;
    uptr val1;
    uptr res;
    uptr shadow0;
    uptr shadow1;
    uptr shadow;
    uptr compute_flags;
    uptr expected_flags;
  };
  // Remove when the crash is resolved:
  // https://github.com/llvm/llvm-project/issues/51767
  // clang-format off
  Test tests[] = {
      {OpOr,   0,        0,      0},
      {OpOr,   0xab00,   0x00cd, 0xabcd},
      {OpOr,   0x0f0f,   0x00ff, 0x0fff},
      {OpOr,   0x0f0f,   0x00ff, 0x0fff, 0xffff, 0xffff, 0xffff},
      {OpOr,   0x0f0f,   0x00ff, 0x0fff, 0x0000, 0xffff, 0xf0f0},
      {OpOr,   0x0f0f,   0x00ff, 0x0fff, 0xffff, 0x0000, 0xff00},

      {OpAnd,  0,        0xffff, 0},
      {OpAnd,  0xab00,   0x00cd, 0},
      {OpAnd,  0x0f0f,   0x00ff, 0x000f},
      {OpAnd,  0x0f0f,   0x00ff, 0x000f, 0xffff, 0xffff, 0xffff},
      {OpAnd,  0x0f0f,   0x00ff, 0x000f, 0x0000, 0xffff, 0x0f0f},
      {OpAnd,  0x0f0f,   0x00ff, 0x000f, 0xffff, 0x0000, 0x00ff},
  };
  // clang-format on
  for (auto test : tests) {
    OpArgs src;
    src[0] = {test.val0,
              Meta().Set(test.shadow0, new OriginChain(new TaintOrigin(
                                           Origin::Type::kTainted, "src0")))};
    src[1] = {test.val1,
              Meta().Set(test.shadow1, new OriginChain(new TaintOrigin(
                                           Origin::Type::kTainted, "src1")))};
    Word res = test.op(src[0], src[1]);
    if (res.val != test.res || res.meta.shadow() != test.shadow)
      GTEST_FAIL() << std::hex << std::showbase << test.op.Name() << "("
                   << test.val0 << "[" << test.shadow0 << "], " << test.val1
                   << "[" << test.shadow0 << "]) = " << res.val << "["
                   << res.meta.shadow() << "], expected " << test.res << "["
                   << test.shadow << "]";
    if (!test.compute_flags)
      continue;
    RegArg dst(kSP);
    ImmArg arg0(test.val0);
    ImmArg arg1(test.val1);
    Instr instr(0, test.op, &dst, {&arg0, &arg1});
    Instr::Flags flags{test.compute_flags};
    uptr untainted = 0;
    uptr got_flags = test.op.ComputeFlags(instr, flags, untainted, res, src);
    if (got_flags != test.expected_flags) {
      GTEST_FAIL() << std::hex << std::showbase << test.op.Name() << "("
                   << test.val0 << ", " << test.val1 << ") = " << res.val
                   << ", got flags " << got_flags << ", expected "
                   << test.expected_flags;
    }
  }
}

}  // namespace
}  // namespace gwpsan
