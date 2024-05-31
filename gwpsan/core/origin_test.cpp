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

#include "gwpsan/core/origin.h"

#include "gtest/gtest.h"
#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/operation.h"

namespace gwpsan {
namespace {

CPUContext CtxWithPC(uptr pc) {
  CPUContext ctx;
  ctx.set_reg(kPC, pc);
  return ctx;
}

TEST(Origin, Basic) {
  HeapAllocatorLifetime alloc_lifetime;
  auto* chain = new OriginChain(
      new RegLoadOrigin(kSP, 0x357),
      new OriginChain(
          new InstructionOrigin(CtxWithPC(0x1), 1),
          new OriginChain(
              // Some unrelated chunk of code that does not operate on our data.
              new InstructionOrigin(CtxWithPC(0x36), 1),
              new OriginChain(
                  new InstructionOrigin(CtxWithPC(0x35), 1),
                  new OriginChain(
                      new InstructionOrigin(CtxWithPC(0x31), 4),
                      new OriginChain(
                          new InstructionOrigin(CtxWithPC(0x30), 1),
                          new OriginChain(
                              new InstructionOrigin(CtxWithPC(0x20), 1),
                              new OriginChain(
                                  new InstructionOrigin(CtxWithPC(0x13), 1),
                                  new OriginChain(
                                      new InstructionOrigin(CtxWithPC(0x11), 2),
                                      new OriginChain(
                                          new InstructionOrigin(CtxWithPC(0x10),
                                                                1),
                                          new OriginChain(
                                              new RegStoreOrigin(kSP),
                                              new OriginChain(
                                                  new OpOrigin(OpAdd, 0x123,
                                                               {0x234, 0x357}),
                                                  new OriginChain(
                                                      new RegLoadOrigin(kSP,
                                                                        0x123),
                                                      new OriginChain(
                                                          new InstructionOrigin(
                                                              CtxWithPC(0x4),
                                                              1),
                                                          new OriginChain(
                                                              new MemLoadOrigin(
                                                                  0x123, 0x234),
                                                              new OriginChain(
                                                                  new MemStoreOrigin(
                                                                      0x345),
                                                                  new OriginChain(new MallocOrigin(
                                                                      CtxWithPC(
                                                                          0x456),
                                                                      0x100,
                                                                      0x100,
                                                                      0x10))))))))))))))))));
  // TODO(dvyukov): We need to check that output somehow.
  // Figure out the story for "output" unit tests.
  chain->Print();
}

}  // namespace
}  // namespace gwpsan
