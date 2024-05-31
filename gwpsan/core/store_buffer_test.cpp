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

#include "gwpsan/core/store_buffer.h"

#include <ios>
#include <vector>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"

namespace gwpsan {
namespace {

TEST(StoreBuffer, Test) {
  struct Access {
    uptr addr;
    uptr size;
    uptr val;
  };
  struct Test {
    uptr result;
    Access load;
    std::vector<Access> stores;
  };
  // clang-format off
  Test tests[] = {
    {
      0xaaaaaaaaaaaaaaaa, Access{0x100, 8, 0xaaaaaaaaaaaaaaaa},
    },
    {
      0xaaaaaaaaaaaaaaaa, Access{0x100, 8, 0xaaaaaaaaaaaaaaaa},
      {Access{0x200, 8, 0xbbbbbbbbbbbbbbbb}},
    },
    {
      0xbbbbbbbbbbbbbbbb, Access{0x100, 8, 0xaaaaaaaaaaaaaaaa},
      {Access{0x100, 8, 0xbbbbbbbbbbbbbbbb}},
    },
    {
      0xaaaaaaaabbbbbbbb, Access{0x100, 8, 0xaaaaaaaaaaaaaaaa},
      {Access{0x100, 4, 0xbbbbbbbbbbbbbbbb}},
    },
    {
      0xbbbbbbbbaaaaaaaa, Access{0x100, 8, 0xaaaaaaaaaaaaaaaa},
      {Access{0x104, 8, 0xbbbbbbbbbbbbbbbb}},
    },
    {
      0xaaaabbbbbbbbaaaa, Access{0x100, 8, 0xaaaaaaaaaaaaaaaa},
      {Access{0x102, 4, 0xbbbbbbbbbbbbbbbb}},
    },
    {
      0xaaaaaaaa, Access{0x100, 4, 0xaaaaaaaa},
      {Access{0x104, 8, 0xbbbbbbbbbbbbbbbb}},
    },
    {
      0xaaaaaaaa, Access{0x104, 4, 0xaaaaaaaa},
      {Access{0x100, 4, 0xbbbbbbbbbbbbbbbb}},
    },
    {
      0xaaaaaaddddbbbbcc, Access{0x100, 8, 0xaaaaaaaaaaaaaaaa},
      {
        Access{0x100, 4, 0xbbbbbbbbbbbbbbbb},
        Access{0x100, 1, 0xcccccccccccccccc},
        Access{0x103, 2, 0xdddddddddddddddd},
      },
    },
  };
  // clang-format on
  for (auto& test : tests) {
    StoreBuffer buffer;
    for (auto& store : test.stores)
      buffer.Store(Addr(store.addr), ByteSize(store.size), store.val);
    uptr result = buffer.Forward(Addr(test.load.addr), ByteSize(test.load.size),
                                 test.load.val);
    EXPECT_EQ(result, test.result)
        << std::showbase << "load " << std::hex << test.load.addr << "/"
        << test.load.size << "/" << std::hex << test.load.val << ": expect "
        << std::hex << test.result << ", got " << std::hex << result;
  }
}

}  // namespace
}  // namespace gwpsan
