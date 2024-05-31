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

#include "gwpsan/base/module_list.h"

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "re2/re2.h"

namespace gwpsan {
namespace {

// Prevent the local variable from being allocated on asan fake stack
// (we need real stack address).
SAN_NOINLINE SAN_NOINSTR uptr StackAddr() {
  int local;
  volatile uptr sp = reinterpret_cast<uptr>(&local);
  return sp;
}

TEST(ModuleList, Basic) {
  ASSERT_TRUE(InitModuleList());
  ForEachModule([](const ModuleInfo& mod) {
    Printf("module %p-%p/%p '%s'\n", reinterpret_cast<void*>(mod.start_address),
           reinterpret_cast<void*>(mod.end_address),
           reinterpret_cast<void*>(mod.pc_offset), mod.name);
  });
  uptr my_pc = reinterpret_cast<uptr>(+[] {});
  const auto* mod = FindModule(my_pc);
  ASSERT_TRUE(mod != nullptr);
  EXPECT_TRUE(my_pc >= mod->start_address && my_pc < mod->end_address);
  // On forge the binary can be called as a long hex hash.
  EXPECT_TRUE(RE2::FullMatch(mod->name, "base_test|[a-f0-9]{16}[a-f0-9_]+"));
  auto stack_bounds = GetStackBounds();
  ASSERT_TRUE(stack_bounds);
  auto [stack_start, stack_end] = *stack_bounds;
  EXPECT_NE(stack_start, 0);
  EXPECT_NE(stack_end, 0);
  EXPECT_GT(StackAddr(), stack_start);
  EXPECT_LT(StackAddr(), stack_end);
}

TEST(ModuleList, Canned) {
  char maps[] = R"(
557c003a2000-557c003a4000 r--p 00000000 fe:01 11311406                   /usr/bin/cat
557c003a4000-557c003a9000 r-xp 00002000 fe:01 11311406                   /usr/bin/cat
557c003a9000-557c003ab000 r--p 00007000 fe:01 11311406                   /usr/bin/cat
557c003ac000-557c003ad000 r--p 00009000 fe:01 11311406                   /usr/bin/cat
557c003ad000-557c003ae000 rw-p 0000a000 fe:01 11311406                   /usr/bin/cat
557c004ce000-557c004ef000 rw-p 00000000 00:00 0                          [heap]
7f8cd4400000-7f8cd46e7000 r--p 00000000 fe:01 11272940                   /usr/lib/locale/locale-archive
7f8cd47de000-7f8cd4800000 rw-p 00000000 00:00 0 
7f8cd4800000-7f8cd4828000 r--p 00000000 fe:01 11538284                   /usr/lib/x86_64-linux-gnu/libc.so.6
7f8cd4828000-7f8cd4996000 r-xp 00028000 fe:01 11538284                   /usr/lib/x86_64-linux-gnu/libc.so.6
7f8cd4996000-7f8cd49ee000 r--p 00196000 fe:01 11538284                   /usr/lib/x86_64-linux-gnu/libc.so.6
7f8cd49ee000-7f8cd49f2000 r--p 001ed000 fe:01 11538284                   /usr/lib/x86_64-linux-gnu/libc.so.6
7f8cd49f2000-7f8cd49f4000 rw-p 001f1000 fe:01 11538284                   /usr/lib/x86_64-linux-gnu/libc.so.6
7f8cd49f4000-7f8cd4a01000 rw-p 00000000 00:00 0 
7f8cd4a0f000-7f8cd4a12000 rw-p 00000000 00:00 0 
7f8cd4a2b000-7f8cd4a2d000 rw-p 00000000 00:00 0 
7f8cd4a2d000-7f8cd4a2e000 r--p 00000000 fe:01 11545190                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f8cd4a2e000-7f8cd4a53000 r-xp 00001000 fe:01 11545190                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f8cd4a53000-7f8cd4a5d000 r--p 00026000 fe:01 11545190                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f8cd4a5d000-7f8cd4a5f000 r--p 0002f000 fe:01 11545190                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f8cd4a5f000-7f8cd4a61000 rw-p 00031000 fe:01 11545190                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffd68e80000-7ffd68ea1000 rw-p 00000000 00:00 0                          [stack]
7ffd68fb6000-7ffd68fba000 r--p 00000000 00:00 0                          [vvar]
7ffd68fba000-7ffd68fbc000 r-xp 00000000 00:00 0                          [vdso]
7ffd68fbc000-7ffd68fbd000 r-xp 00000000 fe:01 11311406                   /fake/module
7ffd68fbd000-7ffd68fbe000 r-xp 00000000 00:00 0                          [fake]
)";
  auto modules =
      internal::ParseModuleList(maps, 0x7f8cd4a2e001, 0x557c003a4001);
  EXPECT_EQ(modules.stack_start, 0x7f8cd4a61000);
  EXPECT_EQ(modules.stack_end, 0x7ffd68ea1000);
  EXPECT_EQ(modules.vdso_start, 0x7ffd68fba000);
  EXPECT_EQ(modules.vdso_end, 0x7ffd68fbc000);
  EXPECT_EQ(modules.own_start, 0x7f8cd4a2e000);
  EXPECT_EQ(modules.own_end, 0x7f8cd4a53000);

  auto* mod = modules.list;
  ASSERT_NE(mod, nullptr);
  EXPECT_STREQ(mod->name, "module");
  EXPECT_EQ(mod->start_address, 0x7ffd68fbc000);
  EXPECT_EQ(mod->end_address, 0x7ffd68fbd000);
  EXPECT_EQ(mod->pc_offset, 0x7ffd68fbc000);

  mod = mod->next;
  EXPECT_STREQ(mod->name, "[vdso]");
  EXPECT_EQ(mod->start_address, 0x7ffd68fba000);
  EXPECT_EQ(mod->end_address, 0x7ffd68fbc000);
  EXPECT_EQ(mod->pc_offset, 0x7ffd68fba000);

  mod = mod->next;
  ASSERT_NE(mod, nullptr);
  EXPECT_STREQ(mod->name, "ld-linux-x86-64.so.2");
  EXPECT_EQ(mod->start_address, 0x7f8cd4a2e000);
  EXPECT_EQ(mod->end_address, 0x7f8cd4a53000);
  EXPECT_EQ(mod->pc_offset, 0x7f8cd4a2d000);

  mod = mod->next;
  ASSERT_NE(mod, nullptr);
  EXPECT_STREQ(mod->name, "libc.so.6");
  EXPECT_EQ(mod->start_address, 0x7f8cd4828000);
  EXPECT_EQ(mod->end_address, 0x7f8cd4996000);
  EXPECT_EQ(mod->pc_offset, 0x7f8cd4800000);

  mod = mod->next;
  ASSERT_NE(mod, nullptr);
  EXPECT_STREQ(mod->name, "cat");
  EXPECT_EQ(mod->start_address, 0x557c003a4000);
  EXPECT_EQ(mod->end_address, 0x557c003a9000);
  EXPECT_EQ(mod->pc_offset, 0x557c003a2000);

  ASSERT_EQ(mod->next, nullptr);
}

}  // namespace
}  // namespace gwpsan
