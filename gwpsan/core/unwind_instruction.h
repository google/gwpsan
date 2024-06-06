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

#ifndef GWPSAN_CORE_UNWIND_INSTRUCTION_H_
#define GWPSAN_CORE_UNWIND_INSTRUCTION_H_

#include "gwpsan/base/common.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/core_fwd.h"

namespace gwpsan SAN_LOCAL {

// UnwindInstruction is used on x86 to work-around the following problem.
// On x86 data watchpoints fire on the next instruction.
// This is very unfortunate since we can't emulate the memory accessing
// instruction and don't know what was loaded/stored and where it is now
// (e.g. in what register). UnwindInstruction tries to find the previous
// instruction and restore the context as it was before the previous
// instruction executed. This is not possible to do reliaby,
// UnwindInstruction return false if it fails.
bool UnwindInstruction(CPUContext& ctx, Breakpoint::Info bpinfo);

// Copies up to kMaxInstrLen bytes preceeding pc into buf and returns
// number of bytes copied. May copy less if some of the bytes are located
// on an inacessible page. In such case the copied bytes are located
// at the end of the buf.
uptr CopyPreceedingCode(uptr pc, u8* buf);

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_CORE_UNWIND_INSTRUCTION_H_
