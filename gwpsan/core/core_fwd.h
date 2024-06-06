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

#ifndef GWPSAN_CORE_CORE_FWD_H_
#define GWPSAN_CORE_CORE_FWD_H_

namespace gwpsan {

class Arg;
class Breakpoint;
class CPUContext;
class Env;
class Instr;
class InstrSequence;
class InstructionOrigin;
class Meta;
class Operation;
class Origin;
class OriginChain;
struct Word;
struct MemAccess;
using OpRef = const Operation&;

}  // namespace gwpsan

#endif  // GWPSAN_CORE_CORE_FWD_H_
