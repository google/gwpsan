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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_DECODE_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_DECODE_H_

#include "gwpsan/base/common.h"

#if GWPSAN_X64
#include "gwpsan/core/decoder_x86.h"
#elif GWPSAN_ARM64
#include "gwpsan/core/decoder_arm64.h"
#endif

namespace gwpsan SAN_LOCAL {

#if GWPSAN_X64
using ArchDecoder = X86Decoder;
#elif GWPSAN_ARM64
using ArchDecoder = Arm64Decoder;
#endif

void DumpInstructions();

}  // namespace gwpsan SAN_LOCAL

#endif
