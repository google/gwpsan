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

#ifndef GWPSAN_BASE_ENV_H_
#define GWPSAN_BASE_ENV_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"

namespace gwpsan SAN_LOCAL {

// Copies `size` bytes from `src` to `dst`; if the copy was completed, returns
// true, false if an access fault occurred during the copy.
bool NonFailingMemcpy(void* dst, const void* src, uptr size);

inline bool NonFailingLoad(Addr addr, ByteSize size, void* dst) {
  auto* src = reinterpret_cast<void*>(Bytes(addr));
  return NonFailingMemcpy(dst, src, Bytes(size));
}

inline bool NonFailingStore(Addr addr, ByteSize size, const void* src) {
  auto* dst = reinterpret_cast<void*>(Bytes(addr));
  return NonFailingMemcpy(dst, src, Bytes(size));
}

bool InitNonFailing();
bool HandleNonFailingAccess(int sig, void* uctx);

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_ENV_H_
