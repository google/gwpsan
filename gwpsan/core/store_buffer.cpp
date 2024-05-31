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

#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"

namespace gwpsan {

uptr StoreBuffer::Forward(Addr addr, ByteSize size, uptr val) {
  // Replay stores from the oldest one to the newest one and copy bits
  // that overlap with the loaded value. This gives us the right value
  // even with arbitrary overlapping stores.
  size = min(size, Sizeof(val));
  for (uptr i = 0; i < buffer_.size(); i++) {
    const auto& store = buffer_[(pos_ + i) % buffer_.size()];
    auto off = store.addr - addr;
    if (off >= size)
      continue;
    auto n = min(store.size, size - off);
    internal_memcpy(reinterpret_cast<char*>(&val) + Bytes(off), &store.val.val,
                    Bytes(n));
  }
  return val;
}

}  // namespace gwpsan
