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
    const auto store_end = store.addr + store.size;
    const auto load_end = addr + size;
    // Note: we can't subtract store.addr from addr directly because both are
    // unsigned and a store that starts before the load would underflow.
    const auto overlap_start = max(store.addr, addr);
    if (overlap_start >= min(store_end, load_end))
      continue;  // no overlap
    // Byte offsets of the overlapping part relative to the start of the
    // load value and of the store value.
    const auto load_off = overlap_start - addr;
    const auto store_off = overlap_start - store.addr;
    const auto n = min(store_end, load_end) - overlap_start;
    internal_memcpy(reinterpret_cast<char*>(&val) + Bytes(load_off),
                    reinterpret_cast<const char*>(&store.val.val) +
                        Bytes(store_off),
                    Bytes(n));
  }
  return val;
}

}  // namespace gwpsan
