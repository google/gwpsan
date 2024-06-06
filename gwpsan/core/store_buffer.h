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

#ifndef GWPSAN_CORE_STORE_BUFFER_H_
#define GWPSAN_CORE_STORE_BUFFER_H_

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/meta.h"

namespace gwpsan SAN_LOCAL {

// StoreBuffer holds past stores to satisfy subsequent loads during emulation.
// It has fixed capacity and can produce incorrect results on overflow.
class StoreBuffer {
 public:
  void Store(Addr addr, ByteSize size, uptr val) {
    size = min(size, Sizeof(val));
    buffer_[pos_++ % buffer_.size()] = MemAccess{0, addr, size, {val}};
  }

  // Forward updates and returns the value val loaded from addr/size
  // based on the previous stores. Since we emulated previous stores
  // the value in memory misses side-effects of these stores.
  // Forward returns the value what would be in memory if the stores
  // would actually happen.
  uptr Forward(Addr addr, ByteSize size, uptr val);

 private:
  // Since we have to use fixed space and cannot memorize all stores,
  // we use a ring buffer with the most recent stores only.
  Array<MemAccess, 16> buffer_;
  uptr pos_ = 0;
};

}  // namespace gwpsan SAN_LOCAL

#endif
