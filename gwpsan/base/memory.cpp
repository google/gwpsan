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

#include "gwpsan/base/memory.h"

#include <stddef.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/synchronization.h"

namespace gwpsan {

DEFINE_METRIC(heap_alloc, 0, "Heap bytes allocated by GWPSan");
DEFINE_METRIC(heap_free, 0, "Heap bytes freed by GWPSan");
DEFINE_METRIC(heap_current, 0, "Currently allocated heap bytes by GWPSan");

void AccountHeapAlloc(uptr size) {
  metric_heap_alloc.LossyAdd(size);
  metric_heap_current.LossyAdd(size);
}

void AccountHeapFree(uptr size) {
  metric_heap_free.LossyAdd(size);
  metric_heap_current.LossyAdd(-size);
}

char* PersistentAlloc(uptr size) {
  size = RoundUpTo(size, alignof(max_align_t));

  // Special fast path case for multiple of page-size allocations.
  if (size % kPageSize == 0)
    return Mmap(size);

  static Mutex mu;
  static char* cache;
  static uptr remain;

  Lock lock(mu);
  if (remain < size) {
    const uptr num_pages = size / kPageSize + 1;
    const uptr alloc_size = num_pages * kPageSize;
    cache = Mmap(alloc_size);
    if (SAN_UNLIKELY(!cache)) {
      // We ran out of memory. Inform the user that they should try again
      // without GWPSan.
      SAN_BUG(
          "Out of memory! Try again without GWPSan: export "
          "GWPSAN_OPTIONS=sample_interval_usec=0");
    }
    remain = alloc_size;
  }
  char* res = cache;
  cache += size;
  remain -= size;
  return res;
}

char* PersistentStrDup(const char* str) {
  uptr len = internal_strlen(str);
  char* dup = PersistentAlloc(len + 1);
  internal_memcpy(dup, str, len + 1);
  return dup;
}

}  // namespace gwpsan
