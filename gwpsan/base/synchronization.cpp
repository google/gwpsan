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

#include "gwpsan/base/synchronization.h"

#include <linux/futex.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/syscall.h"

namespace gwpsan {

SAN_NOINLINE void Semaphore::Wait() {
  u32 count = __atomic_load_n(&state_, __ATOMIC_RELAXED);
  for (;;) {
    if (count == 0) {
      sys_futex(&state_, FUTEX_WAIT_PRIVATE, 0);
      count = __atomic_load_n(&state_, __ATOMIC_RELAXED);
      continue;
    }
    if (__atomic_compare_exchange_n(&state_, &count, count - 1, true,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
      break;
  }
}

SAN_NOINLINE void Semaphore::Post(u32 count) {
  SAN_CHECK_NE(count, 0);
  __atomic_fetch_add(&state_, count, __ATOMIC_RELEASE);
  sys_futex(&state_, FUTEX_WAKE_PRIVATE, count);
}

void OptionalSyncMultipleAccess::Emplace() {
  // Release visibility over object to the increment in Acquire().
  SAN_CHECK_EQ(__atomic_exchange_n(&refs_, kInit, __ATOMIC_RELEASE), 0);
}

void OptionalSyncMultipleAccess::ResetBegin() {
  // Wait for all in-flight Optional::and_then_sync() users to finish. Because
  // `refs_` is below kInit, new users won't use the object. Pairs with the
  // decrement in Release().
  if (SAN_UNLIKELY(__atomic_fetch_sub(&refs_, kInit, __ATOMIC_RELAXED) !=
                   kInit))
    sem_.Wait();
}

void OptionalSyncMultipleAccess::ResetEnd() {
  SAN_CHECK_EQ(__atomic_load_n(&refs_, __ATOMIC_RELAXED), 0);
}

}  // namespace gwpsan
