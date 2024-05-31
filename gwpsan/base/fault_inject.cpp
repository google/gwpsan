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

#if defined(GWPSAN_FAULT_INJECT) || GWPSAN_DEBUG
#include "gwpsan/base/fault_inject.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/numeric.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/synchronization.h"

namespace gwpsan {
namespace {
#ifdef GWPSAN_FAULT_INJECT
static_assert(GWPSAN_FAULT_INJECT > 5,
              "Fault injection inverse probability must be greater than 5");
constexpr uptr kUnlikelyInverseProb = GWPSAN_FAULT_INJECT;
constexpr uptr kLikelyInverseProb = kUnlikelyInverseProb / 5;  // 5x more likely
#else   // GWPSAN_FAULT_INJECT
// Choose a sane default for debug builds.
constexpr uptr kLikelyInverseProb = 128;
#endif  // GWPSAN_FAULT_INJECT

SAN_THREAD_LOCAL int fault_inject_disable_count;
bool fault_inject_disabled;

bool FaultInjectRand(uptr inverse_prob) {
  static constinit bool init;
  static constinit OptionalBase<Rand> rand;

  if (fault_inject_disable_count)
    return false;

  if (__atomic_load_n(&fault_inject_disabled, __ATOMIC_RELAXED))
    return false;

  // Double-checked locking.
  if (!__atomic_load_n(&init, __ATOMIC_ACQUIRE)) {
    static constinit Mutex init_mu;
    TryLock lock(init_mu);
    if (!lock)
      return false;
    if (!__atomic_load_n(&init, __ATOMIC_ACQUIRE))
      rand.emplace();
    __atomic_store_n(&init, true, __ATOMIC_RELEASE);
  }

  return rand->OneOf(inverse_prob);
}
}  // namespace

void FaultInjectDisableCurrent() {
  SAN_CHECK_GE(fault_inject_disable_count, 0);
  fault_inject_disable_count++;
}

void FaultInjectEnableCurrent() {
  SAN_CHECK_GT(fault_inject_disable_count, 0);
  fault_inject_disable_count--;
}

void FaultInjectDisableGlobal() {
  __atomic_store_n(&fault_inject_disabled, true, __ATOMIC_RELAXED);
}

bool FaultInjectLikely() {
  return FaultInjectRand(kLikelyInverseProb);
}

#ifdef GWPSAN_FAULT_INJECT
static_assert(!GWPSAN_DEBUG,
              "Unlikely-fault injection triggers too many debug-only checks");
bool FaultInjectUnlikely() {
  return FaultInjectRand(kUnlikelyInverseProb);
}
#endif  // GWPSAN_FAULT_INJECT

}  // namespace gwpsan
#endif  // GWPSAN_FAULT_INJECT || GWPSAN_DEBUG
