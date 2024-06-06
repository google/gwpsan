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

#ifndef GWPSAN_BASE_FAULT_INJECT_H_
#define GWPSAN_BASE_FAULT_INJECT_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

// If GWPSAN_FAULT_INJECT is not defined, we only enable likely fault injection
// with a fixed probability of 1/128.
//
// We do not want to compile unlikely-fault injection in by default to avoid
// either accidental or malicous enablement in production. To test with unlikely
// fault injection, compile the whole project with:
//
//    GWPSAN_FAULT_INJECT=<inverse-prob>
//
// Where the constant <inverse-prob> is the inverse probability of an "unlikely"
// fault occurring, i.e. a fault will occur with probability 1/<inverse-prob>.
// "Likely" faults are 5x more likely (1/<inverse_prob> * 5).

#if defined(GWPSAN_FAULT_INJECT) || GWPSAN_DEBUG
// Disables all fault injection for the current thread.
void FaultInjectDisableCurrent();
// Re-enables all fault injection for the current thread.
void FaultInjectEnableCurrent();
// Disables fault injection globally.
void FaultInjectDisableGlobal();

// Returns true if a fault should be injected. Use this for likely faults.
//
// Note: In debugging mode, enable likely-fault injection by default. These
// types of faults may happen more frequently in production.
bool FaultInjectLikely();
#else   // GWPSAN_FAULT_INJECT
inline void FaultInjectDisableCurrent() {}
inline void FaultInjectEnableCurrent() {}
inline void FaultInjectDisableGlobal() {}

inline bool FaultInjectLikely() {
  return false;
}
#endif  // GWPSAN_FAULT_INJECT || GWPSAN_DEBUG

#ifdef GWPSAN_FAULT_INJECT
bool FaultInjectUnlikely();
#else   // GWPSAN_FAULT_INJECT
inline bool FaultInjectUnlikely() {
  return false;
}
#endif  // GWPSAN_FAULT_INJECT

// Scoped disables of fault injection for the current thread.
class ScopedFaultInjectDisable {
 public:
  ScopedFaultInjectDisable() {
    FaultInjectDisableCurrent();
  }
  ~ScopedFaultInjectDisable() {
    FaultInjectEnableCurrent();
  }

 private:
  ScopedFaultInjectDisable(const ScopedFaultInjectDisable&) = delete;
  ScopedFaultInjectDisable& operator=(const ScopedFaultInjectDisable&) = delete;
};

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_FAULT_INJECT_H_
