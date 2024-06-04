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

// Most of our code is (non-test) runtime code. Usage of standard libraries used
// by the program being analyzed has several issues:
//
//  1. We need to ensure that the code run in signal handlers is signal-handler
//     safe, e.g. no deadlocks due to taken locks. For example this precludes us
//     from using standard allocators, should we want to analyze them, too.
//
//  2. We need to avoid signal handler recursion, which could happen if standard
//     library code being analyzed (by having breakpoints set in them) is itself
//     used in our signal handler that was triggered by a breakpoint.
//
//  3. We must avoid ODR violations in C++ template libraries. Our runtime
//     uses subtly different compiler flags, in particular the code being
//     analyzed should be compiled with -fsanitize-metadata, whereas our code
//     must be compiled with -fno-sanitize-metadata to avoid self-analysis. This
//     means that pretty much _all_ of the C++ STL cannot be used.
//
// This header provides sanity checking for some of these rules.

// IWYU pragma: private

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_STDLIB_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_STDLIB_H_
#ifndef GWPSAN_TEST

namespace gwpsan {

// Use function object to avoid ADL (which would result in false negatives).
struct DisallowExternalFunc {
  struct AnyRet {
    template <typename T>
    operator T();
  };
  template <typename... Args>
  AnyRet operator()(Args...) const;
  DisallowExternalFunc(const DisallowExternalFunc&) = delete;
  DisallowExternalFunc& operator=(const DisallowExternalFunc&) = delete;
};
#define SAN_DISALLOW_FUNCTION(name)                                          \
  extern DisallowExternalFunc name __attribute__((                           \
      unavailable("Cannot use " #name "() directly - use SAN_LIBCALL(" #name \
                  "(...)) (or ::" #name " for non-calls)")));
#include "gwpsan/base/stdlib_disallow.inc"

// The pattern "SAN_.*_FUNCTION" is used by stdlib_disallow_update.sh producing
// stdlib_disallow.inc to exclude functions explicitly listed here.
// Rerun stdlib_disallow_update.sh on changes to the below list.
#define SAN_ALLOW_FUNCTION(name)  // Document reason...

// -----------------------------------------------------------------------------

SAN_ALLOW_FUNCTION(getauxval);  // Only used during init on x86.

SAN_ALLOW_FUNCTION(abort);  // Only used by abort_on_error.

// The below functions are used by uar/interceptors.cpp, which are never
// executed in signal handlers, and therefore safe to use.
SAN_ALLOW_FUNCTION(dlerror);
SAN_ALLOW_FUNCTION(dlsym);
SAN_ALLOW_FUNCTION(pthread_attr_destroy);
SAN_ALLOW_FUNCTION(pthread_attr_getaffinity_np);
SAN_ALLOW_FUNCTION(pthread_attr_getdetachstate);
SAN_ALLOW_FUNCTION(pthread_attr_getguardsize);
SAN_ALLOW_FUNCTION(pthread_attr_getinheritsched);
SAN_ALLOW_FUNCTION(pthread_attr_getschedparam);
SAN_ALLOW_FUNCTION(pthread_attr_getschedpolicy);
SAN_ALLOW_FUNCTION(pthread_attr_getscope);
SAN_ALLOW_FUNCTION(pthread_attr_getstacksize);
SAN_ALLOW_FUNCTION(pthread_attr_init);
SAN_ALLOW_FUNCTION(pthread_attr_setaffinity_np);
SAN_ALLOW_FUNCTION(pthread_attr_setdetachstate);
SAN_ALLOW_FUNCTION(pthread_attr_setguardsize);
SAN_ALLOW_FUNCTION(pthread_attr_setinheritsched);
SAN_ALLOW_FUNCTION(pthread_attr_setschedparam);
SAN_ALLOW_FUNCTION(pthread_attr_setschedpolicy);
SAN_ALLOW_FUNCTION(pthread_attr_setscope);
SAN_ALLOW_FUNCTION(pthread_attr_setstacksize);
SAN_ALLOW_FUNCTION(pthread_self);

// TODO(elver): Review if below use from signals handlers is safe.
//
// Can be used in signal handler by msan by calling
// BreakManager::CallbackDisable() and CallbackEnable().
SAN_ALLOW_FUNCTION(sigaddset);
SAN_ALLOW_FUNCTION(sigdelset);
SAN_ALLOW_FUNCTION(sigemptyset);
SAN_ALLOW_FUNCTION(sigprocmask);
// Used from signal handler by BreakManager::DispatchCallback().
SAN_ALLOW_FUNCTION(pthread_setspecific);

// -----------------------------------------------------------------------------

}  // namespace gwpsan

#endif  // GWPSAN_TEST
#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_STDLIB_H_
