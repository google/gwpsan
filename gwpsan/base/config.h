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

#ifndef GWPSAN_BASE_CONFIG_H_
#define GWPSAN_BASE_CONFIG_H_

// IWYU pragma: private, include "gwpsan/base/common.h"

// Allow optimized builds to override GWPSAN_DEBUG with build options. The
// default for optimized builds is no debugging checks.
#if GWPSAN_OPTIMIZE && !defined(GWPSAN_DEBUG)
#define GWPSAN_DEBUG 0
#endif

#if defined(__x86_64__)
#define GWPSAN_X64 1
#else
#define GWPSAN_X64 0
#endif

#if defined(__aarch64__)
#define GWPSAN_ARM64 1
#else
#define GWPSAN_ARM64 0
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#define GWPSAN_INSTRUMENTED_ASAN 1
#else
#define GWPSAN_INSTRUMENTED_ASAN 0
#endif

#if __has_feature(hwaddress_sanitizer) || defined(__SANITIZE_HWADDRESS__)
#define GWPSAN_INSTRUMENTED_HWASAN 1
#else
#define GWPSAN_INSTRUMENTED_HWASAN 0
#endif

#if __has_feature(memory_sanitizer) || defined(__SANITIZE_MEMORY__)
#define GWPSAN_INSTRUMENTED_MSAN 1
#else
#define GWPSAN_INSTRUMENTED_MSAN 0
#endif

#if __has_feature(thread_sanitizer) || defined(__SANITIZE_THREAD__)
#define GWPSAN_INSTRUMENTED_TSAN 1
#else
#define GWPSAN_INSTRUMENTED_TSAN 0
#endif

#define GWPSAN_INSTRUMENTED_DFSAN __has_feature(dataflow_sanitizer)
#define GWPSAN_INSTRUMENTED_UBSAN __has_feature(undefined_behavior_sanitizer)
#define GWPSAN_INSTRUMENTED_COVSAN __has_feature(coverage_sanitizer)

// GWPSan inherently conflicts with compiler-based instrumentation tools - list
// all of potential conflicting tools here.
#define GWPSAN_INSTRUMENTED                                  \
  (GWPSAN_INSTRUMENTED_ASAN || GWPSAN_INSTRUMENTED_HWASAN || \
   GWPSAN_INSTRUMENTED_MSAN || GWPSAN_INSTRUMENTED_TSAN ||   \
   GWPSAN_INSTRUMENTED_DFSAN || GWPSAN_INSTRUMENTED_UBSAN || \
   GWPSAN_INSTRUMENTED_COVSAN)

#endif  // GWPSAN_BASE_CONFIG_H_
