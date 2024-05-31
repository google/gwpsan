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

#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/uar/uar.h"

typedef int (*pthread_create_t)(pthread_t* thread, const pthread_attr_t* attr,
                                void* (*start_routine)(void*), void* arg);
typedef int (*pthread_attr_copy_t)(pthread_attr_t*, const pthread_attr_t*);
SAN_WEAK_IMPORT extern "C" int __pthread_create_2_1(pthread_t*,
                                                    const pthread_attr_t*,
                                                    void* (*)(void*), void*);
SAN_WEAK_IMPORT extern "C" int __pthread_attr_copy(pthread_attr_t*,
                                                   const pthread_attr_t*);
SAN_DECLARE_INTERCEPTOR(int, pthread_create, pthread_t* thread,
                        const pthread_attr_t* attr,
                        void* (*start_routine)(void*), void* arg);

namespace gwpsan {
namespace {

int pthread_attr_copy_impl(pthread_attr_t* dst, const pthread_attr_t* src) {
  // Copy all attributes from src to dst.
  // This is potentially problematic b/c new portable or non-portable
  // attributes may be added and we won't copy them. So we use this function
  // only if __pthread_attr_copy is not available (but usually it's not
  // available in dynamic builds).
  // Note: we checked that pthread_attr_getstack is not set.
  size_t stacksize = 0;
  if (pthread_attr_getstacksize(src, &stacksize) ||
      pthread_attr_setstacksize(dst, stacksize)) {
    SAN_LOG("pthread_attr_getstacksize failed");
    return -1;
  }
  size_t guardsize = 0;
  if (pthread_attr_getguardsize(src, &guardsize) ||
      pthread_attr_setguardsize(dst, guardsize)) {
    SAN_LOG("pthread_attr_getguardsize failed");
    return -1;
  }
  int inheritsched = 0;
  if (pthread_attr_getinheritsched(src, &inheritsched) ||
      pthread_attr_setinheritsched(dst, inheritsched)) {
    SAN_LOG("pthread_attr_getinheritsched failed");
    return -1;
  }
  int scope = 0;
  if (pthread_attr_getscope(src, &scope) || pthread_attr_setscope(dst, scope)) {
    SAN_LOG("pthread_attr_getscope failed");
    return -1;
  }
  int detachstate = 0;
  if (pthread_attr_getdetachstate(src, &detachstate) ||
      pthread_attr_setdetachstate(dst, detachstate)) {
    SAN_LOG("pthread_attr_getdetachstate failed");
    return -1;
  }
  int policy = 0;
  if (pthread_attr_getschedpolicy(src, &policy) ||
      pthread_attr_setschedpolicy(dst, policy)) {
    SAN_LOG("pthread_attr_getschedpolicy failed");
    return -1;
  }
  struct sched_param sched_param;
  if (pthread_attr_getschedparam(src, &sched_param) ||
      pthread_attr_setschedparam(dst, &sched_param)) {
    SAN_LOG("pthread_attr_getschedparam failed");
    return -1;
  }
  cpu_set_t cpu_set;
  if (pthread_attr_getaffinity_np(src, sizeof(cpu_set), &cpu_set) ||
      pthread_attr_setaffinity_np(dst, sizeof(cpu_set), &cpu_set)) {
    SAN_LOG("pthread_attr_getaffinity_np failed");
    return -1;
  }
  // Note: pthread_attr_get/setsigmask_np are not defined in grte.
  static const auto getsigmask =
      reinterpret_cast<int (*)(const pthread_attr_t* attr, sigset_t* sigmask)>(
          dlsym(RTLD_DEFAULT, "pthread_attr_getsigmask_np"));
  static const auto setsigmask =
      reinterpret_cast<int (*)(pthread_attr_t* attr, const sigset_t* sigmask)>(
          dlsym(RTLD_DEFAULT, "pthread_attr_setsigmask_np"));
  if (getsigmask && setsigmask) {
    sigset_t seg_set;
    // Note: pthread_attr_getsigmask_np returns either 0 (sig_set is returned)
    // or PTHREAD_ATTR_NO_SIGMASK_NP (-1), which means seg_set is not returned
    // and we don't need to copy it.
    if (getsigmask(src, &seg_set) == 0 && setsigmask(dst, &seg_set)) {
      SAN_LOG("pthread_attr_getsigmask_np failed");
      return -1;
    }
  }
  return 0;
}

int pthread_attr_copy(pthread_attr_t* dst, const pthread_attr_t* src) {
  if (pthread_attr_init(dst))
    return -1;
  if (pthread_attr_copy_impl(dst, src)) {
    pthread_attr_destroy(dst);
    return -1;
  }
  return 0;
}

pthread_create_t resolve_pthread_create() {
  // Try sanitizer interceptor first.
  if (___interceptor_pthread_create)
    return ___interceptor_pthread_create;
  auto fn =
      reinterpret_cast<pthread_create_t>(dlsym(RTLD_NEXT, "pthread_create"));
  if (fn)
    return fn;
  // If the binary is statically linked dlsym won't work.
  // Fortunately pthread contains an alias symbol that we can use.
  if (__pthread_create_2_1)
    return __pthread_create_2_1;
  // Terminate b/c we can't handle the pthread_create call.
  SAN_BUG("dlsym(\"pthread_create\") failed (%s)", dlerror());
}

pthread_attr_copy_t resolve_pthread_attr_copy() {
  // __pthread_attr_copy is an internal pthread symbol that we can access
  // only if the pthread library is linked statically.
  if (__pthread_attr_copy)
    return __pthread_attr_copy;
  return pthread_attr_copy;
}

}  // namespace

SAN_INTERFACE int __interceptor_pthread_create(pthread_t* thread,
                                               const pthread_attr_t* attr,
                                               void* (*start_routine)(void*),
                                               void* arg) {
  static auto real_pthread_create = resolve_pthread_create();
  static auto real_pthread_attr_copy = resolve_pthread_attr_copy();
  pthread_attr_t copy;
  bool destroy = false;
  // Note: UarDetector singleton is created very early, and there should be no
  // other threads running yet that could call pthread_create() concurrently
  // with singleton construction (otherwise we need and_then_sync()).
  UarDetector::singleton().and_then([&](auto& uar) {
    if (uar.ShouldSampleThread(attr)) {
      if ((!attr && !pthread_attr_init(&copy)) ||
          (attr && !real_pthread_attr_copy(&copy, attr))) {
        destroy = true;
        if (uar.ModifyThread(&copy, &start_routine, &arg))
          attr = &copy;
      }
    }
  });
  int res = real_pthread_create(thread, attr, start_routine, arg);
  if (destroy)
    SAN_WARN(pthread_attr_destroy(&copy));
  return res;
}

}  // namespace gwpsan
