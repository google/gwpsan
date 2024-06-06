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

#ifndef GWPSAN_BASE_SYSCALL_ARM64_H_
#define GWPSAN_BASE_SYSCALL_ARM64_H_

// IWYU pragma: private, include "gwpsan/base/syscall.h"

#define GWPSAN_SYSCALL0(type, name)                                          \
  inline Result<type> sys_##name() {                                         \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                       \
    register uptr res __asm__("x0");                                         \
    register uptr __sysreg __asm__("x8") = SYS_##name;                       \
    do                                                                       \
      asm volatile("svc 0" : "=r"(res) : [sysreg] "r"(__sysreg) : "memory"); \
    while (res == -EINTR);                                                   \
    return Result<type>(static_cast<uptr>(res));                             \
  }
#define GWPSAN_SYSCALL1(type, name, type0, arg0)        \
  inline Result<type> sys_##name(type0 arg0) {          \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                  \
    register uptr res __asm__("x0");                    \
    register uptr x8 __asm__("x8") = SYS_##name;        \
    register uptr x0 __asm__("x0") = (uptr)arg0;        \
    do                                                  \
      asm volatile("svc 0"                              \
                   : "=r"(res)                          \
                   : [sysreg] "r"(x8), "r"(x0), "r"(x0) \
                   : "memory");                         \
    while (res == -EINTR);                              \
    return Result<type>(static_cast<uptr>(res));        \
  }
#define GWPSAN_SYSCALL2(type, name, type0, arg0, type1, arg1)    \
  inline Result<type> sys_##name(type0 arg0, type1 arg1) {       \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                           \
    register uptr res __asm__("x0");                             \
    register uptr x8 __asm__("x8") = SYS_##name;                 \
    register uptr x0 __asm__("x0") = (uptr)arg0;                 \
    register uptr x1 __asm__("x1") = (uptr)arg1;                 \
    do                                                           \
      asm volatile("svc 0"                                       \
                   : "=r"(res)                                   \
                   : [sysreg] "r"(x8), "r"(x0), "r"(x0), "r"(x1) \
                   : "memory");                                  \
    while (res == -EINTR);                                       \
    return Result<type>(static_cast<uptr>(res));                 \
  }
#define GWPSAN_SYSCALL3(type, name, type0, arg0, type1, arg1, type2, arg2) \
  inline Result<type> sys_##name(type0 arg0, type1 arg1, type2 arg2) {     \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                     \
    register uptr res __asm__("x0");                                       \
    register uptr x8 __asm__("x8") = SYS_##name;                           \
    register uptr x0 __asm__("x0") = (uptr)arg0;                           \
    register uptr x1 __asm__("x1") = (uptr)arg1;                           \
    register uptr x2 __asm__("x2") = (uptr)arg2;                           \
    do                                                                     \
      asm volatile("svc 0"                                                 \
                   : "=r"(res)                                             \
                   : [sysreg] "r"(x8), "r"(x0), "r"(x0), "r"(x1), "r"(x2)  \
                   : "memory");                                            \
    while (res == -EINTR);                                                 \
    return Result<type>(static_cast<uptr>(res));                           \
  }
#define GWPSAN_SYSCALL4(type, name, type0, arg0, type1, arg1, type2, arg2, \
                        type3, arg3)                                       \
  inline Result<type> sys_##name(type0 arg0, type1 arg1, type2 arg2,       \
                                 type3 arg3) {                             \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                     \
    register uptr res __asm__("x0");                                       \
    register uptr x8 __asm__("x8") = SYS_##name;                           \
    register uptr x0 __asm__("x0") = (uptr)arg0;                           \
    register uptr x1 __asm__("x1") = (uptr)arg1;                           \
    register uptr x2 __asm__("x2") = (uptr)arg2;                           \
    register uptr x3 __asm__("x3") = (uptr)arg3;                           \
    do                                                                     \
      asm volatile("svc 0"                                                 \
                   : "=r"(res)                                             \
                   : [sysreg] "r"(x8), "r"(x0), "r"(x0), "r"(x1), "r"(x2), \
                     "r"(x3)                                               \
                   : "memory");                                            \
    while (res == -EINTR);                                                 \
    return Result<type>(static_cast<uptr>(res));                           \
  }
#define GWPSAN_SYSCALL5(type, name, type0, arg0, type1, arg1, type2, arg2, \
                        type3, arg3, type4, arg4)                          \
  inline Result<type> sys_##name(type0 arg0, type1 arg1, type2 arg2,       \
                                 type3 arg3, type4 arg4) {                 \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                     \
    register uptr res __asm__("x0");                                       \
    register uptr x8 __asm__("x8") = SYS_##name;                           \
    register uptr x0 __asm__("x0") = (uptr)arg0;                           \
    register uptr x1 __asm__("x1") = (uptr)arg1;                           \
    register uptr x2 __asm__("x2") = (uptr)arg2;                           \
    register uptr x3 __asm__("x3") = (uptr)arg3;                           \
    register uptr x4 __asm__("x4") = (uptr)arg4;                           \
    do                                                                     \
      asm volatile("svc 0"                                                 \
                   : "=r"(res)                                             \
                   : [sysreg] "r"(x8), "r"(x0), "r"(x0), "r"(x1), "r"(x2), \
                     "r"(x3), "r"(x4)                                      \
                   : "memory");                                            \
    while (res == -EINTR);                                                 \
    return Result<type>(static_cast<uptr>(res));                           \
  }
#define GWPSAN_SYSCALL6(type, name, type0, arg0, type1, arg1, type2, arg2, \
                        type3, arg3, type4, arg4, type5, arg5)             \
  inline Result<type> sys_##name(type0 arg0, type1 arg1, type2 arg2,       \
                                 type3 arg3, type4 arg4, type5 arg5) {     \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                     \
    register uptr res __asm__("x0");                                       \
    register uptr x8 __asm__("x8") = SYS_##name;                           \
    register uptr x0 __asm__("x0") = (uptr)arg0;                           \
    register uptr x1 __asm__("x1") = (uptr)arg1;                           \
    register uptr x2 __asm__("x2") = (uptr)arg2;                           \
    register uptr x3 __asm__("x3") = (uptr)arg3;                           \
    register uptr x4 __asm__("x4") = (uptr)arg4;                           \
    register uptr x5 __asm__("x5") = (uptr)arg5;                           \
    do                                                                     \
      asm volatile("svc 0"                                                 \
                   : "=r"(res)                                             \
                   : [sysreg] "r"(x8), "r"(x0), "r"(x0), "r"(x1), "r"(x2), \
                     "r"(x3), "r"(x4), "r"(x5)                             \
                   : "memory");                                            \
    while (res == -EINTR);                                                 \
    return Result<type>(static_cast<uptr>(res));                           \
  }

#endif  // GWPSAN_BASE_SYSCALL_ARM64_H_
