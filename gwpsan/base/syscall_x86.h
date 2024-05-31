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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_SYSCALL_X86_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_SYSCALL_X86_H_

// IWYU pragma: private, include "gwpsan/base/syscall.h"

#define GWPSAN_SYSCALL0(type, name)           \
  inline Result<type> sys_##name() {          \
    GWPSAN_FAULT_INJECT_SYSCALL(type);        \
    uptr res;                                 \
    do                                        \
      asm volatile("syscall"                  \
                   : "=a"(res)                \
                   : "0"(SYS_##name)          \
                   : "r11", "rcx", "memory"); \
    while (res == -EINTR);                    \
    return Result<type>(res);                 \
  }
#define GWPSAN_SYSCALL1(type, name, type0, arg0)        \
  inline Result<type> sys_##name(type0 arg0) {          \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                  \
    uptr res;                                           \
    do                                                  \
      asm volatile("syscall"                            \
                   : "=a"(res)                          \
                   : "0"(SYS_##name), "D"((long)(arg0)) \
                   : "r11", "rcx", "memory");           \
    while (res == -EINTR);                              \
    return Result<type>(res);                           \
  }
#define GWPSAN_SYSCALL2(type, name, type0, arg0, type1, arg1)              \
  inline Result<type> sys_##name(type0 arg0, type1 arg1) {                 \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                     \
    uptr res;                                                              \
    do                                                                     \
      asm volatile("syscall"                                               \
                   : "=a"(res)                                             \
                   : "0"(SYS_##name), "D"((long)(arg0)), "S"((long)(arg1)) \
                   : "r11", "rcx", "memory");                              \
    while (res == -EINTR);                                                 \
    return Result<type>(res);                                              \
  }
#define GWPSAN_SYSCALL3(type, name, type0, arg0, type1, arg1, type2, arg2)  \
  inline Result<type> sys_##name(type0 arg0, type1 arg1, type2 arg2) {      \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                      \
    uptr res;                                                               \
    do                                                                      \
      asm volatile("syscall"                                                \
                   : "=a"(res)                                              \
                   : "0"(SYS_##name), "D"((long)(arg0)), "S"((long)(arg1)), \
                     "d"((long)(arg2))                                      \
                   : "r11", "rcx", "memory");                               \
    while (res == -EINTR);                                                  \
    return Result<type>(res);                                               \
  }
#define GWPSAN_SYSCALL4(type, name, type0, arg0, type1, arg1, type2, arg2,  \
                        type3, arg3)                                        \
  inline Result<type> sys_##name(type0 arg0, type1 arg1, type2 arg2,        \
                                 type3 arg3) {                              \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                      \
    uptr res;                                                               \
    do                                                                      \
      asm volatile("movq %5,%%r10; syscall"                                 \
                   : "=a"(res)                                              \
                   : "0"(SYS_##name), "D"((long)(arg0)), "S"((long)(arg1)), \
                     "d"((long)(arg2)), "r"((long)(arg3))                   \
                   : "r10", "r11", "rcx", "memory");                        \
    while (res == -EINTR);                                                  \
    return Result<type>(res);                                               \
  }
#define GWPSAN_SYSCALL5(type, name, type0, arg0, type1, arg1, type2, arg2,   \
                        type3, arg3, type4, arg4)                            \
  inline Result<type> sys_##name(type0 arg0, type1 arg1, type2 arg2,         \
                                 type3 arg3, type4 arg4) {                   \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                       \
    uptr res;                                                                \
    do                                                                       \
      asm volatile("movq %5,%%r10; movq %6,%%r8; syscall"                    \
                   : "=a"(res)                                               \
                   : "0"(SYS_##name), "D"((long)(arg0)), "S"((long)(arg1)),  \
                     "d"((long)(arg2)), "r"((long)(arg3)), "r"((long)(arg4)) \
                   : "r8", "r10", "r11", "rcx", "memory");                   \
    while (res == -EINTR);                                                   \
    return Result<type>(res);                                                \
  }
#define GWPSAN_SYSCALL6(type, name, type0, arg0, type1, arg1, type2, arg2, \
                        type3, arg3, type4, arg4, type5, arg5)             \
  inline Result<type> sys_##name(type0 arg0, type1 arg1, type2 arg2,       \
                                 type3 arg3, type4 arg4, type5 arg5) {     \
    GWPSAN_FAULT_INJECT_SYSCALL(type);                                     \
    uptr res;                                                              \
    do                                                                     \
      asm volatile(                                                        \
          "movq %5,%%r10; movq %6,%%r8; movq %7,%%r9;"                     \
          "syscall"                                                        \
          : "=a"(res)                                                      \
          : "0"(SYS_##name), "D"((long)(arg0)), "S"((long)(arg1)),         \
            "d"((long)(arg2)), "r"((long)(arg3)), "r"((long)(arg4)),       \
            "r"((long)(arg5))                                              \
          : "r8", "r9", "r10", "r11", "rcx", "memory");                    \
    while (res == -EINTR);                                                 \
    return Result<type>(res);                                              \
  }

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_SYSCALL_X86_H_
