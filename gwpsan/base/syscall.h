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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_SYSCALL_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_SYSCALL_H_

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/fault_inject.h"
#include "gwpsan/base/linux.h"

#if GWPSAN_X64
#include <asm/prctl.h>
#include <sys/prctl.h>

#include "gwpsan/base/syscall_x86.h"  // IWYU pragma: export
#elif GWPSAN_ARM64
#include "gwpsan/base/syscall_arm64.h"  // IWYU pragma: export
#endif

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

namespace gwpsan SAN_LOCAL {

#define GWPSAN_FAULT_INJECT_SYSCALL(type) \
  do {                                    \
    if (FaultInjectUnlikely())            \
      return Result<type>(-EAGAIN);       \
  } while (0)

GWPSAN_SYSCALL0(pid_t, getpid);
GWPSAN_SYSCALL0(pid_t, gettid);

GWPSAN_SYSCALL4(int, openat, int, dirfd, const char*, path, int, flags, int,
                mode);
GWPSAN_SYSCALL3(uptr, read, int, fd, void*, data, uptr, n);
GWPSAN_SYSCALL3(uptr, write, int, fd, const void*, data, uptr, n);
GWPSAN_SYSCALL3(uptr, writev, int, fd, const iovec*, vec, uptr, vlen);
GWPSAN_SYSCALL3(int, ioctl, int, fd, int, cmd, void*, arg);
template <typename Arg>
GWPSAN_SYSCALL3(int, fcntl, int, fd, int, cmd, Arg, arg);
GWPSAN_SYSCALL1(int, close, int, fd);
GWPSAN_SYSCALL2(int, pipe2, int*, pipefd, int, flags);
GWPSAN_SYSCALL3(int, dup3, int, oldfd, int, newfd, int, flags);
GWPSAN_SYSCALL3(int, getdents64, unsigned int, fd, linux_dirent64*, dirent,
                unsigned int, count);

GWPSAN_SYSCALL1(int, exit_group, int, status);
GWPSAN_SYSCALL4(pid_t, wait4, pid_t, pid, int*, status, int, options, void*,
                rusage);

GWPSAN_SYSCALL6(char*, mmap, void*, addr, uptr, size, uptr, prot, uptr, flags,
                int, fd, uptr, pgoff)
GWPSAN_SYSCALL2(int, munmap, void*, addr, uptr, size);
GWPSAN_SYSCALL3(int, mprotect, void*, addr, uptr, size, int, prot);

GWPSAN_SYSCALL3(uptr, futex, u32*, addr, int, op, u32, val);

GWPSAN_SYSCALL5(int, perf_event_open, perf_event_attr_v7*, attr, pid_t, pid,
                int, cpu, int, group_fd, uptr, flags);

GWPSAN_SYSCALL4(int, rt_sigprocmask, int, how, sigset_t*, nset, sigset_t*, oset,
                size_t, sigsetsize);
GWPSAN_SYSCALL4(int, rt_tgsigqueueinfo, int, tgid, int, tid, int, sig,
                siginfo_t*, info);

GWPSAN_SYSCALL3(int, timer_create, clockid_t, clockid, struct sigevent*, sevp,
                timer_t*, timerid);
GWPSAN_SYSCALL1(int, timer_delete, timer_t, timerid);
GWPSAN_SYSCALL4(int, timer_settime, timer_t, timerid, int, flags,
                const struct itimerspec*, new_value, struct itimerspec*,
                old_value);
GWPSAN_SYSCALL2(int, clock_gettime, clockid_t, clockid, struct kernel_timespec*,
                tp);
GWPSAN_SYSCALL4(int, clock_nanosleep, clockid_t, clockid, int, flags,
                const struct kernel_timespec*, rqtp, struct kernel_timespec*,
                rmtp);

GWPSAN_SYSCALL6(uptr, process_vm_readv, int, pid, const struct iovec*, lvec,
                uptr, liovcnt, const struct iovec*, rvec, uptr, riovcnt, uptr,
                flags);
GWPSAN_SYSCALL6(uptr, process_vm_writev, int, pid, const struct iovec*, lvec,
                uptr, liovcnt, const struct iovec*, rvec, uptr, riovcnt, uptr,
                flags);

GWPSAN_SYSCALL2(int, getrlimit, int, resource, struct rlimit*, rlim);

template <typename A2, typename A3, typename A4, typename A5>
GWPSAN_SYSCALL5(int, prctl, int, opt, A2, arg2, A3, arg3, A4, arg4, A5, arg5);

#if GWPSAN_X64
GWPSAN_SYSCALL2(int, arch_prctl, int, code, uptr*, addr);
#endif

}  // namespace gwpsan SAN_LOCAL

#undef GWPSAN_SYSCALL0
#undef GWPSAN_SYSCALL1
#undef GWPSAN_SYSCALL2
#undef GWPSAN_SYSCALL3
#undef GWPSAN_SYSCALL4
#undef GWPSAN_SYSCALL5
#undef GWPSAN_SYSCALL6

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_SYSCALL_H_
