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

#include "gwpsan/base/os.h"

#include <stdlib.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/fault_inject.h"
#include "gwpsan/base/linux.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/numeric.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/sanitizer.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/base/units.h"

namespace gwpsan {
constinit OptionalBase<ReadFileMock> readfile_mock;

int GetPid() {
  auto pid = sys_getpid();
  if (SAN_WARN_IF_ERR(pid))
    return 0;
  return pid.val();
}

int GetTid() {
  // With logging, gettid() is one of the most frequent syscalls we make.
  // Disable fault injection to be able to debug with logging on.
  ScopedFaultInjectDisable fault_inject_disable;
  auto tid = sys_gettid();
  if (SAN_UNLIKELY(!tid)) {
    // Can't use SAN_WARN because it depends on GetTid().
    WarnImpl(__FILE_NAME__
             ":" SAN_STRINGIFY(__LINE__) ": WARN: sys_gettid() failed!\n");
    return 0;
  }
  return tid.val();
}

char* Mmap(uptr size) {
  char* res = sys_mmap(nullptr, size, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, -1, 0)
                  .val_or(nullptr);
  if (res) {
    // The memory can be poisoned if it was previously mapped.
    MSAN_UNPOISON_MEMORY_REGION(res, size);
    AccountHeapAlloc(size);
  }
  return res;
}

bool Munmap(void* addr, uptr size) {
  AccountHeapFree(size);
  return !!sys_munmap(addr, size);
}

void Sleep(Nanoseconds delay) {
  kernel_timespec ts = {
      .tv_sec = *Seconds(delay, /*lossy=*/true),
      .tv_nsec = Nanos(delay % Seconds(1)),
  };
  // Our syscall implementation automatically restarts on EINTR,
  // and passing the same pointer as both requested and remaining time
  // makes it do the right thing after restarts.
  SAN_WARN_IF_ERR(sys_clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, &ts));
}

Result<uptr> ReadFile(const char* path, Span<char> buf) {
  if (SAN_UNLIKELY(readfile_mock))
    return (*readfile_mock)(path, buf);

  auto fd = sys_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
  // Touch `buf` after sys_openat(), so that `path` and `buf` may point to the
  // same buffer, allowing efficient reuse of the same buffer.
  buf.at(0) = 0;
  if (!fd)
    return fd.CastError<uptr>();
  char* pos = buf.data();
  uptr remain = buf.size() - 1;
  for (;;) {
    auto nerr = sys_read(fd.val(), pos, remain);
    pos += nerr.val_or(0);
    remain -= nerr.val_or(0);
    if (!nerr || nerr.val() == 0 || remain == 0) {
      pos[0] = 0;
      sys_close(fd.val());
      if (!nerr)
        return nerr;
      const uptr read = pos - buf.data();
      MSAN_UNPOISON_MEMORY_REGION(buf.data(), read);
      return Result<uptr>(read);
    }
  }
}

namespace {
bool GetEnvImpl(const char* name, Span<char> buf, Span<char> file) {
  auto res = ReadFile("/proc/self/environ", file);
  if (!res || !res.val())
    return false;
  uptr name_len = internal_strlen(name);
  const char* pos = file.data();
  for (;;) {
    const char* endp = static_cast<char*>(
        internal_memchr(pos, 0, res.val() - (pos - file.data())));
    if (endp == pos || !endp)
      return false;
    if (internal_memcmp(pos, name, name_len) || pos[name_len] != '=') {
      pos = endp + 1;
      continue;
    }
    internal_strncpy(buf.data(), pos + name_len + 1, buf.size());
    buf.back() = 0;
    return true;
  }
}
}  // namespace

bool GetEnv(const char* name, Span<char> buf) {
  buf.at(0) = 0;
  // /proc/self/environ can be potentially very large and we don't know
  // the size ahead of time (stat says it's 0). So use a huge buffer and rely
  // on OS lazy allocation. The same approach we use in InitModuleList.
  constexpr uptr kFileSize = 256 << 20;
  char* file = Mmap(kFileSize);
  if (!file)
    return false;
  bool res = GetEnvImpl(name, buf, {file, kFileSize});
  Munmap(file, kFileSize);
  return res;
}

bool ReadProcessName(Span<char> buf) {
  return !!ReadFile("/proc/self/cmdline", buf);
}

bool pause_on_die;
bool abort_on_die;
// Error code 66 is commonly used for sanitizers.
int die_error_code = 66;

void Die() {
  if (pause_on_die) {
    Printf("gwpsan: pausing instead of dying (pid=%d)\n", GetPid());
    for (;;)
      Sleep(Seconds(1000));
  }
  if (abort_on_die)
    abort();
  sys_exit_group(die_error_code);
  SAN_UNREACHABLE();
}

Optional<ThreadState> GetThreadState(int tid) {
  // The kernel limits the task name to 64 bytes; ensure we can fit at least the
  // name, the TID, and the state (see fs/proc/array.c:proc_task_name).
  char buf[64 + 32];
  SPrintf(buf, sizeof(buf), "/proc/self/task/%d/stat", tid);
  auto nread = ReadFile(buf, buf);
  if (!nread)
    return {};
  // Scan from back until we find ") ", because a thread name may also include
  // ") " or any other arbitrary character sequence.
  for (sptr i = nread.val() - 1; i >= 2; --i) {
    if (buf[i - 2] == ')' && buf[i - 1] == ' ') {
      switch (buf[i]) {
      case 'R':
        return ThreadState::kRunning;
      case 'S':
        return ThreadState::kSleeping;
      case 'D':
        return ThreadState::kDiskSleep;
      case 'T':
        return ThreadState::kStopped;
      case 'X':
        return ThreadState::kDead;
      case 'Z':
        return ThreadState::kZombie;
      case 'P':
        return ThreadState::kParked;
      case 'I':
        return ThreadState::kIdle;
      default:
        return {};
      }
    }
  }
  return {};
}

int GetNumCPUs() {
  static constinit int cached_num_cpus = 0;

  int num_cpus = 0;
  if (SAN_LIKELY(!readfile_mock)) {
    num_cpus = __atomic_load_n(&cached_num_cpus, __ATOMIC_RELAXED);
    if (SAN_LIKELY(num_cpus))
      return num_cpus;
  }

  // Parse CPU bitmap representation.
  Span<char> buf{Mmap(kPageSize), kPageSize};
  if (!buf.data())
    return 1;  // Retry on next call.

  auto nread = ReadFile("/sys/devices/system/cpu/online", buf);
  if (!!nread && buf[0] >= '0' && buf[0] <= '9') {
    char* num = buf.data();
    Optional<s64> start_range;
    auto add_range = [&] {
      const auto end_range = Atoi(num);
      if (SAN_WARN(!end_range))
        return false;
      // Range is inclusive.
      num_cpus += *end_range - *start_range + 1;
      start_range.reset();
      return true;
    };
    for (char* cur = buf.data(); *cur; ++cur) {
      if (*cur == ',') {
        if (start_range) {
          *cur = '\0';
          // Previous num is end range.
          if (!add_range())
            break;
        } else {
          // No range, just a single CPU.
          ++num_cpus;
        }
        num = cur + 1;
      } else if (*cur == '-') {
        *cur = '\0';
        start_range = Atoi(num);
        if (SAN_WARN(!start_range))
          break;
        num = cur + 1;
      }
    }
    if (start_range)
      add_range();  // last was "...,<num>-<num>"
    else
      ++num_cpus;  // last was "...,<num>"
  }

  if (!num_cpus)
    num_cpus = 1;  // Fallback

  __atomic_store_n(&cached_num_cpus, num_cpus, __ATOMIC_RELAXED);
  Munmap(buf.data(), buf.size());
  return num_cpus;
}

// Note: If ForEachTid() ever becomes performance critical, consider replacing
// the implementation with one that intercepts thread creation. It would require
// moving the existing pthread_create interception to base and provide a way to
// hook into thread creation. It also requires a good data structure to maintain
// the list of threads cheaply.
//
// The current main use is for timer distribution. However, since Linux kernel
// 6.4, timer signals should be better distributed by default, and optimizing
// timer distribution in user space should no longer be necessary.
bool ForEachTid(FunctionRef<bool(int)> callback) {
  auto fd = sys_openat(AT_FDCWD, "/proc/self/task",
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
  if (SAN_WARN_IF_ERR(fd))
    return false;
  // Using a smaller buffer would cause more getdents64 syscalls: when iterating
  // through the list of threads, "seeking" to the previously stopped position
  // is done by the kernel by simply iterating through the list of tasks again.
  // It's faster to allocate a large buffer and reduce the number of syscalls.
  static_assert(Freelist<>::kSize > (sizeof(linux_dirent64) + 8) * 8);
  char* dirent_buf = Freelist<>::Alloc();
  const auto cleanup_f = [&] {
    sys_close(fd.val());
    if (dirent_buf)
      Freelist<>::Free(dirent_buf);
  };
  const CleanupRef cleanup(cleanup_f);
  if (!dirent_buf)
    return false;

  for (;;) {
    auto nbytes =
        sys_getdents64(fd.val(), reinterpret_cast<linux_dirent64*>(dirent_buf),
                       Freelist<>::kSize);
    if (!nbytes)
      return false;
    if (!nbytes.val())
      break;

    for (uptr pos = 0; pos < nbytes.val();) {
      auto* dirent = reinterpret_cast<linux_dirent64*>(dirent_buf + pos);
      if (dirent->d_name[0] != '.') {
        auto tid = Atoi(dirent->d_name);
        if (!SAN_WARN(!tid)) {
          if (!callback(*tid))
            return true;
        }
      }
      pos += dirent->d_reclen;
    }
  }

  return true;
}

}  // namespace gwpsan
