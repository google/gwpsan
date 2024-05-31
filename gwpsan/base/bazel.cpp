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

#include "gwpsan/base/bazel.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/syscall.h"

// Integration with Bazel, see:
// https://bazel.build/reference/test-encyclopedia

namespace gwpsan {
namespace {

constexpr char kWarningsFile[] = "TEST_WARNINGS_OUTPUT_FILE";
constexpr char kWarningPrefix[] = "[gwpsan] ";

constexpr int kNoFD = -1;
constexpr int kFailedFD = -2;

constexpr int kFilePerm = 0640;

int OpenOutputFile() {
  char* filename = Freelist<>::Alloc();
  auto free_filename = [filename] { Freelist<>::Free(filename); };
  CleanupRef free_filename_cleanup(free_filename);
  if (!GetEnv("TEST_UNDECLARED_OUTPUTS_DIR", {filename, Freelist<>::kSize}) ||
      !filename[0])
    return kFailedFD;
  uptr len = internal_strlen(filename);
  SPrintf(filename + len, Freelist<>::kSize - len, "/gwpsan.%u.txt", GetPid());
  return sys_openat(AT_FDCWD, filename, O_WRONLY | O_CREAT, kFilePerm)
      .val_or(kFailedFD);
}

int GetOutputFD() {
  static constinit int global_fd = kNoFD;
  static constinit Mutex global_mtx;
  int fd = __atomic_load_n(&global_fd, __ATOMIC_ACQUIRE);
  if (fd != kNoFD)
    return fd;
  Lock lock(global_mtx);
  fd = global_fd;
  if (fd != kNoFD)
    return fd;
  fd = OpenOutputFile();
  __atomic_store_n(&global_fd, fd, __ATOMIC_RELEASE);
  return fd;
}
}  // namespace

void BazelOnPrint(Span<char> text) {
  SAN_THREAD_LOCAL bool recursion;
  if (recursion)
    return;
  recursion = true;
  int fd = GetOutputFD();
  if (fd >= 0)
    sys_write(fd, text.data(), text.size());
  recursion = false;
}

void BazelOnReport(const char* summary) {
  char* filename = Freelist<>::Alloc();
  auto free_filename = [filename] { Freelist<>::Free(filename); };
  CleanupRef free_filename_cleanup(free_filename);
  if (!GetEnv(kWarningsFile, {filename, Freelist<>::kSize}) || !filename[0])
    return;
  auto fd =
      sys_openat(AT_FDCWD, filename, O_WRONLY | O_CREAT | O_APPEND, kFilePerm);
  if (!fd)
    return;
  iovec vec[] = {
      {.iov_base = const_cast<char*>(kWarningPrefix),
       .iov_len = internal_strlen(kWarningPrefix)                 },
      {.iov_base = const_cast<char*>(summary),
       .iov_len = internal_strlen(summary)                        },
      {.iov_base = const_cast<char*>("\n"),           .iov_len = 1},
  };
  sys_writev(fd.val(), vec, SAN_ARRAY_SIZE(vec));
  sys_close(fd.val());
}

bool BazelReportedWarning() {
  // Sometimes child processes report warnings, but the parent process
  // ignores the child exit status. As a result the test successfully passes.
  // The following code checks whether somebody had written something
  // to the bazel warnings file, and if so fails the test.
  Span<char> buffer{Freelist<>::Alloc(), Freelist<>::kSize};
  auto free_buffer = [buffer] { Freelist<>::Free(buffer.data()); };
  CleanupRef free_buffer_cleanup(free_buffer);
  if (!GetEnv(kWarningsFile, buffer) || !buffer.data()[0])
    return false;
  if (!ReadFile(buffer.data(), buffer))
    return false;
  return internal_strstr(buffer.data(), kWarningPrefix);
}

}  // namespace gwpsan
