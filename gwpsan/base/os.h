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

#ifndef GWPSAN_BASE_OS_H_
#define GWPSAN_BASE_OS_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/units.h"

namespace gwpsan SAN_LOCAL {

// Terminates the process.
[[noreturn]] void Die();

// Returns the process ID of the calling process.
// Returns 0 on failure.
int GetPid();

// Create new virtual mapping in virtual address space of the calling process.
// Returns nullptr on failure.
char* Mmap(uptr size);

// Unmap a virtual mapping in the virtual address space of the calling process.
bool Munmap(void* addr, uptr size);

// Suspends execution of the calling thread for at least `delay`.
void Sleep(Nanoseconds delay);

// Read the contents of a file into the provided buffer.
Result<uptr> ReadFile(const char* path, Span<char> buf);

using ReadFileMock = FunctionRef<Result<uptr>(const char*, Span<char>)>;
inline void SetReadFileMock(const Optional<ReadFileMock>& cb) {
  extern OptionalBase<ReadFileMock> readfile_mock;
  readfile_mock = cb;
}

// Read the environment variable into the provided buffer.
bool GetEnv(const char* name, Span<char> buf);

// Read the process name into the provided buffer.
bool ReadProcessName(Span<char> buf);

enum class ThreadState {
  kRunning,
  kSleeping,
  kDiskSleep,
  kStopped,
  kDead,
  kZombie,
  kParked,
  kIdle,
};
// Get thread state of thread `tid`.
Optional<ThreadState> GetThreadState(int tid);

// Return number of CPUs in the system.
int GetNumCPUs();

// Iterates through this process's list of threads, and calls `callback` with
// their IDs; if `callback` returns true continues iterating, otherwise stops.
// There is no guarantee that the TIDs are still valid, e.g. if a thread exits.
[[nodiscard]] bool ForEachTid(FunctionRef<bool(int)> callback);

extern bool pause_on_die;
extern bool abort_on_die;
extern int die_error_code;

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_OS_H_
