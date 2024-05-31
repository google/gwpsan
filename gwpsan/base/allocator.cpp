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

#include "gwpsan/base/allocator.h"

#include <stddef.h>  // for max_align_t

#include "gwpsan/base/common.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/sanitizer.h"
#include "gwpsan/base/syscall.h"

namespace gwpsan {

ArenaAllocator& ArenaAllocator::operator=(ArenaAllocator&& other) {
  Free();
  swap(allocated_, other.allocated_);
  swap(all_, other.all_);
  swap(free_, other.free_);
  swap(pos_, other.pos_);
  swap(size_, other.size_);
  return *this;
}

void* ArenaAllocator::Alloc(uptr size) {
  constexpr uptr kRedzone = GWPSAN_INSTRUMENTED_ASAN ? sizeof(u64) : 0;
  uptr rounded_size = RoundUpTo(size + kRedzone, sizeof(max_align_t));
  SAN_CHECK_LE(rounded_size, SAN_ARRAY_SIZE(Region::buf));
  if (size_ < rounded_size) {
    if (!AllocRegion())
      return nullptr;
  }
  void* ptr = pos_;
  pos_ += rounded_size;
  size_ -= rounded_size;
  ASAN_UNPOISON_MEMORY_REGION(ptr, size);
  SAN_CHECK_EQ(reinterpret_cast<uptr>(ptr) % sizeof(max_align_t), 0);
  return ptr;
}

bool ArenaAllocator::AllocRegion() {
  auto* reg = free_;
  if (reg) {
    SAN_DCHECK(!!sys_mprotect(reg, sizeof(*reg), PROT_READ | PROT_WRITE));
    free_ = reg->next;
  } else {
    reg = reinterpret_cast<Region*>(Mmap(sizeof(*reg)));
    if (SAN_WARN(!reg))
      return false;
    MSAN_POISON_MEMORY_REGION(reg->buf, sizeof(reg->buf));
    ASAN_POISON_MEMORY_REGION(reg->buf, sizeof(reg->buf));
    reg->next = all_;
    all_ = reg;
  }
  pos_ = reg->buf;
  size_ = SAN_ARRAY_SIZE(reg->buf);
  allocated_ += sizeof(*reg);
  return true;
}

void ArenaAllocator::Reset() {
  for (auto* reg = all_; reg != free_;) {
    auto* next = reg->next;
    MSAN_POISON_MEMORY_REGION(reg->buf, sizeof(reg->buf));
    ASAN_POISON_MEMORY_REGION(reg->buf, sizeof(reg->buf));
    SAN_DCHECK(!!sys_mprotect(reg, sizeof(*reg), PROT_NONE));
    reg = next;
  }
  free_ = all_;
  allocated_ = 0;
  pos_ = nullptr;
  size_ = 0;
}

void ArenaAllocator::Free() {
  bool unprotect = false;
  for (auto* reg = all_; reg != nullptr;) {
    unprotect |= reg == free_;  // need to access reg->next
    if (unprotect)
      SAN_DCHECK(!!sys_mprotect(reg, sizeof(*reg), PROT_READ | PROT_WRITE));
    auto* next = reg->next;
    MSAN_POISON_MEMORY_REGION(reg->buf, sizeof(reg->buf));
    // We have to unpoison the memory if we give it back to the OS, since other
    // code (e.g. in libc) may use mmap() to re-allocate the same memory, but
    // then passes that memory to functions that are hooked by ASan.
    ASAN_UNPOISON_MEMORY_REGION(reg->buf, sizeof(reg->buf));
    SAN_WARN(!Munmap(reg, sizeof(*reg)));
    reg = next;
  }
  allocated_ = 0;
  all_ = nullptr;
  free_ = nullptr;
  pos_ = nullptr;
  size_ = 0;
}

void HeapAllocator::Install() {
  // Allow installing the same allocator recursively in the same thread
  // and from different threads (in this case we assume that it's actually
  // protected by BreakManager mutex).
  if (current_) {
    SAN_DCHECK_EQ(current_, this);
    SAN_DCHECK_GT(current_installed_, 0);
  } else {
    SAN_DCHECK_EQ(current_installed_, 0);
    current_ = this;
  }
  current_installed_++;
  installed_++;
}

void HeapAllocator::Uninstall(bool reset) {
  SAN_DCHECK_EQ(current_, this);
  SAN_DCHECK_GT(current_installed_, 0);
  SAN_DCHECK_GE(installed_, current_installed_);
  if (!--current_installed_)
    current_ = nullptr;
  if (!--installed_ && reset)
    Reset();
}

constinit SAN_THREAD_LOCAL ArenaAllocator* HeapAllocator::current_;
constinit SAN_THREAD_LOCAL uptr HeapAllocator::current_installed_;
#if GWPSAN_DEBUG
constinit SAN_THREAD_LOCAL uptr HeapAllocator::no_heap_allocations_;
#endif

constinit HeapAllocator HeapAllocatorLifetime::global_;

}  // namespace gwpsan
