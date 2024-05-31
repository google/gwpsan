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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_ALLOCATOR_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_ALLOCATOR_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/synchronization.h"

namespace gwpsan SAN_LOCAL {

// A single-threaded region allocator. Does not automatically free memory on
// destruction.
class ArenaAllocator {
 public:
  // The provided `soft_limit` is a soft allocation limit in bytes. It is not
  // enforced by the Alloc() function (to avoid unnecessary nullptr-deref), but
  // can voluntarily be checked with CheckReset().
  constexpr explicit ArenaAllocator(uptr soft_limit = ~0ul)
      : soft_limit_(soft_limit) {}

  // Frees this ArenaAllocator's memory back to the OS (if it allocated any
  // memory), then takes ownership of the moved-from ArenaAllocator's regions.
  // The moved-from ArenaAllocator is left in the initial state.
  //
  // Note: The soft limit remains unchanged of either ArenaAllocator.
  ArenaAllocator& operator=(ArenaAllocator&& other);

  void* Alloc(uptr size);

  template <typename T, typename... Args>
  T* New(Args&&... args) {
    void* mem = Alloc(sizeof(T));
    if (SAN_UNLIKELY(!mem))
      return nullptr;
    return new (Placed(mem)) T(forward<Args>(args)...);
  }

  // Deallocates all heap allocated objects if the current heap size is larger
  // than `soft_limit`. Returns true if the heap was reset.
  bool CheckReset() {
    if (SAN_LIKELY(allocated_ <= soft_limit_))
      return false;
    Reset();
    return true;
  }

  // Unconditionally deallocates all allocated objects, but does not free the
  // memory back to the OS.
  void Reset();

  // Unconditionally deallocates all allocated objects, and frees the memory
  // back to the OS.
  void Free();

 private:
  struct Region {
    char buf[kPageSize - sizeof(Region*)];
    Region* next;
  };
  static_assert(sizeof(Region) == kPageSize);

  bool AllocRegion();

  const uptr soft_limit_;
  uptr allocated_ = 0;
  Region* all_ = nullptr;
  Region* free_ = nullptr;
  char* pos_ = nullptr;
  uptr size_ = 0;

  ArenaAllocator(const ArenaAllocator&) = delete;
  ArenaAllocator& operator=(const ArenaAllocator&) = delete;
};

// CachedArenaAllocator is a variant of ArenaAllocator that tries to preserve
// its regions on destruction for reuse, and upon re-construction would use
// cached regions instead of immediately requesting new memory from the OS.
//
// One such region cache exists per template tag.
template <typename Tag>
class CachedArenaAllocator : public ArenaAllocator {
 public:
  explicit CachedArenaAllocator(uptr soft_limit = ~0ul)
      : ArenaAllocator(soft_limit) {
    TryLock lock(cache_mu_);
    if (SAN_LIKELY(lock)) ArenaAllocator::operator=(move(cache_));
  }

  ~CachedArenaAllocator() {
    Reset();  // move back a reset cache
    TryLock lock(cache_mu_);
    if (SAN_LIKELY(lock))
      cache_ = move(*this);
    else
      Free();  // contention; just free everything
  }

 private:
  static Mutex cache_mu_;
  static ArenaAllocator cache_ SAN_GUARDED_BY(cache_mu_);
};
template <typename Tag>
constinit Mutex CachedArenaAllocator<Tag>::cache_mu_;
template <typename Tag>
constinit ArenaAllocator CachedArenaAllocator<Tag>::cache_;

// A single-threaded region allocator for HeapAllocated-derived objects.
// Instances of HeapAllocator should not be destroyed. Must be installed for
// the current thread with HeapAllocatorInstall or HeapAllocatorLifetime.
class HeapAllocator : public ArenaAllocator {
 public:
  using ArenaAllocator::ArenaAllocator;

  static void* Alloc(uptr size) {
    SAN_DCHECK_EQ(no_heap_allocations_, 0);
    SAN_DCHECK(current_);
    return current_->Alloc(size);
  }

  static void NoHeapAllocations(bool enable) {
#if GWPSAN_DEBUG
    no_heap_allocations_ += enable ? 1 : -1;
#endif
  }

  // Install the allocator to use in the current thread, and increments
  // its refcount.
  void Install();

  // Uninstalls the allocator and if its refcount reaches zero and `reset` is
  // true, resets itself effectively freeing all memory.
  void Uninstall(bool reset);

 private:
  uptr installed_ = 0;

  static SAN_THREAD_LOCAL ArenaAllocator* current_;
  static SAN_THREAD_LOCAL uptr current_installed_;
#if GWPSAN_DEBUG
  static SAN_THREAD_LOCAL uptr no_heap_allocations_;
#endif
};

// Installs `alloc` (a global instance by default) to use for the current
// thread. Frees all allocated memory at the end of the scope.
class HeapAllocatorLifetime {
 public:
  HeapAllocatorLifetime(HeapAllocator& alloc = global_)
      : alloc_(alloc) {
    alloc_.Install();
  }
  ~HeapAllocatorLifetime() {
    alloc_.Uninstall(true);
  }

 private:
  HeapAllocator& alloc_;
  static HeapAllocator global_;

  HeapAllocatorLifetime(const HeapAllocatorLifetime&) = delete;
  HeapAllocatorLifetime& operator=(const HeapAllocatorLifetime&) = delete;
};

// Denotes a scope where no HeapAllocated allocations should be made.
struct NoHeapAllocationsScope {
  NoHeapAllocationsScope() {
    HeapAllocator::NoHeapAllocations(true);
  }
  ~NoHeapAllocationsScope() {
    HeapAllocator::NoHeapAllocations(false);
  }
  NoHeapAllocationsScope(const NoHeapAllocationsScope&) = delete;
  NoHeapAllocationsScope& operator=(const NoHeapAllocationsScope&) = delete;
};

// Base class for garbage-collected heap objects.
// All methods are single-threaded (objects must not be allocated concurrently).
struct HeapAllocated {
  static void* operator new(uptr size) {
    return HeapAllocator::Alloc(size);
  }

  static void operator delete(void* ptr, unsigned long size) = delete;
};

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_ALLOCATOR_H_
