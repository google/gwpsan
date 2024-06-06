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

#ifndef GWPSAN_BASE_MEMORY_H_
#define GWPSAN_BASE_MEMORY_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"

namespace gwpsan SAN_LOCAL {

// Account for `size` heap bytes allocated in gwpsan metrics.
void AccountHeapAlloc(uptr size);

// Account for `size` heap bytes freed in gwpsan metrics.
void AccountHeapFree(uptr size);

// Allocates memory that is not supposed to be freed.
// Intended for things like flag values, loaded modules, etc.
// Aligns returned pointer to std::max_align_t.
// Never returns nullptr (terminates instead).
char* PersistentAlloc(uptr size);

// Returns a pointer to a new string which is a duplicate of the string `str`.
// The memory is allocated with PersistentAlloc().
char* PersistentStrDup(const char* str);

// Convenience wrapper around PersistentAlloc() that allocates memory for T.
template <typename T, typename... Args>
T* PersistentNew(Args&&... args) {
  return new (Placed(PersistentAlloc(sizeof(T)))) T(forward<Args>(args)...);
}

template <uptr kSize>
class FreelistBase {
 public:
  static char* Alloc() {
    AtomicHead cmp;
    __atomic_load(&head_, &cmp, __ATOMIC_ACQUIRE);
    while (cmp.ptr) {
      void* next = *reinterpret_cast<void**>(cmp.ptr);
      AtomicHead xchg = {next, cmp.counter};
      if (__atomic_compare_exchange(&head_, &cmp, &xchg, true, __ATOMIC_ACQ_REL,
                                    __ATOMIC_ACQUIRE))
        return static_cast<char*>(cmp.ptr);
    }
    return PersistentAlloc(max(kSize, sizeof(char*)));
  }

  static void Free(void* ptr) {
    AtomicHead cmp;
    __atomic_load(&head_, &cmp, __ATOMIC_ACQUIRE);
    void** next = reinterpret_cast<void**>(ptr);
    for (;;) {
      *next = cmp.ptr;
      AtomicHead xchg = {ptr, cmp.counter + 1};
      if (__atomic_compare_exchange(&head_, &cmp, &xchg, true, __ATOMIC_ACQ_REL,
                                    __ATOMIC_ACQUIRE))
        break;
    }
  }

 private:
  struct UnalignedHead {
    void* ptr;
    uptr counter;
  };
  struct alignas(sizeof(UnalignedHead)) AtomicHead : UnalignedHead {};

  static AtomicHead head_;
  FreelistBase() = delete;
};

template <uptr kSize>
typename FreelistBase<kSize>::AtomicHead FreelistBase<kSize>::head_;

// Compute allocation size class.
static constexpr uptr GetSizeClass(uptr size) {
  const uptr round_to = size <= 128    ? 32
                        : size <= 256  ? 64
                        : size <= 512  ? 128
                        : size <= 1024 ? 256
                                       : 512;
  return ((size + round_to - 1) / round_to) * round_to;
}

// Global thread-safe freelist of memory blocks of size kRequestSize.
template <uptr kRequestSize = 1024>
class Freelist : public FreelistBase<GetSizeClass(kRequestSize)> {
 public:
  static constexpr uptr kSize = GetSizeClass(kRequestSize);
};

// Internal replacement for std::unique_ptr.
template <typename T, typename Deleter = void (*)(T*)>
class UniquePtr {
 public:
  constexpr UniquePtr() = default;

  constexpr explicit UniquePtr(T* ptr, Deleter deleter)
      : ptr_(ptr)
      , deleter_(move(deleter)) {}

  UniquePtr(UniquePtr&& other)
      : ptr_(other.release())
      , deleter_(move(other.deleter_)) {}

  ~UniquePtr() {
    reset();
  }

  UniquePtr& operator=(UniquePtr&& rhs) {
    reset();
    ptr_ = rhs.release();
    deleter_ = rhs.deleter_;
    return *this;
  }

  T& operator*() const {
    return *ptr_;
  }

  T* operator->() const {
    return ptr_;
  }

  T* get() const {
    return ptr_;
  }

  Deleter& get_deleter() {
    return deleter_;
  }
  const Deleter& get_deleter() const {
    return deleter_;
  }

  explicit operator bool() const {
    return ptr_ != nullptr;
  }

  T* release() {
    T* ret = ptr_;
    ptr_ = nullptr;
    return ret;
  }

  void reset() {
    if (ptr_) {
      deleter_(ptr_);
      ptr_ = nullptr;
    }
  }

  void swap(UniquePtr& other) {
    gwpsan::swap(*this, other);
  }

 private:
  T* ptr_ = nullptr;
  Deleter deleter_;

  UniquePtr(const UniquePtr&) = delete;
  UniquePtr& operator=(const UniquePtr&) = delete;
};
template <typename T, typename D>
UniquePtr(T*, D) -> UniquePtr<T, D>;

template <typename T, typename... Args>
UniquePtr<T> MakeUniqueFreelist(Args&&... args) {
  return UniquePtr(
      new (Placed(Freelist<sizeof(T)>::Alloc())) T(forward<Args>(args)...),
      +[](T* ptr) {
        ptr->~T();
        Freelist<sizeof(T)>::Free(ptr);
      });
}

template <typename T, typename Tag = void, typename... Args>
UniquePtr<T> MakeUniqueGlobal(Args&&... args) {
  static constinit OptionalBase<T> obj;
  SAN_CHECK(!obj);
  obj.emplace(forward<Args>(args)...);
  return UniquePtr(
      &obj.value_unchecked(), +[](T*) { obj.reset(); });
}

template <typename T, typename Base = T, typename Tag = void, typename... Args>
UniquePtr<Base> TryMakeUniqueGlobal(Args&&... args) {
  static constinit OptionalBase<T> obj;
  SAN_CHECK(!obj);
  if (!obj.try_emplace(forward<Args>(args)...))
    return {};
  return UniquePtr<Base>(
      &obj.value_unchecked(), +[](Base*) { obj.reset(); });
}

template <typename T, typename Tag = void, typename... Args>
UniquePtr<T> MakeUniqueThreadLocal(Args&&... args) {
  static constinit SAN_THREAD_LOCAL OptionalBase<T> obj;
  SAN_CHECK(!obj);
  obj.emplace(forward<Args>(args)...);
  return UniquePtr(
      &obj.value_unchecked(), +[](T*) { obj.reset(); });
}

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_MEMORY_H_
