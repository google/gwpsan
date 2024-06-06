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

#ifndef GWPSAN_BASE_SYNCHRONIZATION_H_
#define GWPSAN_BASE_SYNCHRONIZATION_H_

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"

#define SAN_MUTEX __attribute__((capability("mutex")))
#define SAN_SCOPED_LOCK __attribute__((scoped_lockable))
#define SAN_GUARDED_BY(x) __attribute__((guarded_by(x)))
#define SAN_PT_GUARDED_BY(x) __attribute__((pt_guarded_by(x)))
#define SAN_REQUIRES(...) __attribute__((requires_capability(__VA_ARGS__)))
#define SAN_ACQUIRE(...) __attribute__((acquire_capability(__VA_ARGS__)))
#define SAN_TRY_ACQUIRE(...) \
  __attribute__((try_acquire_capability(__VA_ARGS__)))
#define SAN_RELEASE(...) __attribute__((release_capability(__VA_ARGS__)))
#define SAN_EXCLUDES(...) __attribute__((locks_excluded(__VA_ARGS__)))
#define SAN_CHECK_LOCKED(...) __attribute__((assert_capability(__VA_ARGS__)))
#define SAN_NO_THREAD_SAFETY_ANALYSIS __attribute__((no_thread_safety_analysis))

namespace gwpsan SAN_LOCAL {

// Semaphore provides an OS-dependent way to park/unpark threads.
// The last thread returned from Wait can destroy the object.
class Semaphore {
 public:
  constexpr Semaphore() = default;
  void Wait();
  void Post(u32 count = 1);

 private:
  u32 state_ = 0;

  Semaphore(const Semaphore&) = delete;
  void operator=(const Semaphore&) = delete;
};

class SAN_MUTEX Mutex {
 public:
  constexpr Mutex() = default;

  [[nodiscard]] bool TryLock() SAN_TRY_ACQUIRE(true) {
    u32 cmp = 0;
    return __atomic_compare_exchange_n(&waiters_, &cmp, 1, true,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
  }

  void Lock() SAN_ACQUIRE() {
    u32 old = __atomic_fetch_add(&waiters_, 1, __ATOMIC_ACQUIRE);
    if (SAN_UNLIKELY(old))
      sem_.Wait();
  }

  void Unlock() SAN_RELEASE() {
    u32 old = __atomic_fetch_sub(&waiters_, 1, __ATOMIC_RELEASE);
    if (SAN_UNLIKELY(old > 1))
      sem_.Post();
  }

  void CheckLocked() const SAN_CHECK_LOCKED() {
    SAN_DCHECK_NE(__atomic_load_n(&waiters_, __ATOMIC_RELAXED), 0);
  }

 private:
  u32 waiters_ = 0;
  Semaphore sem_;

  Mutex(const Mutex&) = delete;
  Mutex& operator=(const Mutex&) = delete;
};

// Value type for interfacing with SeqLock<T>. It ensures that the storage for T
// is aligned and padded correctly to enable efficient machine-word sized atomic
// accesses to its underlying storage.
//
// REQUIRES: Type T must not have specialized assignment or move operators, and
// is trivially copyable, i.e. copying it with a memcpy() is safe.
template <typename T>
class SeqValue {
  static_assert(is_trivially_copyable_v<T>, "cannot safely copy with memcpy()");

 public:
  // Default initialize the typed storage.
  constexpr SeqValue()
      : typed_() {}
  constexpr explicit SeqValue(T val)
      : typed_(move(val)) {}

  // Accessors for T.
  T* operator->() {
    return &typed_;
  }
  T& operator*() {
    return typed_;
  }
  const T* operator->() const {
    return &typed_;
  }
  const T& operator*() const {
    return typed_;
  }

 private:
  struct Uninit {};
  constexpr SeqValue(Uninit) {}

  void AtomicCopyTo(SeqValue& dst) const {
    for (uptr i = 0; i < untyped_.size(); ++i)
      dst.untyped_[i] = __atomic_load_n(&untyped_[i], __ATOMIC_RELAXED);
  }

  void AtomicCopyFrom(const SeqValue& src) {
    for (uptr i = 0; i < untyped_.size(); ++i)
      __atomic_store_n(&untyped_[i], src.untyped_[i], __ATOMIC_RELAXED);
  }

  // The union ensures that even if alignof(T) < alignof(uptr), we'll always
  // align to at least alignof(uptr).
  union {
    // Round up required storage to a multiple of word size, so that we only
    // have to do a single loop of uptr-sized loads.
    Array<uptr, (sizeof(T) - 1) / sizeof(uptr) + 1> untyped_;
    T typed_;
  };

  template <typename>
  friend class SeqLock;
};
template <typename T>
SeqValue(T) -> SeqValue<T>;

// Multiversion Seqlock implementation. High-level description of algorithm:
// https://groups.google.com/g/lock-free/c/VwUmXvehoaM/m/md8vMzk30QgJ
//
// For discussion of general trade-offs of Seqlock implementations vs. the C++
// memory model, also see [1]. This implementation chooses to wrap type T in
// SeqValue<T> to copy T with a atomic-access loop, which avoids data races.
// This limits which types of T we can support.
//
// [1] Hans-J. Boehm, "Can Seqlocks Get Along With Programming Language
//     Memory Models?", 2012.
//     URL: https://www.hpl.hp.com/techreports/2012/HPL-2012-68.pdf
template <typename T>
class SeqLock {
  static constexpr uptr kVersions = 2;

 public:
  // SeqLock does not serialize ReadExclusive() and Write() calls, but the
  // provided Mutex `mu` is checked to be locked in ReadExclusive() and Write()
  // calls. The lifetime of `mu` must match the associated SeqLock object.
  constexpr SeqLock(Mutex& mu)
      : mu_(mu) {}

  // Get a copy of the current version. Thread-safety: Can be called
  // concurrently with Write() calls.
  SeqValue<T> Read() const {
    SeqValue<T> copy(typename SeqValue<T>::Uninit{});
    uptr seq0, seq1;
    for (;;) {
      // Try to acquire the current version. Also see comment in Write().
      const uptr cur = __atomic_load_n(&current_, __ATOMIC_RELAXED);
      const SeqVersion& ver = versions_[cur % kVersions];
      seq0 = __atomic_load_n(&ver.seq, __ATOMIC_ACQUIRE);
      if (SAN_UNLIKELY(seq0 & 1))
        continue;  // Inconsistent version, retry with current.
      // Copy out its data.
      ver.value.AtomicCopyTo(copy);
      // Order making the copy with re-load of sequence counter.
      __atomic_thread_fence(__ATOMIC_ACQUIRE);
      // Reload the sequence counter to validate.
      seq1 = __atomic_load_n(&ver.seq, __ATOMIC_RELAXED);
      // Validate that the seq counter hasn't changed.
      if (SAN_LIKELY(seq0 == seq1))
        break;
      // We've read inconsistent data; retry.
    }
    return copy;
  }

  // Read the current version under the writer lock. Thread-safety: Cannot be
  // called concurrently with Write() calls.
  //
  // REQUIRES: mu_ is locked
  const SeqValue<T>& ReadExclusive() const {
    mu_.CheckLocked();
    return versions_[current_ % kVersions].value;
  }

  // Write a new version of the value. After completion, readers will see the
  // new value. Thread-safety: Cannot be called concurrently with other Write()
  // calls.
  //
  // REQUIRES: mu_ is locked
  void Write(const SeqValue<T>& value) {
    mu_.CheckLocked();
    // Get the next version ...
    SeqVersion& ver = versions_[(current_ + 1) % kVersions];
    SAN_DCHECK(!(ver.seq & 1));
    // ... and mark it as inconsistent.
    __atomic_store_n(&ver.seq, ver.seq + 1, __ATOMIC_RELAXED);
    // Order write of ver.seq with copying the new version.
    __atomic_thread_fence(__ATOMIC_RELEASE);
    // Copy in the new version.
    ver.value.AtomicCopyFrom(value);
    // Mark it as consistent again.
    __atomic_store_n(&ver.seq, ver.seq + 1, __ATOMIC_RELEASE);
    // Publish the new version. Use of a relaxed store is sufficient: if the
    // store of current_ is reordered before the release of ver.seq, the reader
    // will spin until it sees a consistent ver.seq value. However, to ensure
    // only the CPU could do such reordering, add a signal fence.
    __atomic_signal_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&current_, current_ + 1, __ATOMIC_RELAXED);
  }

 private:
  struct SeqVersion {
    SeqValue<T> value;  // storage for T
    uptr seq = 0;       // per-entry sequence counter
  };

  Array<SeqVersion, kVersions> versions_;
  uptr current_ = 0;
  Mutex& mu_;

  SeqLock(const SeqLock&) = delete;
  SeqLock& operator=(const SeqLock&) = delete;
};

class SAN_SCOPED_LOCK Lock {
 public:
  explicit Lock(Mutex& mu) SAN_ACQUIRE(mu)
      : mu_(mu) {
    mu_.Lock();
  }

  ~Lock() SAN_RELEASE() {
    mu_.Unlock();
  }

 private:
  Mutex& mu_;

  Lock(const Lock&) = delete;
  Lock& operator=(const Lock&) = delete;
};

class SAN_SCOPED_LOCK TryLock {
 public:
  explicit TryLock(Mutex& mu, bool force_fail = false) SAN_ACQUIRE(mu)
      : mu_(mu)
      , locked_(force_fail ? false : mu_.TryLock()) {}

  ~TryLock() SAN_RELEASE() {
    if (locked_)
      mu_.Unlock();
  }

  operator bool() const {
    return locked_;
  }

 private:
  Mutex& mu_;
  const bool locked_;

  TryLock(const TryLock&) = delete;
  TryLock& operator=(const TryLock&) = delete;
};

// Sync policy implementation for Optional that permits multiple concurrent
// accessors with Optional::and_then_sync(), but blocks Optional::reset() until
// all accessors are done.
class OptionalSyncMultipleAccess final {
 public:
  constexpr OptionalSyncMultipleAccess() = default;
  void Emplace();
  void ResetBegin();
  void ResetEnd();

  bool Acquire() {
    uptr refs = __atomic_load_n(&refs_, __ATOMIC_ACQUIRE);
    while (refs >= kInit) {
      // Pairs with the store in Emplace().
      if (__atomic_compare_exchange_n(&refs_, &refs, refs + 1, true,
                                      __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)) {
        return true;
      }
    }
    return false;
  }

  void Release() {
    // Release visibility over the object to the load in ResetBegin().
    if (SAN_UNLIKELY(__atomic_fetch_sub(&refs_, 1, __ATOMIC_RELEASE) == 1))
      sem_.Post();
  }

 private:
  // Note: The implementation could be replaced by a Mutex supporting
  // reader-locking, but for now we don't need such a Mutex elsewhere.
  static constexpr uptr kInit = 1ull << (kWordBits - 1);
  uptr refs_ = 0;
  Semaphore sem_;
};

// Base class for all classes for which there can only be a singleton that needs
// to be accessible from arbitrary threads after construction, including threads
// spawned before construction of the singleton. Thread-safe access is done via
// singleton().and_then_sync().
template <typename T>
class SynchronizedSingleton {
 public:
  using Singleton = OptionalBase<T, OptionalSyncMultipleAccess>;

  static Singleton& singleton() {
    return singleton_;
  }

 private:
  static Singleton singleton_;
};
template <typename T>
constinit SynchronizedSingleton<T>::Singleton
    SynchronizedSingleton<T>::singleton_;

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_SYNCHRONIZATION_H_
