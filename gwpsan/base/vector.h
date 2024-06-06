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

#ifndef GWPSAN_BASE_VECTOR_H_
#define GWPSAN_BASE_VECTOR_H_

#include <stdlib.h>

#include "gwpsan/base/common.h"
#include "gwpsan/base/memory.h"

namespace gwpsan SAN_LOCAL {

// Internal replacement for std::vector.
template <typename Storage>
struct Vector {
  using value_type = Storage::value_type;
  using iterator = value_type*;
  using const_iterator = const value_type*;

  Vector() = default;
  Vector(const Vector&) = delete;
  Vector& operator=(const Vector&) = delete;

  Vector(Vector&& other)
      : storage_(move(other.storage_))
      , size_(other.size_) {
    other.size_ = 0;
  }

  Vector& operator=(Vector&& other) {
    storage_ = move(other.storage_);
    size_ = other.size_;
    other.size_ = 0;
    return *this;
  }

  ~Vector() {
    reset();
  }

  constexpr iterator begin() {
    return iterator(data());
  }

  constexpr const_iterator begin() const {
    return const_iterator(data());
  }

  constexpr iterator end() {
    return iterator(data() + size_);
  }

  constexpr const_iterator end() const {
    return const_iterator(data() + size_);
  }

  constexpr uptr size() const {
    return size_;
  }

  constexpr uptr capacity() const {
    return storage_.capacity();
  }

  constexpr bool empty() const {
    return size_ == 0;
  }

  constexpr value_type& operator[](uptr n) {
    SAN_DCHECK_LT(n, size_);
    return data()[n];
  }

  constexpr const value_type& operator[](uptr n) const {
    SAN_DCHECK_LT(n, size_);
    return data()[n];
  }

  constexpr value_type& at(uptr n) {
    SAN_CHECK_LT(n, size_);
    return data()[n];
  }

  constexpr const value_type& at(uptr n) const {
    SAN_CHECK_LT(n, size_);
    return data()[n];
  }

  constexpr value_type& front() {
    return (*this)[0];
  }

  constexpr const value_type& front() const {
    return (*this)[0];
  }

  constexpr value_type& back() {
    return (*this)[size_ - 1];
  }

  constexpr const value_type& back() const {
    return (*this)[size_ - 1];
  }

  constexpr value_type* data() {
    return static_cast<value_type*>(storage_.data());
  }

  constexpr const value_type* data() const {
    return static_cast<value_type*>(storage_.data());
  }

  template <class... Args>
  void emplace_back(Args&&... args) {
    reserve(size_ + 1);
    new (Placed(data() + size_++)) value_type{forward<Args>(args)...};
  }

  value_type pop_back() {
    SAN_CHECK_GT(size_, 0);
    value_type v = move(data()[size_ - 1]);
    data()[--size_].~value_type();
    return move(v);
  }

  void resize(uptr n, value_type v = value_type()) {
    if (n > size_) {
      reserve(n);
      while (size_ != n)
        new (Placed(data() + size_++)) value_type(v);
    } else {
      shrink(n);
    }
  }

  void reserve(uptr cap) {
    if (cap > capacity())
      storage_.grow_capacity(size_, cap);
  }

  // ----- Non-standard extensions -----

  void shrink(uptr n) {
    SAN_CHECK_LE(n, size_);
    while (size_ != n)
      data()[--size_].~value_type();
  }

  // clear + shrink_to_fit
  void reset() {
    for (uptr i = 0; i < size_; ++i)
      data()[i].~value_type();
    size_ = 0;
    storage_.reset();
  }

 private:
  Storage storage_;
  uptr size_ = 0;
};

// Vector storage with fixed pre-allocated capacity.
template <typename T, uptr kSize>
class ArrayStorage {
 public:
  using value_type = T;

  ArrayStorage() = default;

  // We don't know how many elements to move (constructed),
  // so for now this is unimplemented.
  ArrayStorage(ArrayStorage&& other) = delete;
  ArrayStorage& operator=(ArrayStorage&& other) = delete;

  constexpr void* data() const {
    return const_cast<char*>(data_);
  }

  constexpr uptr capacity() const {
    return kSize;
  }

  void grow_capacity(uptr size, uptr cap) {
    SAN_BUG("ArrayStorage grow");
  }

  void reset() {}

 private:
  alignas(value_type) char data_[sizeof(value_type) * kSize];
};

// Variable-size Vector storage allocated with malloc.
template <typename T>
class MallocStorage {
 public:
  using value_type = T;

  MallocStorage() = default;
  MallocStorage(MallocStorage&& other)
      : data_(other.data_)
      , capacity_(other.capacity_) {
    other.data_ = nullptr;
    other.capacity_ = 0;
  }

  MallocStorage& operator=(MallocStorage&& other) {
    reset();
    data_ = other.data_;
    capacity_ = other.capacity_;
    other.data_ = nullptr;
    other.capacity_ = 0;
    return *this;
  }

  constexpr void* data() const {
    return const_cast<void*>(data_);
  }

  constexpr uptr capacity() const {
    return capacity_;
  }

  void grow_capacity(uptr size, uptr cap) {
    SAN_CHECK_GT(cap, size);
    SAN_CHECK_LE(size, capacity_);
    const uptr new_capacity = max(cap, 2 * capacity_);
    const uptr new_bytes = new_capacity * sizeof(value_type);
    void* data = SAN_LIBCALL(malloc(new_bytes));
    AccountHeapAlloc(new_bytes);
    SAN_CHECK(data);
    for (uptr i = 0; i < size; ++i) {
      T* dst = static_cast<T*>(data) + i;
      T* src = static_cast<T*>(data_) + i;
      new (Placed(dst)) T(move(*src));
      src->~T();
    }
    reset();
    data_ = data;
    capacity_ = new_capacity;
  }

  void reset() {
    if (data_) {
      SAN_LIBCALL(free(data_));
      AccountHeapFree(capacity_ * sizeof(value_type));
      data_ = nullptr;
      capacity_ = 0;
    }
  }

  ~MallocStorage() {
    reset();
  }

 private:
  void* data_ = nullptr;
  uptr capacity_ = 0;
};

template <typename T, uptr kSize>
using ArrayVector = Vector<ArrayStorage<T, kSize>>;

template <typename T>
using MallocVector = Vector<MallocStorage<T>>;

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_VECTOR_H_
