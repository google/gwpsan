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

#ifndef GWPSAN_BASE_ARRAY_H_
#define GWPSAN_BASE_ARRAY_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

// Internal replacement for std::array.
template <typename T, uptr kSize>
struct Array {
  using value_type = T;
  using iterator = T*;
  using const_iterator = const T*;

  // This is public, to simplify initializer list construction without having
  // to define the constructors (similar to std::array).
  T data__[kSize];

  constexpr iterator begin() {
    return iterator(data());
  }

  constexpr const_iterator begin() const {
    return const_iterator(data());
  }

  constexpr iterator end() {
    return iterator(data() + kSize);
  }

  constexpr const_iterator end() const {
    return const_iterator(data() + kSize);
  }

  constexpr uptr size() const {
    return kSize;
  }

  constexpr bool empty() const {
    return !kSize;
  }

  constexpr T& operator[](uptr n) {
    SAN_DCHECK_LT(n, kSize);
    return data__[n];
  }

  constexpr const T& operator[](uptr n) const {
    SAN_DCHECK_LT(n, kSize);
    return data__[n];
  }

  constexpr T& at(uptr n) {
    SAN_CHECK_LT(n, kSize);
    return data__[n];
  }

  constexpr const T& at(uptr n) const {
    SAN_CHECK_LT(n, kSize);
    return data__[n];
  }

  constexpr T& front() {
    return (*this)[0];
  }

  constexpr const T& front() const {
    return (*this)[0];
  }

  constexpr T& back() {
    return (*this)[kSize - 1];
  }

  constexpr const T& back() const {
    return (*this)[kSize - 1];
  }

  constexpr T* data() {
    return data__;
  }

  constexpr const T* data() const {
    return data__;
  }
};

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_ARRAY_H_
