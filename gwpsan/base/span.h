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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_SPAN_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_SPAN_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

template <typename, uptr>
class Array;

// Internal replacement for std::span.
template <typename T>
class Span {
 public:
  using element_type = T;
  using value_type = remove_cv_t<T>;
  using size_type = uptr;
  using difference_type = sptr;
  using pointer = element_type*;
  using const_pointer = const element_type*;
  using reference = element_type&;
  using const_reference = const element_type&;
  using iterator = pointer;
  using const_iterator = const_pointer;

  constexpr Span()
      : Span(nullptr, 0) {}
  constexpr Span(pointer data, size_type size)
      : data_(data)
      , size_(size) {}
  template <uptr N>
  constexpr Span(element_type (&arr)[N])
      : Span(arr, N) {}
  template <typename C>
  constexpr Span(C& container)
      : Span(container.data(), container.size()) {}

  // These overloads allow constructing a Span from an Array in a constant
  // expression where we want to initialize the Span before an Array, both of
  // which are members of a class (calling data()/size() at this point is UB).
  template <typename ArrT, uptr kSize>
  constexpr Span(Array<ArrT, kSize>& arr)
      : Span(arr.data__, kSize) {}
  template <typename ArrT, uptr kSize>
  constexpr Span(const Array<ArrT, kSize>& arr)
      : Span(arr.data__, kSize) {}

  constexpr Span(const Span& other) = default;
  constexpr Span& operator=(const Span& other) = default;

  constexpr size_type size() const {
    return size_;
  }

  constexpr size_type size_bytes() const {
    return size() * sizeof(element_type);
  }

  [[nodiscard]] constexpr bool empty() const {
    return !size_;
  }

  constexpr reference operator[](size_type idx) const {
    SAN_DCHECK_LT(idx, size());
    return data_[idx];
  }

  constexpr reference at(size_type idx) const {
    SAN_CHECK_LT(idx, size());
    return data_[idx];
  }

  constexpr reference front() const {
    SAN_DCHECK(size());
    return data_[0];
  }

  constexpr reference back() const {
    SAN_DCHECK(size());
    return data_[size() - 1];
  }

  constexpr pointer data() const {
    return data_;
  }

  constexpr iterator begin() const {
    return iterator(data());
  }

  constexpr iterator end() const {
    return iterator(data() + size());
  }

  constexpr const_iterator cbegin() const {
    return const_iterator(data());
  }

  constexpr const_iterator cend() const {
    return const_iterator(data() + size());
  }

  constexpr Span first(size_type count) const {
    SAN_CHECK_LE(count, size());
    return Span(data(), count);
  }

  constexpr Span last(size_type count) const {
    SAN_CHECK_LE(count, size());
    Span(data() + (size() - count), count);
  }

  constexpr Span subspan(size_type offset, size_type count = -1ull) const {
    SAN_CHECK_LE(offset, size());
    if (count == size_type{-1ull})
      count = size() - offset;
    else
      SAN_CHECK_LE(count, size() - offset);
    return Span(data() + offset, count);
  }

 private:
  pointer data_;
  size_type size_;
};

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_SPAN_H_
