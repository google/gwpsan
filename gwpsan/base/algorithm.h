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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_ALGORITHM_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_ALGORITHM_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

template <typename T>
struct less {
  bool operator()(const T& a, const T& b) const {
    return a < b;
  }
};

template <typename Iter, typename Comp>
bool is_sorted(Iter first, Iter last, Comp comp) {
  if (first == last)
    return true;
  for (auto it = first; ++it != last; first = it) {
    if (comp(*it, *first))
      return false;
  }
  return true;
}

template <typename Iter>
bool is_sorted(Iter first, Iter last) {
  return gwpsan::is_sorted(first, last,
                           less<remove_cvref_t<decltype(*first)>>());
}

template <typename Iter, typename Comp>
void sort(Iter first, Iter last, Comp comp) {
  // Use shell sort b/c it's short and does not use additional memory. See:
  // https://en.wikipedia.org/wiki/Shellsort
  constexpr uptr kGaps[] = {701, 301, 132, 57, 23, 10, 4, 1};
  const uptr size = last - first;
  for (uptr gap : kGaps) {
    for (uptr i = gap; i < size; i++) {
      auto tmp = move(first[i]);
      uptr j = i;
      for (; (j >= gap) && !comp(first[j - gap], tmp); j -= gap)
        first[j] = move(first[j - gap]);
      first[j] = move(tmp);
    }
  }
}

template <typename Iter>
void sort(Iter first, Iter last) {
  gwpsan::sort(first, last, less<remove_cvref_t<decltype(*first)>>());
}

template <typename Iter, typename T, typename Comp>
Iter upper_bound(Iter first, Iter last, const T& v, Comp comp) {
  uptr size = last - first;
  while (size != 0) {
    auto half = size / 2;
    auto mid = first + half;
    if (comp(v, *mid)) {
      size = half;
    } else {
      first = ++mid;
      size -= half + 1;
    }
  }
  return first;
}

template <typename Iter, typename T>
Iter upper_bound(Iter first, Iter last, const T& v) {
  return gwpsan::upper_bound(first, last, v,
                             less<remove_cvref_t<decltype(*first)>>());
}

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_ARRAY_H_
