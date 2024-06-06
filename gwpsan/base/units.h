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

#ifndef GWPSAN_BASE_UNITS_H_
#define GWPSAN_BASE_UNITS_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

// Strongly-type representation of units, with seamless conversions between
// Units with different multipliers.
template <typename T, T kMultiplier>
class Units {
  typedef struct null* null_t;

 public:
  using Type = T;

  constexpr Units()
      : val_() {}
  constexpr Units(null_t)
      : val_() {}
  constexpr explicit Units(Type val)
      : val_(val) {}

  template <Type kOther>
  Units(const Units<Type, kOther>& other, bool lossy = false) {
    if constexpr (kMultiplier <= kOther) {
      static_assert((kOther % kMultiplier) == 0, "incompatible units");
      val_ = *other * kOther / kMultiplier;
    } else {
      static_assert((kMultiplier % kOther) == 0, "incompatible units");
      if (!lossy)
        SAN_WARN((*other % (kMultiplier / kOther)) != 0);
      val_ = *other / (kMultiplier / kOther);
    }
  }

  constexpr Units& operator=(const Units& other) {
    val_ = other.val_;
    return *this;
  }
  constexpr Units& operator=(null_t) {
    val_ = 0;
    return *this;
  }

  constexpr const Type& operator*() const {
    return val_;
  }
  constexpr bool operator!() const {
    return val_ == 0;
  }
  constexpr bool operator==(null_t) const {
    return val_ == 0;
  }
  constexpr bool operator!=(null_t) const {
    return val_ != 0;
  }

  template <Type kOther>
  constexpr bool operator==(const Units<Type, kOther>& other) const {
    return val_ == Units(other).val_;
  }
  template <Type kOther>
  constexpr bool operator!=(const Units<Type, kOther>& other) const {
    return val_ != Units(other).val_;
  }
  template <Type kOther>
  constexpr bool operator<(const Units<Type, kOther>& other) const {
    return val_ < Units(other).val_;
  }
  template <Type kOther>
  constexpr bool operator<=(const Units<Type, kOther>& other) const {
    return val_ <= Units(other).val_;
  }
  template <Type kOther>
  constexpr bool operator>(const Units<Type, kOther>& other) const {
    return val_ > Units(other).val_;
  }
  template <Type kOther>
  constexpr bool operator>=(const Units<Type, kOther>& other) const {
    return val_ >= Units(other).val_;
  }

  template <Type kOther>
  constexpr Units operator+(const Units<Type, kOther>& other) const {
    return Units(val_ + Units(other).val_);
  }
  template <Type kOther>
  constexpr Units operator-(const Units<Type, kOther>& other) const {
    return Units(val_ - Units(other).val_);
  }
  template <Type kOther>
  constexpr Units operator*(const Units<Type, kOther>& other) const {
    return Units(val_ * Units(other).val_);
  }
  template <Type kOther>
  constexpr Units operator/(const Units<Type, kOther>& other) const {
    return Units(val_ / Units(other).val_);
  }
  template <Type kOther>
  constexpr Units operator%(const Units<Type, kOther>& other) const {
    return Units(val_ % Units(other).val_);
  }
  template <Type kOther>
  constexpr Units& operator+=(const Units<Type, kOther>& other) {
    val_ += Units(other).val_;
    return *this;
  }
  template <Type kOther>
  constexpr Units& operator-=(const Units<Type, kOther>& other) {
    val_ -= Units(other).val_;
    return *this;
  }
  template <Type kOther>
  constexpr Units& operator*=(const Units<Type, kOther>& other) {
    val_ *= Units(other).val_;
    return *this;
  }
  template <Type kOther>
  constexpr Units& operator/=(const Units<Type, kOther>& other) {
    val_ /= Units(other).val_;
    return *this;
  }
  template <Type kOther>
  constexpr Units& operator%=(const Units<Type, kOther>& other) {
    val_ %= Units(other).val_;
    return *this;
  }
  constexpr Units& operator++() {
    ++val_;
    return *this;
  }
  constexpr Units operator++(int) {
    return Units(val_++);
  }
  constexpr Units& operator--() {
    --val_;
    return *this;
  }
  constexpr Units operator--(int) {
    return Units(val_--);
  }

 private:
  Type val_;
};

// Same as Units but can be constructed/assigned from a pointer type.
template <typename T, T kMultiplier>
class AddrUnits : public Units<T, kMultiplier> {
 public:
  using Units<T, kMultiplier>::Units;
  using Units<T, kMultiplier>::operator=;
  using Units<T, kMultiplier>::operator-;

  template <typename Y>
  constexpr AddrUnits(Y* ptr)
      : Units<T, kMultiplier>(reinterpret_cast<T>(ptr)) {}

  template <typename Ret, typename... Args>
  constexpr AddrUnits(Ret (*ptr)(Args...))
      : Units<T, kMultiplier>(reinterpret_cast<T>(ptr)) {}

  template <typename Y>
  constexpr AddrUnits& operator=(Y* ptr) {
    *this = AddrUnits(reinterpret_cast<T>(ptr));
    return *this;
  }

  template <typename Ret, typename... Args>
  constexpr AddrUnits& operator=(Ret (*ptr)(Args...)) {
    *this = AddrUnits(reinterpret_cast<T>(ptr));
    return *this;
  }

  constexpr AddrUnits operator-() const {
    return AddrUnits(-**this);
  }
};

using BitSize = Units<uptr, 1>;
using ByteSize = Units<uptr, kByteBits>;
using WordSize = Units<uptr, kWordBits>;
using Addr = AddrUnits<uptr, kByteBits>;

constexpr uptr Bits(const BitSize& val) {
  return *val;
}

constexpr uptr Bytes(const ByteSize& val) {
  return *val;
}

constexpr uptr Words(const WordSize& val) {
  return *val;
}

inline constexpr WordSize kPtrSize(1);

template <typename T>
constexpr ByteSize Sizeof() {
  return ByteSize(sizeof(T));
}

template <typename T>
constexpr ByteSize Sizeof(const volatile T&) {
  return Sizeof<T>();
}

inline uptr Bitmask(BitSize size) {
  SAN_DCHECK_LE(Bits(size), Bits(kPtrSize));
  return size == kPtrSize ? ~0ul : (1ul << Bits(size)) - 1;
}

inline uptr SignBit(BitSize size) {
  SAN_DCHECK_LE(Bits(size), Bits(kPtrSize));
  return 1ul << (Bits(size) - 1);
}

// Returns true if [addr0, addr0+size0) intersects with [addr1, addr1+size1).
constexpr bool DoRangesIntersect(Addr addr0, ByteSize size0, Addr addr1,
                                 ByteSize size1) {
  return max(addr0, addr1) < min(addr0 + size0, addr1 + size1);
}

using Nanoseconds = Units<s64, 1>;
using Microseconds = Units<s64, 1000>;
using Milliseconds = Units<s64, 1000000>;
using Seconds = Units<s64, 1000000000>;
using Duration = Nanoseconds;  // lowest resolution for generic duration

constexpr s64 Nanos(const Nanoseconds& val) {
  return *val;
}

constexpr s64 Micros(const Microseconds& val) {
  return *val;
}

constexpr s64 Millis(const Milliseconds& val) {
  return *val;
}

constexpr s64 Secs(const Seconds& val) {
  return *val;
}

}  // namespace gwpsan SAN_LOCAL

#ifdef GWPSAN_TEST
// For tests only.
#include <iosfwd>
namespace gwpsan SAN_LOCAL {
template <typename T, T kMultiplier>
std::ostream& operator<<(std::ostream& os, const Units<T, kMultiplier>& val);
template <typename T, T kMultiplier>
std::ostream& operator<<(std::ostream& os,
                         const AddrUnits<T, kMultiplier>& val);
}  // namespace gwpsan SAN_LOCAL
#endif  // GWPSAN_TEST

#endif  // GWPSAN_BASE_UNITS_H_
