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

#include "gwpsan/core/meta.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/numeric.h"
#include "gwpsan/base/span.h"
#include "gwpsan/core/operation.h"
#include "gwpsan/core/origin.h"

namespace gwpsan {

Meta::Meta(uptr shadow, Bits* bits)
    : shadow_(shadow)
    , bits_(bits) {
  DebugCheck();
}

Meta& Meta::operator=(const Meta& other) {
  // Note: this object may contain dangling pointers to freed objects since
  // operator= is called during state reset.
  if (this == &other)
    return *this;
  other.DebugCheck();
  shadow_ = other.shadow_;
  bits_ = nullptr;
  for (Bits* bits = other.bits_; bits; bits = bits->next)
    bits_ = new Bits(bits->mask, bits->origin, bits_);
  DebugCheck();
  return *this;
}

Meta::Bits* Meta::SimplestBits(Origin::Type type, uptr mask) const {
  DebugCheck();
  if (shadow_ == 0)
    return nullptr;
  Bits* simplest = nullptr;
  for (Bits* bits = bits_; bits; bits = bits->next) {
    if ((bits->mask & mask) == 0)
      continue;
    if (type != Origin::Type::kAny && type != bits->origin->type())
      continue;
    if (!simplest ||
        bits->origin == OriginChain::Simpler(bits->origin, simplest->origin))
      simplest = bits;
  }
  return simplest;
}

void Meta::Chain(Origin* origin) {
  DebugCheck();
  for (Bits* bits = bits_; bits; bits = bits->next)
    bits->origin = new OriginChain(origin, bits->origin);
}

Meta& Meta::Reset(uptr mask) {
  DebugCheck();
  uptr new_shadow = shadow_ & ~mask;
  if (new_shadow == shadow_)
    return *this;
  shadow_ = new_shadow;
  Bits* new_bits = nullptr;
  for (Bits* bits = bits_; bits;) {
    Bits* next = bits->next;
    bits->next = nullptr;
    bits->mask &= ~mask;
    if (bits->mask) {
      bits->next = new_bits;
      new_bits = bits;
    }
    bits = next;
  }
  bits_ = new_bits;
  DebugCheck();
  return *this;
}

Meta& Meta::Set(uptr mask, OriginChain* origin) {
  DebugCheck();
  if (!mask)
    return *this;
  Reset(mask);
  shadow_ |= mask;
  bits_ = new Bits(mask, origin, bits_);
  DebugCheck();
  return *this;
}

Meta Meta::BitwiseOr(const Meta& a, const Meta& b) {
  a.DebugCheck();
  b.DebugCheck();
  if ((a.shadow_ | b.shadow_) == 0)
    return Meta();
  // Start with a.
  Meta res = a;
  // Then add all of b bits.
  res.shadow_ |= b.shadow_;
  for (Bits* bits = b.bits_; bits; bits = bits->next) {
    uptr mask = bits->mask;
    // Check if new bits intersect with any of the existing bits.
    // If so, choose simpler origin for the intersecting bits.
    for (Bits* bits0 = res.bits_; bits0; bits0 = bits0->next) {
      uptr both = mask & bits0->mask;
      if (!both)
        continue;
      if (bits->origin == OriginChain::Simpler(bits->origin, bits0->origin))
        bits0->mask &= ~both;
      else
        mask &= ~both;
    }
    if (mask)
      res.bits_ = new Bits(mask, bits->origin, res.bits_);
  }
  // The previous step can leave some bits with 0 mask, remove any such bits.
  Bits* new_bits = nullptr;
  for (Bits* bits = res.bits_; bits;) {
    Bits* next = bits->next;
    bits->next = nullptr;
    if (bits->mask) {
      bits->next = new_bits;
      new_bits = bits;
    }
    bits = next;
  }
  res.bits_ = new_bits;
  res.DebugCheck();
  return res;
}

template <typename Func>
Meta Meta::Transform(const Meta& m, Func func) {
  m.DebugCheck();
  uptr shadow = func(m.shadow_);
  if (shadow == 0)
    return Meta();
  Bits* new_bits = nullptr;
  for (Bits* bits = m.bits_; bits; bits = bits->next) {
    uptr mask = func(bits->mask);
    if (mask)
      new_bits = new Bits(mask, bits->origin, new_bits);
  }
  return Meta(shadow, new_bits);
}

Meta Meta::Shift(OpRef op, const Meta& m, uptr n) {
  return Transform(m,
                   [&op, n](uptr shadow) { return ShiftVal(op, shadow, n); });
}

Meta Meta::RotateRight(const Meta& m, uptr n, uptr size) {
  return Transform(
      m, [n, size](uptr shadow) { return RotateRightVal(shadow, n, size); });
}

Meta Meta::ReverseBits(const Meta& m) {
  return Transform(m, [](uptr shadow) { return ReverseBitsVal(shadow); });
}

Meta Meta::Blend(const Meta& a, const Meta& b) {
  a.DebugCheck();
  b.DebugCheck();
  if ((a.shadow_ | b.shadow_) == 0)
    return Meta();
  return Meta(OriginChain::Simpler(a.Simplest(Origin::Type::kAny),
                                   b.Simplest(Origin::Type::kAny)));
}

Meta Meta::Blend(const Meta& a) {
  return Blend(a, Meta());
}

OriginChain* Meta::Simplest(Origin::Type type, uptr mask) const {
  Bits* bits = SimplestBits(type, mask);
  return bits ? bits->origin : nullptr;
}

void Meta::Print(Origin::Type type) const {
  auto* simplest = SimplestBits(type, ~0ul);
  if (!simplest)
    return;
  Printf("[0x%zx] bits originated at:\n", simplest->mask);
  simplest->origin->Print();
}

void Meta::DebugCheck() const {
  if (!GWPSAN_DEBUG)
    return;
  uptr shadow = 0;
  for (Bits* bits1 = bits_; bits1; bits1 = bits1->next) {
    SAN_CHECK_NE(bits1->mask, 0);
    shadow |= bits1->mask;
    for (Bits* bits2 = bits1->next; bits2; bits2 = bits2->next)
      SAN_CHECK_EQ(bits1->mask & bits2->mask, 0);
  }
  SAN_CHECK_EQ(shadow_, shadow);
}

SAN_USED LogBuf MemAccess::ToString() const {
  LogBuf buf;
  return buf.Append("%s 0x%zx/%zu at 0x%zx%s", TypeAsString(), *addr, *size, pc,
                    is_use ? " (use)" : "");
}

const char* MemAccess::TypeAsString() const {
  if (is_atomic.value_or(false)) {
    if (is_read && is_write)
      return "Read-Write (atomic)";
    if (is_read)
      return "Read (atomic)";
    if (is_write)
      return "Write (atomic)";
  } else {
    if (is_read && is_write)
      return "Read-Write";
    if (is_read)
      return "Read";
    if (is_write)
      return "Write";
  }
  SAN_BUG("unhandled type");
}

bool MemAccess::operator==(const MemAccess& other) const {
  return pc == other.pc && addr == other.addr && size == other.size &&
         is_read == other.is_read && is_write == other.is_write &&
         is_use == other.is_use && is_atomic == other.is_atomic;
}

Span<MemAccess> MergeAccesses(Span<MemAccess> a) {
  // First, merge accesses to the same addr/size. Then, merge adjacent accesses
  // of the same type. Doing it in one loop may prevent some merging.
  // Maybe it may be faster if we sort by address, but we assume N is small.
  uptr n = a.size();
  for (sptr i = n - 1; i >= 0; i--) {
    for (sptr j = i - 1; j >= 0; j--) {
      SAN_DCHECK_EQ(a[i].pc, a[j].pc);
      if (a[i].addr == a[j].addr && a[i].size == a[j].size) {
        a[j].is_read |= a[i].is_read;
        a[j].is_write |= a[i].is_write;
        a[j].is_use |= a[i].is_use;
        if (a[i].is_atomic)
          a[j].is_atomic = a[j].is_atomic.value_or(false) || *a[i].is_atomic;
        a[i] = a[--n];
        break;
      }
    }
  }
  for (sptr i = n - 1; i >= 0; i--) {
    for (sptr j = i - 1; j >= 0; j--) {
      if (max(a[i].addr, a[j].addr) <=
              min(a[i].addr + a[i].size, a[j].addr + a[j].size) &&
          a[i].is_read == a[j].is_read && a[j].is_write == a[j].is_write &&
          a[i].is_use == a[j].is_use && a[j].is_atomic == a[j].is_atomic) {
        auto addr = min(a[j].addr, a[i].addr);
        a[j].size = max(a[j].addr + a[j].size, a[i].addr + a[i].size) - addr;
        a[j].addr = addr;
        a[i] = a[--n];
        break;
      }
    }
  }
  return {a.data(), n};
}

}  // namespace gwpsan
