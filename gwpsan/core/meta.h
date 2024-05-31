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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_META_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_META_H_

#include "gwpsan/base/allocator.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/core_fwd.h"
#include "gwpsan/core/origin.h"

namespace gwpsan SAN_LOCAL {

// Meta contains uninit/taint bits + origins for a single word.
class Meta {
 public:
  // Creates initialized/non-tainted meta info.
  Meta() = default;
  // Creates fully uninitialized/tainted meta info.
  explicit Meta(Origin* origin)
      : Meta(new OriginChain(origin)) {
    SAN_WARN(!origin);
  }
  // Creates fully uninitialized/tainted meta info.
  explicit Meta(OriginChain* chain)
      : shadow_(~0ul) {
    SAN_WARN(!chain);
    bits_ = new Bits(~0ul, chain);
  }

  Meta(const Meta& other) {
    *this = other;
  }

  Meta(Meta&& other) {
    *this = move(other);
  }

  Meta& operator=(const Meta& other);

  Meta& operator=(Meta&& other) {
    shadow_ = other.shadow_;
    other.shadow_ = 0;
    bits_ = other.bits_;
    other.bits_ = nullptr;
    return *this;
  }

  uptr shadow() const {
    return shadow_;
  }

  // Returns true if meta contains any uninit/tainted bits.
  operator bool() const {
    return shadow_ != 0;
  }

  // Chain the given origin to all existing origins for this word.
  void Chain(Origin* origin);

  // Reset shadow for these bits (mark them as initialized/untainted).
  Meta& Reset(uptr mask);
  // Set shadow for these bits (mark them as uninit/tainted).
  Meta& Set(uptr mask, OriginChain* origin);

  // Bitwise combine a and b.
  static Meta BitwiseOr(const Meta& a, const Meta& b);
  // Shifts all shadow bits in m left/right by n.
  static Meta Shift(OpRef op, const Meta& m, uptr n);
  // Rotates size shadow bits in m right by n.
  static Meta RotateRight(const Meta& m, uptr n, uptr size);
  // Reverse bit order in the meta.
  static Meta ReverseBits(const Meta& m);
  // If any of the bits in a or b are tainted, set all bits as tainted.
  static Meta Blend(const Meta& a, const Meta& b);
  static Meta Blend(const Meta& a);

  // Selects the origin that should be easier for user to understand
  // that intersects with the mask bits.
  OriginChain* Simplest(Origin::Type type, uptr mask = ~0ul) const;

  void Print(Origin::Type type) const;

 private:
  // Different bits in the word can have different origins.
  // Bits represent a group of bits in the word with the same origin.
  struct Bits : HeapAllocated {
    uptr mask;  // what bits are uninit/tainted
    OriginChain* origin;
    Bits* next;

    Bits(uptr mask, OriginChain* origin, Bits* next = nullptr)
        : mask(mask)
        , origin(origin)
        , next(next) {}
  };

  // What bits are uninit/tainted (union of all Bits.mask).
  // Note: intersection of Bits.mask is 0 (don't keep more than one origin per
  // bit).
  uptr shadow_ = 0;
  Bits* bits_ = nullptr;

  Meta(uptr shadow, Bits* bits);

  template <typename Func>
  static Meta Transform(const Meta& m, Func func);

  void DebugCheck() const;
  Bits* SimplestBits(Origin::Type type, uptr mask) const;
};

// Word contains actual user value + meta info for a single word
// in a register or in memory.
struct Word {
  uptr val;
  Meta meta;

  Word(uptr val = 0, const Meta& meta = Meta())
      : val(val)
      , meta(meta) {}
};

// MemAccess describes one memory access.
struct MemAccess {
  uptr pc = 0;
  Addr addr;
  ByteSize size;
  Word val;
  // Both is_read and is_write can be set for RMW operations.
  bool is_read = false;
  bool is_write = false;
  // For reads means that the read value is used (e.g. passed to syscall).
  bool is_use = false;
  Optional<bool> is_atomic;  // unset if we don't know yet

  LogBuf ToString() const;
  const char* TypeAsString() const;
  bool operator==(const MemAccess& other) const;
};

// MergeMemAccesses merges a set of memory accesses into an equivalent,
// but smaller set by combining accesses to the same and adjacent locations.
// The accesses are assumed to be produced by a single instruction (same pc).
// Merging is done in-line and the resulting span is returned.
Span<MemAccess> MergeAccesses(Span<MemAccess> a);

}  // namespace gwpsan SAN_LOCAL

#endif
