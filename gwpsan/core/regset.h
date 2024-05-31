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

#ifndef THIRD_PARTY_GWP_SANITIZERS_CORE_REGSET_H_
#define THIRD_PARTY_GWP_SANITIZERS_CORE_REGSET_H_

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/core/arch.h"

namespace gwpsan SAN_LOCAL {

// A set of registers.
class RegSet {
 public:
  RegSet() = default;
  RegSet(RegIdx reg0, RegIdx reg1 = kRZ, RegIdx reg2 = kRZ, RegIdx reg3 = kRZ,
         RegIdx reg4 = kRZ, RegIdx reg5 = kRZ);
  RegSet& AddRange(RegIdx start, RegIdx end);
  RegSet& Remove(RegIdx reg0, RegIdx reg1 = kRZ, RegIdx reg2 = kRZ,
                 RegIdx reg3 = kRZ);

  // Returns true if the set contains at least one register.
  operator bool() const;
  // Returns true if 'reg' is present in the set.
  bool operator[](RegIdx reg) const;
  // Merges 'other' into 'this'.
  RegSet& operator|=(const RegSet& other);

  LogBuf Dump() const;

  // Iterator over registers in the set.
  class iterator {
   public:
    iterator& operator++();
    RegIdx operator*() const;
    bool operator!=(const iterator& other) const;

   private:
    const RegSet* parent_;
    uptr pos_;

    bool IsCurrentBitSet() const;
    iterator();
    iterator(const RegSet& set);
    friend class RegSet;
  };
  iterator begin() const;
  iterator end() const;

 private:
  static constexpr uptr kSize =
      RoundUpTo<uptr>(kRegCount, kWordBits) / kWordBits;
  Array<uptr, kSize> set_ = {};

  void Set(int reg);
  void Reset(int reg);
};

}  // namespace gwpsan SAN_LOCAL

#endif
