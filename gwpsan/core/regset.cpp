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

#include "gwpsan/core/regset.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/core/arch.h"

namespace gwpsan {

RegSet::RegSet(RegIdx reg0, RegIdx reg1, RegIdx reg2, RegIdx reg3, RegIdx reg4,
               RegIdx reg5) {
  for (auto reg : (RegIdx[]){reg0, reg1, reg2, reg3, reg4, reg5}) {
    if (reg != kRZ)
      Set(reg);
  }
}

RegSet& RegSet::AddRange(RegIdx start, RegIdx end) {
  for (int reg = start; reg <= end; reg++)
    Set(reg);
  return *this;
}

RegSet& RegSet::Remove(RegIdx reg0, RegIdx reg1, RegIdx reg2, RegIdx reg3) {
  for (auto reg : (RegIdx[]){reg0, reg1, reg2, reg3}) {
    if (reg != kRZ)
      Reset(reg);
  }
  return *this;
}

void RegSet::Set(int reg) {
  SAN_CHECK_NE(reg, kUNDEF);
  set_[reg / kWordBits] |= 1ul << (reg % kWordBits);
}

void RegSet::Reset(int reg) {
  SAN_CHECK_NE(reg, kUNDEF);
  set_[reg / kWordBits] &= ~(1ul << (reg % kWordBits));
}

RegSet::operator bool() const {
  for (auto elem : set_) {
    if (elem)
      return true;
  }
  return false;
}

bool RegSet::operator[](RegIdx reg) const {
  return set_[reg / kWordBits] & (1ul << (reg % kWordBits));
}

RegSet& RegSet::operator|=(const RegSet& other) {
  for (uptr i = 0; i < kSize; i++)
    set_[i] |= other.set_[i];
  return *this;
}

LogBuf RegSet::Dump() const {
  LogBuf buf;
  for (auto reg : *this)
    buf.Append("%s%s", buf.Empty() ? "" : ",", RegNames[reg]);
  return buf;
}

RegSet::iterator::iterator()
    : parent_()
    , pos_(kRegCount) {}

RegSet::iterator::iterator(const RegSet& set)
    : parent_(&set)
    , pos_(0) {
  for (; !IsCurrentBitSet(); pos_++) {}
}

RegSet::iterator& RegSet::iterator::operator++() {
  for (pos_++; !IsCurrentBitSet(); pos_++) {}
  return *this;
}

bool RegSet::iterator::IsCurrentBitSet() const {
  if (pos_ == kRegCount)
    return true;
  return parent_->set_[pos_ / kWordBits] & (1ul << (pos_ % kWordBits));
}

RegIdx RegSet::iterator::operator*() const {
  return static_cast<RegIdx>(pos_);
}

bool RegSet::iterator::operator!=(const RegSet::iterator& other) const {
  return pos_ != other.pos_;
}

RegSet::iterator RegSet::begin() const {
  return iterator(*this);
}

RegSet::iterator RegSet::end() const {
  return iterator();
}

}  // namespace gwpsan
