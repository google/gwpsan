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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_TYPE_ID_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_TYPE_ID_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

// TypeId provides an efficient opaque unique identifier for different types.
// Can be used as a more lightweight alternative to typeid() or dynamic casting
// where RTTI is unavailable.
//
// Example:
//
//   class Base : public TypeId {
//    public:
//     using TypeId::TypeId;
//   };
//
//   class Foo : public Base {
//    public:
//     Foo() : Base(this) {}
//   };
//
//   class Bar : public Base {
//    public:
//     Bar() : Base(this) {}
//   };
//
//   Foo foo;
//   Bar bar;
//   assert(foo.type_id() != bar.type_id());
//   assert(foo.type_id() == GetTypeId<Foo>());
//   assert(bar.type_id() == GetTypeId<Bar>());
//
class TypeId {
 public:
  template <typename T>
  explicit TypeId(const T*)
      : id_(GetInternalId<T>()) {}

  bool operator==(const TypeId& rhs) const {
    return id_ == rhs.id_;
  }
  bool operator!=(const TypeId& rhs) const {
    return !(*this == rhs);
  }

  // Return TypeId for derived classes.
  const TypeId& type_id() const {
    return *this;
  }

 private:
  template <typename T>
  static void* GetInternalId() {
    static char id;
    return &id;
  }

  void* const id_;
};

template <typename T>
TypeId GetTypeId() {
  return TypeId(static_cast<const T*>(nullptr));
}

// dyn_cast<> may be used on classes derived from TypeId to safely cast between
// base and derived classes.
template <typename To, typename From>
To* dyn_cast(From* from) {
  return (from && from->type_id() == GetTypeId<To>()) ? static_cast<To*>(from)
                                                      : nullptr;
}
template <typename To, typename From>
const To* dyn_cast(const From* from) {
  return (from && from->type_id() == GetTypeId<To>())
             ? static_cast<const To*>(from)
             : nullptr;
}

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_TYPE_ID_H_
