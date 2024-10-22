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

#ifndef GWPSAN_BASE_FLAGS_H_
#define GWPSAN_BASE_FLAGS_H_

#include "gwpsan/base/common.h"
#include "gwpsan/base/span.h"

namespace gwpsan SAN_LOCAL {

struct FlagDesc {
  enum class Type {
    kBool,
    kInt,
    kUptr,
    kString,
  };
  struct TypedVar {
    constexpr TypedVar(bool* ptr)
        : type(Type::kBool)
        , ptr(ptr) {}
    constexpr TypedVar(int* ptr)
        : type(Type::kInt)
        , ptr(ptr) {}
    constexpr TypedVar(uptr* ptr)
        : type(Type::kUptr)
        , ptr(ptr) {}
    constexpr TypedVar(const char** ptr)
        : type(Type::kString)
        , ptr(ptr) {}
    const Type type;
    void* const ptr;
  };
  constexpr FlagDesc(TypedVar var, const char* name, const char* desc)
      : var(var)
      , name(name)
      , desc(desc) {}

  const TypedVar var;
  const char* const name;
  const char* const desc;
};

bool ParseFlagsFromStr(char* str, const Span<const FlagDesc>& flags);

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_FLAGS_H_
