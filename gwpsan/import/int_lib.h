//===-- int_lib.h - configuration header for compiler-rt  -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
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
//
//===----------------------------------------------------------------------===//
//
// This file is not part of the interface of this library.
//
// This file defines various standard types, most importantly a number of unions
// used to access parts of larger types.
//
// This version is minimized to provide the bare minimum for the builtins
// required by the GWPSan runtime.
//
//===----------------------------------------------------------------------===//

#ifndef THIRD_PARTY_GWP_SANITIZERS_IMPORT_INT_LIB_H_
#define THIRD_PARTY_GWP_SANITIZERS_IMPORT_INT_LIB_H_

#include "gwpsan/base/common.h"

static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);

namespace gwpsan::third_party {

typedef s32 si_int;
typedef u32 su_int;
typedef s64 di_int;
typedef u64 du_int;
typedef int ti_int __attribute__((mode(TI)));
typedef unsigned tu_int __attribute__((mode(TI)));

union utwords {
  tu_int all;
  struct {
    du_int low;
    du_int high;
  } s;
};

extern "C" tu_int gwpsan_udivmodti4(tu_int a, tu_int b, tu_int* rem);

}  // namespace gwpsan::third_party

#endif  // THIRD_PARTY_GWP_SANITIZERS_IMPORT_INT_LIB_H_
