//===-- udivti3.c - Implement __udivti3 -----------------------------------===//
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
// This file implements __udivti3 for the compiler_rt library.
//
//===----------------------------------------------------------------------===//

#include "gwpsan/base/common.h"
#include "gwpsan/import/int_lib.h"

namespace gwpsan::third_party {
extern "C" {

// Returns: a / b

SAN_LOCAL SAN_USED tu_int gwpsan_udivti3(tu_int a, tu_int b) {
  return gwpsan_udivmodti4(a, b, 0);
}

}  // extern "C"
}  // namespace gwpsan::third_party
