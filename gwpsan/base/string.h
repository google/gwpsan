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

#ifndef GWPSAN_BASE_STRING_H_
#define GWPSAN_BASE_STRING_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

// Simple pattern matching. Without additional metacharacters matches if
// `pattern` is a substring of `str`.
//
// Note: Metacharacters cannot be escaped, so only use this where the `pattern`
// string should not contain literal characters that are also used as
// metacharacters.
//
// Available metacharacters:
//  ^ : match beginning;
//  $ : match end;
//  | : or (match multiple patterns);
bool MatchStr(const char* str, const char* pattern);

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_STRING_H_
