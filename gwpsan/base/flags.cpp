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

#include "gwpsan/base/flags.h"

#include "gwpsan/base/common.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/numeric.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/os.h"
#include "gwpsan/base/span.h"

namespace gwpsan {
namespace {
bool SetFlag(bool& var, const char* val) {
  if (val[0] == 0 || !internal_strcmp(val, "1") ||
      !internal_strcmp(val, "true"))
    var = true;
  else if (!internal_strcmp(val, "0") || !internal_strcmp(val, "false"))
    var = false;
  else
    return false;
  return true;
}

template <typename T>
bool SetIntFlag(T& var, const char* val) {
  const Optional<s64> num = Atoi(val);
  var = static_cast<T>(num.value_or(0));
  return num.has_value();
}

bool SetFlag(const char*& var, const char* val) {
  var = PersistentStrDup(val);
  return true;
}

bool ParseFlag(const char* name, const char* value,
               const Span<const FlagDesc>& flags) {
  for (const auto& flag : flags) {
    if (internal_strcmp(name, flag.name))
      continue;
    switch (flag.var.type) {
    case FlagDesc::Type::kBool:
      return SetFlag(*static_cast<bool*>(flag.var.ptr), value);
    case FlagDesc::Type::kInt:
      return SetIntFlag(*static_cast<int*>(flag.var.ptr), value);
    case FlagDesc::Type::kUptr:
      return SetIntFlag(*static_cast<uptr*>(flag.var.ptr), value);
    case FlagDesc::Type::kString:
      return SetFlag(*static_cast<const char**>(flag.var.ptr), value);
    }
  }
  return false;
}

void PrintHelp(const Span<const FlagDesc>& flags) {
  Printf("gwpsan: supported flags\n");
  for (const auto& flag : flags) {
    Printf("%s\n    %s\n    Value: ", flag.name, flag.desc);
    switch (flag.var.type) {
    case FlagDesc::Type::kBool:
      Printf("%s", *static_cast<bool*>(flag.var.ptr) ? "true" : "false");
      break;
    case FlagDesc::Type::kInt:
      Printf("%d", *static_cast<int*>(flag.var.ptr));
      break;
    case FlagDesc::Type::kUptr:
      Printf("%zu", *static_cast<uptr*>(flag.var.ptr));
      break;
    case FlagDesc::Type::kString:
      Printf("%s", *static_cast<const char**>(flag.var.ptr) ?: "");
      break;
    }
    Printf("\n");
  }
}
}  // namespace

bool ParseFlagsFromEnv(const char* env, const Span<const FlagDesc>& flags) {
  char buf[400];  // should be enough for everyone
  GetEnv(env, buf);
  return ParseFlagsFromStr(buf, flags);
}

bool ParseFlagsFromStr(char* str, const Span<const FlagDesc>& flags) {
  bool help = false;
  for (char* next = str; next && *next;) {
    char* name = next;
    next = internal_strchr(next, ':');
    if (next)
      *next++ = 0;
    char* val = internal_strchr(name, '=');
    if (val)
      *val++ = 0;
    if (!internal_strcmp(name, "help")) {
      help = true;
    } else if (!ParseFlag(name, val ?: "", flags)) {
      Printf("gwpsan: failed to parse flag '%s'='%s'\n", name, val);
      return false;
    }
  }
  if (help) {
    PrintHelp(flags);
    Die();
  }
  return true;
}

}  // namespace gwpsan
