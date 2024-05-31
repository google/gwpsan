#!/usr/bin/env bash

# Copyright 2024 The GWPSan Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ue

cd "${0%/*}"

LICENSE_TEXT="\
[#/ ]* Copyright 20[,\-[:digit:]]* The GWPSan Authors\n\
[#/ ]*\n\
[#/ ]* Licensed under the Apache License, Version 2\.0 \(the \"License\"\);\n\
[#/ ]* you may not use this file except in compliance with the License\.\n\
[#/ ]* You may obtain a copy of the License at\n\
[#/ ]*\n\
[#/ ]*     https?://www\.apache\.org/licenses/LICENSE-2\.0\n\
[#/ ]*\n\
[#/ ]* Unless required by applicable law or agreed to in writing, software\n\
[#/ ]* distributed under the License is distributed on an \"AS IS\" BASIS,\n\
[#/ ]* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.\n\
[#/ ]* See the License for the specific language governing permissions and\n\
[#/ ]* limitations under the License\."

MATCH=(
  -name "*.cpp" -o
  -name "*.h" -o
  -name "*.sh" -o
  -name "*.bzl" -o
  -name "BUILD" -o
  -name "WORKSPACE" -o
  -name "MODULE.bazel"
)

IGNORE=(
  # May not replicate above header exactly.
  -wholename "./gwpsan/import/*" -o
  -wholename "./import/*" -o
  -wholename "./google/*"
)

find -type f \( "${MATCH[@]}" \) -a \! \( "${IGNORE[@]}" \) |
(
  fails=0
  pass=0
  while read path; do
    if ! grep -Pzoq "$LICENSE_TEXT" "$path"; then
      echo "${path}: does not have standard license header"
      (( fails++ )) || :
    else
      (( pass++ )) || :
    fi
  done
  if (( fails )); then
    exit 1
  fi
  echo "${pass} files checked"
)
