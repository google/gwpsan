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

set -ueo pipefail

INPUT="stdlib.h"
OUTPUT="stdlib_disallow.inc"

cd "${0%/*}"

# Finds the location of libc.
libc=$(ldd "$(which nm)" | grep -m1 "libc\.so" | sed 's!^.*=> \([^ ]*\) .*$!\1!')
echo "libc: $libc"

(
  echo "// AUTOMATICALLY GENERATED BY ${0##*/}"
  # Generate new list
  nm -D "$libc" |
    # Looks for text (or weak) symbols.
    grep ' [TW] ' | cut -d ' ' -f 3 |
    # Strips the version after @@.
    cut -d '@' -f 1 |
    # Filters out symbols with __ and capital letters.
    grep -v '__\|[A-Z]' | sort -u |
    # Filters out symbols we explicitly allow per stdlib.h.
    grep -Fxv "$(grep "^SAN_.*_FUNCTION(" "$INPUT" | sed 's/^.*(\([^)]*\)).*$/\1/')" |
    # Writes the remaining symbols to the out file.
    while read sym; do
      echo "SAN_DISALLOW_FUNCTION(${sym});"
    done
) > "$OUTPUT"