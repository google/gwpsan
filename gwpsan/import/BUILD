# Copyright 2024 The GWPSan Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Third party libraries adjusted to work within the GWPSan runtime.  Also
# provide build rules for libraries that do not ship with Bazel build rules.

load("//gwpsan/base:cc_implicit_output.bzl", "cc_implicit_output")
load("//gwpsan/base:defs.bzl", "gwpsan_library")
load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//gwpsan:__subpackages__"],
)

# Builtins implementations derived from LLVM/compiler-rt.
gwpsan_library(
    name = "builtins",
    srcs = [
        "udivmodti4.cpp",
        "udivti3.cpp",
    ],
    hdrs = [
        "int_lib.h",
    ],
    deps = [
        "//gwpsan/base",
    ],
)

cmake(
    name = "drdecode",
    lib_source = "@dynamorio//:all_srcs",
    cache_entries = {
        "DISABLE_WARNINGS": "ON",
        "BUILD_TESTS": "OFF",
        "BUILD_DOCS": "OFF",
        "BUILD_SAMPLES": "OFF",
        "BUILD_EXT": "OFF",
        "BUILD_CLIENTS": "OFF",
    },
    build_args = ["-j10"],
    targets = ["drdecode", "drlibc"],
    # Installation tries to install everything, not just the targets selected
    # above. Instead we then just have to selectively install what we need.
    install = 0,
    postfix_script = """
    libs=(
        libdrdecode.a
        libdrlibc.a
    )
    for x in "${libs[@]}"; do
        install -D lib64/$x $INSTALLDIR/lib/$x
    done
    for x in include/dr_*.h; do
        install -D $x $INSTALLDIR/$x
    done
    # Configure DynamoRIO:
    (
        case "$(uname -m)" in
            x86*) arch=X86_64;;
            arm*|aarch*) arch=ARM_64;;
            *) echo "Unknown architecture"; exit 1;;
        esac
        echo "#define $arch"
        echo "#define LINUX"
        cat include/dr_defines.h
    ) > $INSTALLDIR/include/dr_defines.h
    """,
    out_static_libs = [
        "libdrdecode.a",
        "libdrlibc.a",
    ],
)
