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

# The base libraries contain common types, replacements for standard library
# functions, and hooks into OS and environment.

load("//gwpsan/base:defs.bzl", "gwpsan_library", "gwpsan_test", "gwpsan_test_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//gwpsan:__subpackages__"],
)

genrule(
    name = "stdlib_disallow",
    srcs = ["stdlib.h"],
    outs = ["stdlib_disallow.inc"],
    # The below command:
    #  1. Finds the location of libc.
    #  2. Looks for text (or weak) symbols.
    #  3. Strips the version after @@.
    #  4. Filters out symbols with __ and capital letters.
    #  5. Filters out symbols we explicitly allow per stdlib.h.
    #  6. Writes the remaining symbols to the out file.
    cmd = r"""
        libc=$$(ldd "$$(which $(NM))" | grep -m1 "libc\.so" | sed 's!^.*=> \([^ ]*\) .*$$!\1!')
        $(NM) -D "$${libc}" |
            grep ' [TW] ' | cut -d ' ' -f 3 | cut -d '@' -f 1 |
            grep -v '__\|[A-Z]' | sort -u |
            grep -Fxv "$$(grep "^SAN_.*_FUNCTION(" "$(location stdlib.h)" | sed 's/^.*(\([^)]*\)).*$$/\1/')" |
            while read sym; do
                echo "SAN_DISALLOW_FUNCTION($${sym});"
            done > "$@"
        """,
    toolchains = ["@bazel_tools//tools/cpp:current_cc_toolchain"],
)

gwpsan_library(
    name = "base",
    srcs = [
        "allocator.cpp",
        "bazel.cpp",
        "env.cpp",
        "fault_inject.cpp",
        "flags.cpp",
        "log.cpp",
        "memory.cpp",
        "module_list.cpp",
        "numeric.cpp",
        "os.cpp",
        "printf.cpp",
        "signal.cpp",
        "string.cpp",
        "synchronization.cpp",
        "timer.cpp",
        "unwind.cpp",
    ],
    hdrs = [
        "algorithm.h",
        "allocator.h",
        "array.h",
        "bazel.h",
        "common.h",
        "config.h",
        "env.h",
        "fault_inject.h",
        "flags.h",
        "linux.h",
        "log.h",
        "memory.h",
        "metric.h",
        "metric_collection.h",
        "module_list.h",
        "numeric.h",
        "optional.h",
        "os.h",
        "printf.h",
        "sanitizer.h",
        "signal.h",
        "span.h",
        "stdlib.h",
        "synchronization.h",
        "syscall.h",
        "syscall_arm64.h",
        "syscall_x86.h",
        "timer.h",
        "type_id.h",
        "units.h",
        "unwind.h",
        "vector.h",
        "weak_imports.h",
        ":stdlib_disallow",
    ],
    linkopts = [
        "-ldl",
    ],
    deps = [
        "@com_google_absl//absl/base:config",
    ],
)

# Separate target to link --whole-archive with minimal bloat.
gwpsan_library(
    name = "metric_collection",
    srcs = ["metric_collection.cpp"],
    hdrs = ["metric_collection.h"],
    linkopts = ["-Wl,--export-dynamic-symbol=gwpsan_collect_metrics"],
    deps = [":base"],
)

# Contains functions that can be used by "extension" targets.
gwpsan_library(
    name = "external_interface",
    srcs = [
        # Must not contain non-inline functions used by internalized runtime
        # and extension target (inline functions are deduplicated by linker).
        # Separating this from base helps to avoid duplicate symbol linking
        # errors due to the internalized library (unified_private). Otherwise,
        # we would get two versions of each symbol: one comes from the
        # internalized library and another from the extension target (since it
        # would also link in base).
    ],
    hdrs = [
        "allocator.h",
        "array.h",
        "common.h",
        "config.h",
        "env.h",
        "log.h",
        "memory.h",
        "metric.h",
        "metric_collection.h",
        "optional.h",
        "printf.h",
        "signal.h",
        "span.h",
        "stdlib.h",
        "synchronization.h",
        "units.h",
        "unwind.h",
        "vector.h",
        ":stdlib_disallow",
    ],
)

# This target serves the same purpose as external_interface but for tests.
gwpsan_test_library(
    name = "test_utils",
    srcs = [
        "test_flags.cpp",
        "test_report_interceptor.cpp",
        "units_test_printer.cpp",
        "weak_imports_use.cpp",
    ],
    hdrs = [
        "test_report_interceptor.h",
        "test_signal_listener.h",
    ],
    deps = [
        ":external_interface",
        "@googletest//:gtest",
        # Note: the target does not use symbolize directly,
        # but we link it to provide implementations for our Symbolize function.
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/strings",
        "@re2//:re2",
    ],
)

gwpsan_test(
    name = "base_test",
    timeout = "long",
    srcs = [
        "algorithm_test.cpp",
        "bazel_test.cpp",
        "common_test.cpp",
        "flags_test.cpp",
        "memory_test.cpp",
        "metric_test.cpp",
        "module_list_test.cpp",
        "numeric_test.cpp",
        "os_test.cpp",
        "printf_test.cpp",
        "string_test.cpp",
        "test_report_interceptor_test.cpp",
        "timer_test.cpp",
        "vector_test.cpp",
        "weak_imports_test.cpp",
    ],
    env = {
        "GWPSAN_GETENV_TEST_EMPTY": "",
        "GWPSAN_GETENV_TEST_NONEMPTY": "nonempty",
    },
    deps = [
        ":base",
        ":metric_collection",
        ":test_utils",
        "@googletest//:gtest_main",
        "@com_google_absl//absl/debugging:symbolize",
        "@re2//:re2",
    ],
)

# The test must not depend on gunit, since it may install own handlers.
gwpsan_test_library(
    name = "signal_test_lib",
    srcs = ["signal_test.cpp"],
    deps = [
        ":base",
    ],
)

gwpsan_test(
    name = "signal_test",
    deps = [":signal_test_lib"],
)

gwpsan_test(
    name = "signal_test_foreign_interceptor",
    srcs = ["signal_test_foreign_interceptor.cpp"],
    deps = [":signal_test_lib"],
)
