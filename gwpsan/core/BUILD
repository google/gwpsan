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

# The core libraries contain core runtime code shared across sanitizers.

load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")
load("//gwpsan/base:defs.bzl", "common_features", "common_test_copts", "gwpsan_library", "gwpsan_test", "gwpsan_test_library", "supported_architectures")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//gwpsan:__subpackages__"],
)

gwpsan_library(
    name = "core",
    srcs = [
        "breakmanager.cpp",
        "breakpoint.cpp",
        "context.cpp",
        "decoder.cpp",
        "decoder_dumper.cpp",
        "decoder_dynamorio.cpp",
        "env.cpp",
        "flags.cpp",
        "init.cpp",
        "instruction.cpp",
        "known_functions.cpp",
        "meta.cpp",
        "operation.cpp",
        "origin.cpp",
        "regset.cpp",
        "report.cpp",
        "semantic_metadata.cpp",
        "store_buffer.cpp",
        "unwind_instruction.cpp",
    ] + select({
        "@platforms//cpu:x86_64": [
            "context_x86.cpp",
            "decoder_x86.cpp",
        ],
        "@platforms//cpu:aarch64": [
            "context_arm64.cpp",
            "decoder_arm64.cpp",
        ],
    }),
    hdrs = [
        "arch.h",
        "breakmanager.h",
        "breakpoint.h",
        "context.h",
        "core_fwd.h",
        "decode.h",
        "decoder.h",
        "decoder_dynamorio.h",
        "env.h",
        "flags.h",
        "init.h",
        "instruction.h",
        "known_functions.h",
        "meta.h",
        "operation.h",
        "origin.h",
        "regset.h",
        "report.h",
        "semantic_metadata.h",
        "store_buffer.h",
        "unwind_instruction.h",
    ] + select({
        "@platforms//cpu:x86_64": [
            "decoder_x86.h",
        ],
        "@platforms//cpu:aarch64": [
            "decoder_arm64.h",
        ],
    }),
    # This is needed for dlopen of instrumented libraries.
    linkopts = ["-Wl,--export-dynamic-symbol=__sanitizer_metadata_*"],
    deps = [
        "//gwpsan/import:drdecode",
        "//gwpsan/base",
    ],
)

# Similar to base:external_interface.
gwpsan_library(
    name = "external_interface",
    hdrs = [
        "arch.h",
        "core_fwd.h",
        "flags.h",
        "meta.h",
        "origin.h",
        "semantic_metadata.h",
    ],
    deps = ["//gwpsan/base:external_interface"],
)

gwpsan_test_library(
    name = "disable_test_lib",
    srcs = ["disable_test.cpp"],
    deps = [
        ":core",
        # Trivially passes if sample_interval_usec is 0, so we need to link
        # options to enable minimal runtime.
        "//gwpsan/base:test_utils",
    ],
)

gwpsan_test(
    name = "disable_test",
    linkopts = ["-Wl,--defsym=gwpsan_user_opt_out=1"],
    deps = [":disable_test_lib"],
)

gwpsan_test_library(
    name = "test_utils",
    srcs = [
        "decoder_executor.cpp",
    ],
    hdrs = [
        "decoder_executor.h",
    ],
    deps = [
        ":core",
        "//gwpsan/base",
        "//gwpsan/base:test_utils",
    ],
)

gwpsan_test_library(
    name = "test_init",
    srcs = ["init_for_test.cpp"],
    deps = [
        ":core",
        "//gwpsan/base",
    ],
)

gwpsan_test(
    name = "core_test",
    srcs = [
        "breakmanager_stress_test.cpp",
        "breakmanager_test.cpp",
        "breakpoint_test.cpp",
        "decoder_test.cpp",
        "env_test.cpp",
        "known_functions_test.cpp",
        "meta_test.cpp",
        "operation_test.cpp",
        "origin_test.cpp",
        "regset_test.cpp",
        "report_test.cpp",
        "store_buffer_test.cpp",
        "unwind_instruction_test.cpp",
    ],
    deps = [
        ":core",
        ":test_init",
        ":test_utils",
        "@googletest//:gtest_main",
        "//gwpsan/base",
        "//gwpsan/base:test_utils",
    ],
)

gwpsan_test(
    name = "core_benchmark",
    srcs = [
        "breakmanager_benchmark.cpp",
        "breakpoint_benchmark.cpp",
        "context_benchmark.cpp",
    ],
    deps = [
        ":core",
        ":test_init",
        ":test_utils",
        "@google_benchmark//:benchmark_main",
        "//gwpsan/base",
        "//gwpsan/base:test_utils",
    ],
)

cc_fuzz_test(
    name = "decoder_fuzzer",
    testonly = 1,
    srcs = ["decoder_fuzzer.cpp"],
    copts = common_test_copts,
    features = common_features,
    restricted_to = supported_architectures,
    tags = ["nomsan"],  # interference with MSan signal interception
    deps = [
        ":core",
        ":test_init",
        ":test_utils",
        "//gwpsan/base",
    ],
)

gwpsan_test_library(
    name = "semantic_metadata_test_linkstatic",
    srcs = ["semantic_metadata_test_linkstatic.cpp"],
    sanitize_metadata = 1,
)

gwpsan_test(
    name = "semantic_metadata_test",
    srcs = ["semantic_metadata_test.cpp"],
    data = [
        ":semantic_metadata_test_lib1.so",
        ":semantic_metadata_test_lib2.so",
        ":semantic_metadata_test_lib3.so",
    ],
    sanitize_metadata = 1,
    deps = [
        ":core",
        ":semantic_metadata_test_linkstatic",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/time",
        "//gwpsan/base",
    ],
)

cc_binary(
    name = "semantic_metadata_test_lib1.so",
    testonly = 1,
    srcs = ["semantic_metadata_test_lib1.cpp"],
    copts = [
        "-fno-sanitize=all",
        "-fexperimental-sanitize-metadata=atomics,uar",
    ],
    features = common_features,
    linkshared = 1,
    deps = [":semantic_metadata_test_lib1_uncovered"],
)

cc_library(
    name = "semantic_metadata_test_lib1_uncovered",
    testonly = 1,
    srcs = ["semantic_metadata_test_lib1_uncovered.cpp"],
    features = common_features,
    linkstatic = 1,
    alwayslink = 1,
)

cc_binary(
    name = "semantic_metadata_test_lib2.so",
    testonly = 1,
    srcs = ["semantic_metadata_test_lib2.cpp"],
    copts = [
        "-fno-sanitize=all",
        "-fexperimental-sanitize-metadata=atomics,uar",
    ],
    features = common_features,
    linkshared = 1,
)

cc_binary(
    name = "semantic_metadata_test_lib3.so",
    testonly = 1,
    srcs = ["semantic_metadata_test_lib1.cpp"],
    copts = [
        "-fno-sanitize=all",
        "-fexperimental-sanitize-metadata=atomics,uar",
    ],
    features = common_features,
    linkshared = 1,
)

gwpsan_test_library(
    name = "semantic_metadata_test_linkstatic_mixedcm",
    srcs = ["semantic_metadata_test_linkstatic.cpp"],
    copts = select({
        # TODO(elver): Switch this to -mcmodel=large when Clang 19 is released.
        # Until then, this test is not actually testing mixed code models.
        "@platforms//cpu:x86_64": ["-mcmodel=small"],
        # This currently only works on x86, because arm64 wants -fno-pic with
        # -mcmodel=large, but that causes other problems.
        "@platforms//cpu:aarch64": ["-mcmodel=small"],
    }),
    sanitize_metadata = 1,
)

# Test for mixed-version semantic metadata by mixing code models.
gwpsan_test(
    name = "semantic_metadata_test_mixedcm",
    srcs = ["semantic_metadata_test.cpp"],
    copts = common_test_copts + ["-mcmodel=small"],
    data = [
        ":semantic_metadata_test_lib1.so",
        ":semantic_metadata_test_lib2.so",
        ":semantic_metadata_test_lib3.so",
    ],
    sanitize_metadata = 1,
    deps = [
        ":core",
        ":semantic_metadata_test_linkstatic_mixedcm",
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/time",
        "//gwpsan/base",
    ],
)

# This target can be injected into binaries to benchmark effect of watchpoints on execution.
# The target creates max number of watchpoints and they are inherited by all threads,
# but the watchpoints stay disabled and never fire.
# If -gwpsan_arm_watchpoints flag is passed to the program, then all watchpoints are also armed
# (but still never fire during execution).
gwpsan_library(
    name = "breakmanager_perf_test",
    srcs = ["breakmanager_perf_test.cpp"],
    copts = common_test_copts,
    deps = [
        ":core",
        "@abseil-cpp//absl/flags:flag",
        "//gwpsan/base",
    ],
    # Link in all of our code since the target binary does not really depend
    # on anything in this target.
    alwayslink = 1,
)
