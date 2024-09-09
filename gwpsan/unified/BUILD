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

load("//gwpsan/base:defs.bzl", "common_copts", "common_features", "gwpsan_library", "gwpsan_test", "gwpsan_test_library", "supported_architectures")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//gwpsan:__subpackages__"],
)

gwpsan_library(
    name = "tool",
    hdrs = ["tool.h"],
    deps = [
        "//gwpsan/base",
        "//gwpsan/core",
    ],
)

gwpsan_library(
    name = "unified_unlinked",
    srcs = [
        "init.cpp",
        "unified.cpp",
    ],
    hdrs = ["unified.h"],
    deps = [
        ":tool",
        "//gwpsan/base",
        "//gwpsan/core",
        "//gwpsan/lmsan",
        "//gwpsan/tsan",
        "//gwpsan/uar",
    ],
)

# Builds a combined object with all dependencies we want to internalize. We
# don't want to share any dependencies with the main program because any code
# executed by the main program is subject to instrumentation.
genrule(
    name = "unified_linked",
    srcs = [
        ":unified_unlinked_output",
        "//gwpsan/base:base_output",
        "//gwpsan/base:metric_collection_output",
        "//gwpsan/core:core_output",
        "//gwpsan/import:builtins_output",
        "//gwpsan/import:drdecode",
        "//gwpsan/lmsan:lmsan_output",
        "//gwpsan/tsan:tsan_output",
        "//gwpsan/uar:uar_output",
    ],
    outs = ["unified_linked.o"],
    cmd = "$(LD) --gc-sections" +
          " $$($(LD) --version | grep -q '^GNU' && echo --gc-keep-exported)" +
          " -r -o $@" +
          # Libraries that contain "entry points" (namely: initializing constructor,
          # compiler callbacks and interceptors) need to into --whole-archive part
          # or otherwise these entry points will be discarded as unused.
          " --whole-archive" +
          " $(location :unified_unlinked_output)" +
          " $(location //gwpsan/base:metric_collection_output)" +
          " $(location //gwpsan/uar:uar_output)" +
          # Only used internally, but no references exist yet because we need
          # to redefine the builtins via redefined.syms. With --gc-sections,
          # the entire archive is removed if not in whole-archive, despite the
          # builtins marked as SAN_USED.
          " $(location //gwpsan/import:builtins_output)" +
          " --no-whole-archive" +
          # Ensure to list dependencies with roots of the dependency graph
          # first. Some linkers only retain symbols if their usage precedes
          # their definition on the input list.
          " $(location //gwpsan/lmsan:lmsan_output)" +
          " $(location //gwpsan/tsan:tsan_output)" +
          " $(location //gwpsan/core:core_output)" +
          " $$(ls -1 $(locations //gwpsan/import:drdecode) | grep '\\.a$$')" +
          " $(location //gwpsan/base:base_output)",
    restricted_to = supported_architectures,
    toolchains = ["@bazel_tools//tools/cpp:current_cc_toolchain"],
)

GWPSAN_INTERCEPTED = [
    "fork",
    "pthread_create",
    "sigaction",
    "signal",
]

# Generate list of symbols we want to internalize (by prefixing with "gwpsan.").
# We internalize all symbols that do not contain "gwpsan". We assume that
# gwpsan symbols won't be used by the main program. So prefixing them is
# unnecessary, would break c++filt and would break symbol redefinition for
# gwpsan_memset/cpy.
genrule(
    name = "unified_list_syms",
    srcs = [":unified_linked"],
    outs = [
        "unified_redefine.syms",
        "unified_localize.syms",
    ],
    cmd = "$(NM) -j --defined-only $(location :unified_linked)" +
          # Don't touch externally called functions (compiler callbacks and interceptors).
          " | egrep -v 'gwpsan|__sanitizer_metadata_|__interceptor|" +
          "|".join([s for s in GWPSAN_INTERCEPTED]) + "'" +
          # Don't touch compiler-generated symbols
          # (such as from sanitizers, e.g. ___asan_globals_registered).
          " | egrep -v '\\.|^___'" +
          " | while read sym; do" +
          "     echo \"$${sym} gwpsan.$${sym}\" >> $(location unified_redefine.syms);" +
          "     echo \"gwpsan.$${sym}\" >> $(location unified_localize.syms); done",
    restricted_to = supported_architectures,
    toolchains = ["@bazel_tools//tools/cpp:current_cc_toolchain"],
)

# Build internalized runtime library that does not use/export any functions
# that can be used by the tested program itself. First, we prefix all defined
# symbols (see unified_redefine_syms above). Second, we rename some undefined
# symbols used by DynamoRIO (see redefined.syms) to point to our copies
# (namely, memset/cpy are renamed to our gwpsan_memset/cpy). Finally, we
# localize all symbols we depend on and strip unneeded symbols.
genrule(
    name = "unified_private",
    srcs = [
        ":unified_linked",
        ":unified_redefine.syms",
        ":unified_localize.syms",
        "redefined.syms",
    ],
    outs = ["unified_private.o"],
    cmd = "$(OBJCOPY) --redefine-syms $(location redefined.syms)" +
          " --redefine-syms $(location :unified_redefine.syms)" +
          # "ld -r"/objcopy reorders symbol tables and therefore invalidates
          # .llvm_addrsig; remove it to avoid the --icf=safe linker warning.
          " --remove-section=.llvm_addrsig" +
          " $(location :unified_linked) $@" +
          "&& $(OBJCOPY) --localize-symbols $(location :unified_localize.syms) $@" +
          select({
              "//gwpsan:mode_opt": " && $(STRIP) --strip-unneeded $@",
              "//conditions:default": "",
          }),
    restricted_to = supported_architectures,
    toolchains = ["@bazel_tools//tools/cpp:current_cc_toolchain"],
)

GWPSAN_LINKOPTS = [
    "-ldl",
    "-lpthread",
    "-Wl,--export-dynamic-symbol=__sanitizer_metadata_*",
    "-Wl,--export-dynamic-symbol=gwpsan_collect_metrics",
    "-Wl,--export-dynamic-symbol=gwpsan_get_stack_limits",
] + [
    "-Wl,--export-dynamic-symbol=%s" % name
    for name in GWPSAN_INTERCEPTED
] + [
    "-Wl,--export-dynamic-symbol=__interceptor_%s" % name
    for name in GWPSAN_INTERCEPTED
] + [
    # In static binaries the linker discards the libc-specific definitions of
    # the intercepted functions if nothing else references them. While our weak
    # declarations reference these symbols, weak references do _not_ cause the
    # linker to satisfy the reference by pulling an archive that contains the
    # symbol.
    #
    # To ensure the definitions are pulled in even in fully static binaries,
    # pass --undefined which causes the linker to pull the libc definitions on
    # a best-effort basis (if they exist in an input archive, they are pulled,
    # but no error is generated if not).
    "-Wl,--undefined=__%s" % name
    for name in GWPSAN_INTERCEPTED
]

gwpsan_library(
    name = "unified",
    srcs = [":unified_private.o"],
    linkopts = GWPSAN_LINKOPTS,
    alwayslink = 1,
)

# Library archive for shipping as a binary blob.
genrule(
    name = "gwpsan_archive",
    srcs = [":unified_private.o"],
    outs = ["libgwpsan.a"],
    cmd = "$(AR) qcs $@ $<",
    restricted_to = supported_architectures,
    toolchains = ["@bazel_tools//tools/cpp:current_cc_toolchain"],
)

# Shared library for shipping as a binary that can be LD_PRELOAD'ed.
cc_binary(
    name = "libgwpsan.so",
    copts = common_copts,
    features = common_features,
    linkshared = 1,
    restricted_to = supported_architectures,
    deps = [":unified"],
)

gwpsan_test_library(
    name = "unified_test_lib",
    srcs = ["unified_test.cpp"],
    sanitize_metadata = 1,
    deps = [
        ":unified",
        "@googletest//:gtest",
        "//gwpsan/base:external_interface",
        "//gwpsan/base:test_utils",
    ],
)

gwpsan_test(
    name = "unified_test",
    timeout = "long",
    deps = [":unified_test_lib"],
)

gwpsan_test(
    name = "unified_notool_test",
    srcs = ["unified_notool_test.cpp"],
    deps = [
        ":unified",
        "@googletest//:gtest_main",
        "//gwpsan/base:external_interface",
        "//gwpsan/base:test_utils",
    ],
)

# To test that default ":unified" works, and also specified all necessary
# dependencies (above tests' dependencies might hide missing dependencies).
gwpsan_test(
    name = "unified_default_test",
    deps = [
        ":unified",
        "@googletest//:gtest_main",
    ],
)

# Test that we can be linked into targets that want to do --icf=safe.
gwpsan_test(
    name = "unified_icf_test",
    linkopts = ["-Wl,--icf=safe"],
    deps = [
        ":unified",
        "@googletest//:gtest_main",
    ],
)
