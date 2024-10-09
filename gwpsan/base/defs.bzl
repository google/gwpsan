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

"""
This file contains common helpers for all of the GWPSan project.
"""

load("//gwpsan/base:cc_implicit_output.bzl", "cc_implicit_output")

base_copts = [
    "-fno-exceptions",  # We don't use exceptions nor C++STL.
    "-Wno-c99-designator",
] + select({
    "//gwpsan:mode_dbg": ["-DGWPSAN_DEBUG=1", "-DGWPSAN_OPTIMIZE=0"],
    "//gwpsan:mode_fastbuild": ["-DGWPSAN_DEBUG=1", "-DGWPSAN_OPTIMIZE=1"],
    "//gwpsan:mode_opt": ["-DGWPSAN_OPTIMIZE=2"],
})

common_copts = base_copts + [
    # Always build as PIC to allow linking into shared libraries.
    "-fPIC",
    # Disable semantic metadata for all our tools, which will avoid
    # self-analysis if statically linked (covered metadata missing).
    "-fno-experimental-sanitize-metadata=all",
    "-Wglobal-constructors",
    "-Wexit-time-destructors",
    "-fno-unwind-tables",  # No exceptions.
    "-fno-asynchronous-unwind-tables",  # No exceptions.
] + select({
    "//gwpsan:mode_opt": [
        "-O2",
        # Stack space in signal handlers is precious.
        "-Wframe-larger-than=512",
    ],
    "//conditions:default": [
        # In fastbuild and debug builds we also need to be careful with stack
        # space usage. Therefore, build with at least -O1 and also warn about
        # excessive stack usage.
        "-O1",
        "-Wframe-larger-than=2048",
    ],
}) + select({
    # Condition may be true if optimized or unoptimized, so we need another select.
    "//gwpsan:sanitizer_msan": ["-Wno-frame-larger-than"],
    "//conditions:default": [],
})

common_test_copts = base_copts + ["-DGWPSAN_TEST"]
sanitize_metadata_copts = ["-fexperimental-sanitize-metadata=atomics,uar", "-mllvm", "-sanitizer-metadata-nosanitize-attr=0"]
nosanitize_metadata_copts = ["-fno-experimental-sanitize-metadata=all"]

# "None" will permit all default architectures; override this to something
# sensible to actually restrict the build.
supported_architectures = None

# If the Bazel Toolchain supports GWPSan directly, assume the below feature
# names are used for compiler metadata and linking runtime respectively. Remove
# both from GWPSan internals itself (we add flags explicitly to tests).
common_features = ["-gwpsan_metadata", "-gwpsan_runtime"]

def gwpsan_library(
        name,
        copts = common_copts,
        # We need all runtime libraries to statically link into the final binary:
        #   1. metric collection works (only have 1 metric section);
        #   2. interception of other library functions works.
        linkstatic = 1,
        alwayslink = 0,
        restricted_to = supported_architectures,
        features = [],
        **kwargs):
    final_features = features + common_features
    native.cc_library(
        name = name,
        copts = copts,
        linkstatic = linkstatic,
        alwayslink = alwayslink,
        restricted_to = restricted_to,
        features = final_features,
        **kwargs
    )
    if not alwayslink:
        cc_implicit_output(
            name = name + "_output",
            files = [":lib" + name + ".a"],
            restricted_to = supported_architectures,
            deps = [":" + name],
        )

def gwpsan_test_library(
        copts = common_test_copts,
        # See above.
        linkstatic = 1,
        alwayslink = 1,
        sanitize_metadata = 0,
        restricted_to = supported_architectures,
        features = [],
        **kwargs):
    if sanitize_metadata:
        final_copts = copts + sanitize_metadata_copts
    else:
        final_copts = copts + nosanitize_metadata_copts
    final_features = features + common_features
    native.cc_library(
        copts = final_copts,
        linkstatic = linkstatic,
        alwayslink = alwayslink,
        restricted_to = restricted_to,
        features = final_features,
        testonly = 1,
        **kwargs
    )

def gwpsan_test(
        copts = common_test_copts,
        linkopts = [],
        # Every death test dumps core and that takes too long in dynamic builds.
        linkstatic = 1,
        sanitize_metadata = 0,
        restricted_to = supported_architectures,
        features = [],
        tags = [],
        **kwargs):
    if sanitize_metadata:
        final_copts = copts + sanitize_metadata_copts
    else:
        final_copts = copts + nosanitize_metadata_copts

    # We have some redefintions of weak symbols which look like backwards references
    # and interceptors which may introduce backwards references, e.g. pthread_create
    # in thread/thread.pic.o refers to gwp_sanitizers/uar/interceptors.pic.o.
    final_linkopts = linkopts + ["-Wl,--warn-backrefs-exclude=*/gwpsan/*"]
    final_features = features + common_features
    final_tags = tags + ["notsan"]
    native.cc_test(
        copts = final_copts,
        linkstatic = linkstatic,
        restricted_to = restricted_to,
        features = final_features,
        tags = final_tags,
        linkopts = final_linkopts,
        **kwargs
    )
