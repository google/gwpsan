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

load("//gwpsan/base:defs.bzl", "gwpsan_library", "gwpsan_test", "gwpsan_test_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//gwpsan:__subpackages__"],
)

gwpsan_library(
    name = "tsan",
    srcs = ["tsan.cpp"],
    hdrs = ["tsan.h"],
    deps = [
        "//gwpsan/base",
        "//gwpsan/core",
        "//gwpsan/unified:tool",
    ],
)

gwpsan_test_library(
    name = "tsan_test_lib",
    srcs = ["tsan_test.cpp"],
    sanitize_metadata = 1,
    deps = [
        "@googletest//:gtest_main",
        "//gwpsan/base:external_interface",
        "//gwpsan/base:test_utils",
        "//gwpsan/core:external_interface",
        "//gwpsan/unified",
    ],
)

gwpsan_test(
    name = "tsan_test",
    tags = [
        "notap",
    ],
    deps = [":tsan_test_lib"],
)
