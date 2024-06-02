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

# See MODULE.bazel for external dependencies setup.

# Having both WORKSPACE and MODULE.bazel specify dependencies is brittle.
# rules_fuzzing is not yet available via Bazel registry, but should be soon:
#   https://github.com/bazelbuild/rules_fuzzing/pull/242
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
http_archive(
    name = "rules_fuzzing",
    sha256 = "c0dc1f90dea236299271e558d8303dd4cc8c7554b2b0639561e5007d2d33328e",
    strip_prefix = "rules_fuzzing-0.4.0",
    urls = ["https://github.com/bazelbuild/rules_fuzzing/archive/v0.4.0.zip"],
)
load("@rules_fuzzing//fuzzing:repositories.bzl", "rules_fuzzing_dependencies")
rules_fuzzing_dependencies()
load("@rules_fuzzing//fuzzing:init.bzl", "rules_fuzzing_init")
rules_fuzzing_init()
load("@fuzzing_py_deps//:requirements.bzl", "install_deps")
install_deps()
