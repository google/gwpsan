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

load("@bazel_skylib//rules:common_settings.bzl", "string_flag")

package(default_applicable_licenses = ["//:license"])

config_setting(
    name = "mode_dbg",
    values = {
        "compilation_mode": "dbg",
    },
)

config_setting(
    name = "mode_fastbuild",
    values = {
        "compilation_mode": "fastbuild",
    },
)

config_setting(
    name = "mode_opt",
    values = {
        "compilation_mode": "opt",
    },
)

string_flag(
    name = "sanitizer",
    build_setting_default = "",
)

config_setting(
    name = "sanitizer_msan",
    flag_values = {
        ":sanitizer": "msan",
    },
)
