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

load("@rules_license//rules:license.bzl", "license")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//gwpsan:__subpackages__"],
)

license(
    name = "license",
    package_name = "gwpsan",
    copyright_notice = "Copyright © 2024 The GWPSan Authors. All rights reserved.",
    license_kinds = [
        "@rules_license//licenses/spdx:Apache-2.0",
    ],
    license_text = "LICENSE",
)

licenses(["notice"])

exports_files(["LICENSE"])
