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

"""cc_implicit_output rule to expose implicit outputs from cc_library"""

def _get_file_from_list(artifacts, file_short_path):
    for artifact in artifacts:
        if artifact != None and artifact.short_path == file_short_path:
            return [artifact]

    fail("Could not find implicit output '" + file_short_path + "' in the listed dependency")

def _create_short_path(ctx):
    target = ctx.attr.files[0]
    if not target.startswith("//"):
        target = "//" + ctx.label.package + target

    return target[2:].replace(":", "/")

def _cc_implicit_output_impl(ctx):
    if len(ctx.attr.deps) != 1:
        fail("Exactly one dependency required.")
    if len(ctx.attr.files) != 1:
        fail("Exactly one file required.")

    linker_inputs = ctx.attr.deps[0][CcInfo].linking_context.linker_inputs.to_list()
    if len(linker_inputs) == 0 or len(linker_inputs[0].libraries) == 0:
        return DefaultInfo()

    library_to_link = linker_inputs[0].libraries[0]

    file_short_path = _create_short_path(ctx)
    files = _get_file_from_list([
        library_to_link.static_library,
        library_to_link.pic_static_library,
        library_to_link.dynamic_library,
        library_to_link.resolved_symlink_dynamic_library,
    ], file_short_path)

    return DefaultInfo(
        files = depset(files),
        runfiles = ctx.runfiles(files = files),
    )

cc_implicit_output = rule(
    implementation = _cc_implicit_output_impl,
    attrs = {
        "deps": attr.label_list(
            providers = [CcInfo],
        ),
        "files": attr.string_list(),
    },
)
