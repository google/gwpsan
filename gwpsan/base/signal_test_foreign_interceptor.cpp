// Copyright 2024 The GWPSan Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Test that foreign interceptors, with or without sanitizers, will not
// interfere with gwpsan's interception. Follows the protocol described in
// compiler-rt:
//
//  https://github.com/llvm/llvm-project/blob/a68c96875566/compiler-rt/lib/interception/interception.h#L86
//

// For this test, __interceptor_sigaction can be non-weak, because we only test
// it in the presence of gwpsan as well.
extern "C" int __interceptor_sigaction(int sig, const struct sigaction* act,
                                       struct sigaction* old);

extern "C" int sigaction(int sig, const struct sigaction* act,
                         struct sigaction* old) {
  return __interceptor_sigaction(sig, act, old);
}
