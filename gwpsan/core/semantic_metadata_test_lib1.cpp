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

static volatile int var;

// There seems to be a compiler issue with returning the label address with GCOV
// enabled. Disable instrumentation - we don't need it here.
__attribute__((no_profile_instrument_function)) extern "C" long no_atomics() {
  var = var + 1;
  var = var - 1;
here:
  return reinterpret_cast<long>(&&here) + 0;
}

__attribute__((no_profile_instrument_function)) extern "C" long atomics() {
  var = var + 1;
  __atomic_store_n(&var, 1, __ATOMIC_RELAXED);
  var = var - 1;
here:
  return reinterpret_cast<long>(&&here) + 0;
}
