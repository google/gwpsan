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

extern "C" const char* gwpsan_default_flags() {
  return "test_mode:"
         "must_init:"
         "log_failures:"
         "sample_interval_usec=1000:"
         "tsan_delay_usec=500:"
         "uar_check_every_nth_thread=1:";
}
