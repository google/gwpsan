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

#include <ios>
#include <ostream>

#include "gwpsan/base/units.h"

namespace gwpsan {

template <>
std::ostream& operator<<(std::ostream& os, const BitSize& val) {
  return os << *val << "bits";
}

template <>
std::ostream& operator<<(std::ostream& os, const ByteSize& val) {
  return os << *val << "bytes";
}

template <>
std::ostream& operator<<(std::ostream& os, const WordSize& val) {
  return os << *val << "words";
}

template <>
std::ostream& operator<<(std::ostream& os, const Addr& val) {
  return os << std::hex << std::showbase << *val;
}

template <>
std::ostream& operator<<(std::ostream& os, const Seconds& val) {
  return os << *val << "sec";
}

template <>
std::ostream& operator<<(std::ostream& os, const Milliseconds& val) {
  return os << *val << "msec";
}

template <>
std::ostream& operator<<(std::ostream& os, const Microseconds& val) {
  return os << *val << "usec";
}

template <>
std::ostream& operator<<(std::ostream& os, const Nanoseconds& val) {
  return os << *val << "nsec";
}

}  // namespace gwpsan
