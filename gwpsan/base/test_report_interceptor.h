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

#ifndef GWPSAN_BASE_TEST_REPORT_INTERCEPTOR_H_
#define GWPSAN_BASE_TEST_REPORT_INTERCEPTOR_H_

#include <functional>
#include <string>

#include "gwpsan/base/common.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/synchronization.h"

namespace gwpsan SAN_LOCAL {

std::string ReportRegexp(const char* report);
void ExpectReport(std::function<void()> const& body, const char* report,
                  int timeout_sec = 100);
void ExpectDeathReport(std::function<void()> const& body, const char* report,
                       int timeout_sec = 100);

class ReportInterceptor {
 public:
  ReportInterceptor();
  ~ReportInterceptor();

  std::string output() const;
  bool Empty() const;
  void ExpectReport(const char* report);
  void ExpectPartial(const char* report);
  void ExpectRegexp(const char* re);

 private:
  mutable Mutex mtx_;
  std::string output_;
  bool has_output_ = false;

  void Expect(const char* report, bool partial);

  // Printf() callback.
  void operator()(const Span<const char>& str);
  friend PrintfCallback;

  ReportInterceptor(const ReportInterceptor&) = delete;
  ReportInterceptor& operator=(const ReportInterceptor&) = delete;
};

}  // namespace gwpsan SAN_LOCAL

#endif
