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

#include "gwpsan/base/test_report_interceptor.h"

#include <chrono>
#include <functional>
#include <string>

#include "gtest/gtest.h"
#include "absl/strings/str_replace.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/synchronization.h"
#include "re2/re2.h"

namespace gwpsan {

std::string ReportRegexp(const char* report) {
  auto res = absl::StrReplaceAll(
      report,
      {
          {"[",              "\\["                                              },
          {"]",              "\\]"                                              },
          {"(",              "\\("                                              },
          {")",              "\\)"                                              },
          {"$",              "\\$"                                              },
          {"[[MARKER]]",
           "====================================="
           "============================"                                       },
          {"[[ANY]]",        ".*"                                               },
          {"[[PC]]",         "(0x)?[a-f0-9]+ \\([a-zA-Z0-9_-]+\\+0x[a-f0-9]+\\)"},
          {"[[FUNC]]",       "[a-zA-Z0-9_:<>()]+"                               },
          {"[[MODULE]]",
           "\\([a-zA-Z0-9_.-]+\\+0x[a-f0-9]+\\)( [a-zA-Z0-9_.+-/]+:[0-9]+)?"    },
          {"[[ADDR]]",       "0x[a-f0-9]+"                                      },
          {"[[NUM]]",        "[0-9]+"                                           },
          {"[[SKIP-LINES]]", "(.*\n)*.*"                                        },
  });
  // Most likely a typo in one of these replacements.
  SAN_CHECK_EQ(internal_strstr(res.c_str(), "\\[\\["), nullptr);
  return res;
}

void ExpectReport(std::function<void()> const& body, const char* report,
                  int timeout_sec) {
  ReportInterceptor report_interceptor;
  using clock = std::chrono::high_resolution_clock;
  const auto start = clock::now();
  while (report_interceptor.Empty() &&
         clock::now() - start < std::chrono::seconds{timeout_sec})
    for (int i = 0; i < 10 && report_interceptor.Empty(); i++)
      body();
  report_interceptor.ExpectPartial(report);
}

void ExpectDeathReport(std::function<void()> const& body, const char* report,
                       int timeout_sec) {
  EXPECT_DEATH(
      ({
        using clock = std::chrono::high_resolution_clock;
        const auto start = clock::now();
        while (clock::now() - start < std::chrono::seconds{timeout_sec}) {
          for (int i = 0; i < 10; i++)
            body();
        }
      }),
      ReportRegexp(report));
}

ReportInterceptor::ReportInterceptor() {
  SetPrintfCallback({*this});
}

ReportInterceptor::~ReportInterceptor() {
  SetPrintfCallback({});
}

std::string ReportInterceptor::output() const {
  Lock lock(mtx_);
  return output_;
}

bool ReportInterceptor::Empty() const {
  return !__atomic_load_n(&has_output_, __ATOMIC_RELAXED);
}

void ReportInterceptor::ExpectReport(const char* report) {
  Expect(report, false);
}

void ReportInterceptor::ExpectPartial(const char* report) {
  Expect(report, true);
}

void ReportInterceptor::Expect(const char* report, bool partial) {
  const std::string re = ReportRegexp(report);
  bool res;
  if (partial)
    res = RE2::PartialMatch(output(), re);
  else
    res = RE2::FullMatch(output(), re);
  EXPECT_TRUE(res) << "Expected:\n" << report;
}

void ReportInterceptor::ExpectRegexp(const char* re) {
  EXPECT_TRUE(RE2::FullMatch(output(), re));
}

void ReportInterceptor::operator()(const Span<const char>& str) {
  Lock lock(mtx_);
  output_.append(str.data(), str.size());
  __atomic_store_n(&has_output_, true, __ATOMIC_RELAXED);
}

}  // namespace gwpsan
