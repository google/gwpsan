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

#include "gwpsan/core/report.h"

#include <thread>

#include "gtest/gtest.h"
#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/test_report_interceptor.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/report.h"

namespace gwpsan {
namespace {

// Trickery to prevent tail calls, optimizations and ensure stable stacks
// in debug and release builds.
SAN_NOINLINE extern "C" void NoInline() {
  SAN_BARRIER();
}

SAN_NOINLINE extern "C" void MyAccess(volatile int* data) {
  NoInline();
  *data = 1;
  NoInline();
}

SAN_NOINLINE extern "C" void MyCaller(volatile int* data) {
  NoInline();
  MyAccess(data);
  NoInline();
}

struct StackCapturer : BreakManager::Callback {
  Array<uptr, 128> stack;
  uptr size;
  uptr max_size;

  uptr OnEmulate(const CPUContext& ctx) override {
    size = UnwindStackSpan({stack.data(), max_size}, ctx.uctx());
    return 0;
  }
};

TEST(UnwindStack, Basic) {
  bool ok = true;
  ScopedBreakManagerSingleton<> mgr(ok);
  ASSERT_TRUE(ok);
  StackCapturer capturer;
  volatile int data = 0;
  enum UnwindType { kMain, kThread };
  for (UnwindType type : {kMain, kThread}) {
    for (uptr max_size : {12, 64}) {
      capturer.size = 0;
      capturer.max_size = max_size;
      // TODO(dvyukov, elver): setup the breakpoint once before the loop
      // once Arm breakpoints are fixed.
      auto* bp =
          mgr->Watch({Breakpoint::Type::kReadWrite, &data, Sizeof(data)});
      switch (type) {
        case kMain: {
          MyCaller(&data);
          break;
        }
        case kThread: {
          std::thread th([&data]() { MyCaller(&data); });
          th.join();
          break;
        }
        default:
          ASSERT_TRUE(false) << "unhandled unwind type: " << type;
      }
      mgr->Unwatch(bp);
      Printf("type=%d max_size=%zu size=%zu:\n", static_cast<int>(type),
             max_size, capturer.size);
      ReportInterceptor interceptor;
      PrintStackTrace({capturer.stack.data(), capturer.size}, "  ");
      switch (type) {
        case kMain:
          interceptor.ExpectReport(
              R"(  #0: [[MODULE]] MyAccess
  #1: [[MODULE]] MyCaller
  #2: [[MODULE]] gwpsan::(anonymous namespace)::UnwindStack_Basic_Test::TestBody()
  #3: [[MODULE]] testing::.*
[[SKIP-LINES]])"
#if GWPSAN_OPTIMIZE >= 2
              // Only with max. optimizations will main be within first 10
              // frames.
              R"(  #[[NUM]]: [[MODULE]] main
)"
#endif
          );
          break;
        case kThread:
          // Depending on standard library, and optimizations we'll end up with
          // std::function internals (due to lack of tail call optimizations) or
          // other possibly unsymbolizable functions in the stack trace as well.
          // We are limited to testing the start of the trace looks as expected.
          interceptor.ExpectReport(
              R"(  #0: [[MODULE]] MyAccess
  #1: [[MODULE]] MyCaller
[[SKIP-LINES]])");
          break;
        default:
          ASSERT_TRUE(false) << "unhandled unwind type: " << type;
      }
    }
  }
}

}  // namespace
}  // namespace gwpsan
