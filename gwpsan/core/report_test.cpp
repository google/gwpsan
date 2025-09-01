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

#include <signal.h>
#include <sys/time.h>

#include <cstddef>
#include <span>
#include <thread>

#include "gtest/gtest.h"
#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/test_report_interceptor.h"
#include "gwpsan/base/units.h"
#include "gwpsan/base/unwind.h"
#include "gwpsan/core/breakmanager.h"
#include "gwpsan/core/breakpoint.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/report.h"

namespace gwpsan {
namespace {

volatile int data = 0;
volatile bool signal_fired = false;

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

SAN_NOINLINE extern "C" void SigprofHandler(int sig) {
  MyCaller(&data);
  signal_fired = true;
}

struct StackCapturer : BreakManager::Callback {
  Array<uptr, 128> stack;
  uptr size;
  uptr max_size;
  bool raw_unwind;

  uptr OnEmulate(const CPUContext& ctx) override {
    if (raw_unwind) {
      // This unwinds as our SAN_WARN macro from the runtime would do.
      // It starts from the current frame, so will include all of our
      // runtime frames.
      size =
          RawUnwindStack({stack.data(), max_size}, __builtin_frame_address(0));
    } else {
      size = UnwindStackSpan({stack.data(), max_size}, ctx.uctx());
    }
    return 0;
  }
};

TEST(UnwindStack, Basic) {
  bool ok = true;
  ScopedBreakManagerSingleton<> mgr(ok);
  ASSERT_TRUE(ok);
  StackCapturer capturer;
  struct sigaction oldact = {};
  struct sigaction act = {};
  act.sa_handler = SigprofHandler;
  ASSERT_NE(sigaction(SIGALRM, &act, &oldact), -1);
  enum UnwindType { kMain, kThread, kSyncSignal, kAsyncSignal };
  for (UnwindType type : {kMain, kThread, kSyncSignal, kAsyncSignal}) {
    for (bool raw_unwind : {false, true}) {
      for (uptr max_size : {12, 64}) {
        capturer.size = 0;
        capturer.max_size = max_size;
        capturer.raw_unwind = raw_unwind;
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
            std::thread th([]() { MyCaller(&data); });
            th.join();
            break;
          }
          case kSyncSignal: {
            raise(SIGALRM);
            break;
          }
          case kAsyncSignal: {
            signal_fired = false;
            itimerval interval = {};
            interval.it_value.tv_usec = 1000;
            ASSERT_NE(setitimer(ITIMER_REAL, &interval, nullptr), -1);
            while (!signal_fired) {
            }
            break;
          }
          default:
            ASSERT_TRUE(false) << "unhandled unwind type: " << type;
        }
        mgr->Unwatch(bp);
        Printf("type=%d raw_unwind=%d max_size=%zu size=%zu:\n",
               static_cast<int>(type), raw_unwind, max_size, capturer.size);
        ReportInterceptor interceptor;
        PrintStackTrace({capturer.stack.data(), capturer.size}, "  ");
        if (raw_unwind) {
          // In raw unwind mode we check just few basic things,
          // it's too painful to do more precise check for our runtime.
          // We are mostly interested that it does not crash on the
          // sigreturn frames, etc.
          interceptor.ExpectReport(
              R"([[SKIP-LINES]]
.* gwpsan::BreakManager::OnBreakpoint()
[[SKIP-LINES]]
.* MyCaller
[[SKIP-LINES]])");
        } else {
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
              // Depending on standard library, and optimizations we'll end up
              // with std::function internals (due to lack of tail call
              // optimizations) or other possibly unsymbolizable functions in
              // the stack trace as well. We are limited to testing the start of
              // the trace looks as expected.
              interceptor.ExpectReport(
                  R"(  #0: [[MODULE]] MyAccess
  #1: [[MODULE]] MyCaller
[[SKIP-LINES]])");
              break;
            case kSyncSignal:
            case kAsyncSignal:
              interceptor.ExpectReport(
                  R"(  #0: [[MODULE]] MyAccess
  #1: [[MODULE]] MyCaller
  #2: [[MODULE]] SigprofHandler
)"
// With MSan there may be another SignalHandler frame here.
#if !GWPSAN_INSTRUMENTED_MSAN
                  R"(  #3: [[SIGRETURN_FRAME]]
)"
#endif
                  "[[SKIP-LINES]]");
              break;
            default:
              ASSERT_TRUE(false) << "unhandled unwind type: " << type;
          }
        }
      }
    }
  }
  ASSERT_NE(sigaction(SIGALRM, &oldact, nullptr), -1);
}

SAN_NOINLINE extern "C" size_t CorruptedUnwind(std::span<uptr> stack) {
  NoInline();
  size_t size =
      RawUnwindStack({stack.data(), stack.size()}, __builtin_frame_address(0));
  NoInline();
  return size;
}

SAN_NOINLINE extern "C" size_t CorruptingFrame(std::span<uptr> stack,
                                               bool frame_or_pc) {
  NoInline();
  uptr& frame =
      reinterpret_cast<uptr*>(__builtin_frame_address(0))[frame_or_pc ? 0 : 1];
  uptr orig = frame;
  // We need some PC that always faults, but is not obviously bogus
  // (e.g. around 0, we filter these earlier). Sanitizers map lots of memory
  // as shadow, so we use a non-canonical address that we don't filter out.
  frame = 0x00dead0012345678;
  NoInline();
  size_t size = CorruptedUnwind(stack);
  NoInline();
  frame = orig;
  return size;
}

SAN_NOINLINE extern "C" size_t CorruptedCaller(std::span<uptr> stack,
                                               bool frame_or_pc) {
  NoInline();
  size_t size = CorruptingFrame(stack, frame_or_pc);
  NoInline();
  return size;
}

TEST(UnwindStack, Corrupted) {
  // Ensure our unwinding procedure does not crash on corrupted stack frames
  // (both frame pointers and PC values).
  for (bool frame_or_pc : {true, false}) {
    Array<uptr, 64> stack;
    size_t size = CorruptedCaller(stack, frame_or_pc);
    Printf("frame_or_pc=%d size=%zu:\n", frame_or_pc, size);
    ReportInterceptor interceptor;
    PrintStackTrace({stack.data(), size}, "  ");
    if (frame_or_pc) {
      interceptor.ExpectReport(
          R"(  #0: [[MODULE]] CorruptingFrame
  #1: [[MODULE]] CorruptedCaller
)");
    } else {
      interceptor.ExpectReport(
          R"(  #0: [[MODULE]] CorruptingFrame
  #1:  0xdead0012345678 (unknown)
[[SKIP-LINES]])
  #[[NUM]]: [[MODULE]] main
)");
    }
  }
}

}  // namespace
}  // namespace gwpsan
