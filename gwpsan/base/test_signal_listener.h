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

#ifndef GWPSAN_BASE_TEST_SIGNAL_LISTENER_H_
#define GWPSAN_BASE_TEST_SIGNAL_LISTENER_H_

#include <functional>
#include <utility>

#include "gwpsan/base/common.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/synchronization.h"

namespace gwpsan SAN_LOCAL {

template <int kSig>
class TestSignalListener {
 protected:
  ~TestSignalListener() {
    SignalReceiver::singleton().reset();
  }

  // Resets OnSignalFunc, to avoid use-after-destruction by in-flight signals.
  class ScopedSignalHandler {
   public:
    ~ScopedSignalHandler() {
      // Will wait for in-flight signal handlers to finish.
      SignalReceiver::singleton()->on_signal().reset();
    }

   private:
    ScopedSignalHandler() = default;
    ScopedSignalHandler(const ScopedSignalHandler&) = delete;
    ScopedSignalHandler& operator=(const ScopedSignalHandler&) = delete;
    friend class TestSignalListener;
  };

  [[nodiscard]] ScopedSignalHandler set_on_signal(
      std::function<void(const siginfo_t& siginfo)> on_signal) {
    SignalReceiver::singleton().emplace(std::move(on_signal));
    return {};
  }

 private:
  class SignalReceiver : public SignalListener<kSig, SignalReceiver>,
                         public SynchronizedSingleton<SignalReceiver> {
    using OnSignalFunc = Optional<std::function<void(const siginfo_t& siginfo)>,
                                  OptionalSyncMultipleAccess>;

   public:
    explicit SignalReceiver(
        std::function<void(const siginfo_t& siginfo)> on_signal) {
      on_signal_.emplace(std::move(on_signal));
      SAN_CHECK(this->InstallSignalHandler());
    }

    bool OnSignal(int sig, siginfo_t* siginfo, void* uctx) {
      on_signal_.and_then_sync([=](auto& f) { f(*siginfo); });
      return true;  // Assume all signals handled by test.
    }

    OnSignalFunc& on_signal() {
      return on_signal_;
    }

   private:
    OnSignalFunc on_signal_;
  };
};

}  // namespace gwpsan SAN_LOCAL

#endif  // GWPSAN_BASE_TEST_SIGNAL_LISTENER_H_
