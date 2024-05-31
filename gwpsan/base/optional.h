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

#ifndef THIRD_PARTY_GWP_SANITIZERS_BASE_OPTIONAL_H_
#define THIRD_PARTY_GWP_SANITIZERS_BASE_OPTIONAL_H_

#include "gwpsan/base/common.h"

namespace gwpsan SAN_LOCAL {

// Default sync implementation: no synchronization across threads.
struct OptionalUnsynced {
  // Called after emplace().
  constexpr void Emplace() {}
  // Called before reset() (if engaged).
  constexpr void ResetBegin() {}
  // Called after reset() (if engaged).
  constexpr void ResetEnd() {}
  // Acquire access with and_then_sync().
  constexpr bool Acquire() {
    return true;
  }
  // Release access with and_then_sync().
  constexpr void Release() {}
};

// Base class for Optional without constructor/destructor. On its own useful for
// lazily initialized global objects with constant initialization that can
// optionally be initialized, re-initialized, but not automatically destroyed.
//
// The class Sync can optionally provide the ability to synchronize the entire
// Optional (without additional wrappers), where concurrent accesses are done
// via and_then_sync(); as a side-effect this avoids data races on `engaged_`.
template <typename T, typename Sync = OptionalUnsynced>
class OptionalBase {
 public:
  using value_type = T;

  constexpr OptionalBase() = default;

  constexpr OptionalBase& operator=(const OptionalBase& rhs) {
    if (rhs.has_value())
      emplace(rhs.ref());
    else
      reset();
    return *this;
  }
  constexpr OptionalBase& operator=(OptionalBase&& rhs) {
    if (rhs.has_value())
      emplace(gwpsan::move(rhs.ref()));
    else
      reset();
    return *this;
  }
  constexpr OptionalBase& operator=(const T& val) {
    emplace(val);
    return *this;
  }
  constexpr OptionalBase& operator=(T&& val) {
    emplace(gwpsan::move(val));
    return *this;
  }

  constexpr void reset() {
    if (has_value()) {
      sync_.ResetBegin();
      ref().~T();
      set_engaged(false);
    }
  }

  template <typename... Args>
  constexpr T& emplace(Args&&... args) {
    reset();
    // Note: Here and elsewhere we fully qualify forward/move, so that we can
    // use Optional with std containers withour tripping over ambiguous lookups
    // due to ADL.
    new (Placed(mem_)) T(gwpsan::forward<Args>(args)...);
    set_engaged(true);
    return ref();
  }

  constexpr bool has_value() const {
    return engaged_;
  }

  constexpr explicit operator bool() const {
    return has_value();
  }

  constexpr bool operator==(const OptionalBase& rhs) const {
    const bool has_lhs = has_value();
    const bool has_rhs = rhs.has_value();
    if (has_lhs && has_rhs)
      return ref() == rhs.ref();
    return has_lhs == has_rhs;
  }
  constexpr bool operator!=(const OptionalBase& rhs) const {
    return !(*this == rhs);
  }

  constexpr const T* operator->() const {
    SAN_CHECK(has_value());
    return &ref();
  }
  constexpr T* operator->() {
    SAN_CHECK(has_value());
    return &ref();
  }
  constexpr const T& operator*() const& {
    SAN_CHECK(has_value());
    return ref();
  }
  constexpr T& operator*() & {
    SAN_CHECK(has_value());
    return ref();
  }
  constexpr T&& operator*() && {
    SAN_CHECK(has_value());
    return gwpsan::move(ref());
  }
  constexpr const T&& operator*() const&& {
    SAN_CHECK(has_value());
    return gwpsan::move(ref());
  }
  constexpr const T& value() const& {
    SAN_CHECK(has_value());
    return ref();
  }
  constexpr T& value() & {
    SAN_CHECK(has_value());
    return ref();
  }
  constexpr T&& value() && {
    SAN_CHECK(has_value());
    return gwpsan::move(ref());
  }
  constexpr const T&& value() const&& {
    SAN_CHECK(has_value());
    return gwpsan::move(ref());
  }

  template <typename U>
  constexpr T value_or(U&& def_val) const& {
    return has_value() ? ref() : static_cast<T>(gwpsan::forward<U>(def_val));
  }
  template <typename U>
  constexpr T value_or(U&& def_val) && {
    return has_value() ? gwpsan::move(ref())
                       : static_cast<T>(gwpsan::forward<U>(def_val));
  }

  // Unlike std::optional, F may return any type, as long as we can
  // default-construct the type.
  template <typename F>
  constexpr auto and_then(F f) & {
    return has_value() ? f(ref()) : decltype(f(ref()))();
  }
  template <typename F>
  constexpr auto and_then(F&& f) && {
    return has_value() ? f(gwpsan::move(ref()))
                       : decltype(f(gwpsan::move(ref())))();
  }
  template <typename F>
  constexpr auto and_then(F&& f) const& {
    return has_value() ? f(ref()) : decltype(f(ref()))();
  }
  template <typename F>
  constexpr auto and_then(F&& f) const&& {
    return has_value() ? f(gwpsan::move(ref()))
                       : decltype(f(gwpsan::move(ref())))();
  }

  // ----- Non-standard extensions -----

  constexpr T* ptr_or(T* def_ptr = nullptr) {
    return has_value() ? &ref() : def_ptr;
  }
  constexpr const T* ptr_or(const T* def_ptr = nullptr) const {
    return has_value() ? &ref() : def_ptr;
  }

  constexpr T& value_unchecked() {
    SAN_DCHECK(has_value());
    return ref();
  }

  template <typename F>
  auto and_then_sync(F f) {
    if (sync_.Acquire()) {
      // Need CleanupRef for supporting return void.
      auto release = [this] { sync_.Release(); };
      CleanupRef release_cleanup(release);
      return has_value() ? f(ref()) : decltype(f(ref()))();
    }
    return decltype(f(ref()))();
  }

  // Our construction protocol is that constructors accept a bool 'ok' to denote
  // success or not; helper to pass 'ok' to a constructor and automatically
  // destroy and return nullptr on failure.
  template <typename... Args>
  [[nodiscard]] constexpr OptionalBase& try_emplace(Args&&... args) {
    bool ok = true;
    emplace(ok, gwpsan::forward<Args>(args)...);
    if (!ok)
      reset();
    return *this;
  }

 protected:
  constexpr T& ref() {
    return *reinterpret_cast<T*>(mem_);
  }
  constexpr const T& ref() const {
    return *reinterpret_cast<const T*>(mem_);
  }

  constexpr void set_engaged(bool val) {
    engaged_ = val;
    if (val)
      sync_.Emplace();
    else
      sync_.ResetEnd();
  }

  // Other implementations typically use a union with T, however, this results
  // in the default destructor being deleted; also, defining a destructor does
  // not work here because we enforce no exit-time destructors being called
  // which would preclude us from using OptionalBase<T> as a global.
  union {
    // Single-element union to allow constinit while mem_ isn't initialized.
    alignas(T) char mem_[sizeof(T)];
  };
  bool engaged_ = false;
  Sync sync_;
};

// Internal replacement for std::optional.
template <typename T, typename Sync = OptionalUnsynced>
class Optional : public OptionalBase<T, Sync> {
 public:
  using OptionalBase<T, Sync>::operator=;
  using OptionalBase<T, Sync>::OptionalBase;

  constexpr Optional(const Optional& rhs)
      : Optional() {
    operator=(rhs);
  }
  constexpr Optional(Optional&& rhs)
      : Optional() {
    operator=(gwpsan::move(rhs));
  }
  constexpr Optional(const T& val) {
    new (Placed(this->mem_)) T(val);
    this->set_engaged(true);
  }
  constexpr Optional(T&& val) {
    new (Placed(this->mem_)) T(gwpsan::move(val));
    this->set_engaged(true);
  }

  ~Optional() {
    this->reset();
  }

  constexpr Optional& operator=(const Optional& rhs) {
    OptionalBase<T, Sync>::operator=(rhs);
    return *this;
  }
  constexpr Optional& operator=(Optional&& rhs) {
    OptionalBase<T, Sync>::operator=(gwpsan::move(rhs));
    return *this;
  }
};

// Allow class template argument deduction.
template <typename T>
Optional(T) -> Optional<T>;

}  // namespace gwpsan SAN_LOCAL

#endif  // THIRD_PARTY_GWP_SANITIZERS_BASE_OPTIONAL_H_
