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

#ifndef GWPSAN_BASE_COMMON_H_
#define GWPSAN_BASE_COMMON_H_

// Since common.h is included in many places, including tests, we might get
// naming conflicts if macros don't have a namespace prefix. For brevity, use
// "SAN_" as the macro prefix.

#include "gwpsan/base/config.h"  // IWYU pragma: export
#include "gwpsan/base/stdlib.h"  // IWYU pragma: keep

#define SAN_ALIAS(x) __attribute__((alias(#x)))
#define SAN_FORMAT(f, a) __attribute__((format(printf, f, a)))
#define SAN_ALWAYS_INLINE inline __attribute__((always_inline))
#define SAN_MUSTTAIL [[clang::musttail]]
#define SAN_NOINLINE __attribute__((noinline))
#define SAN_OPTNONE __attribute__((optnone))
#define SAN_LIKELY(x) __builtin_expect(!!(x), 1)
#define SAN_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define SAN_UNREACHABLE() __builtin_unreachable()
#define SAN_UNUSED __attribute__((unused))
#define SAN_USED __attribute__((used, retain))
#define SAN_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
// We always use initial-exec to avoid external __tls_get_addr calls.
#define SAN_THREAD_LOCAL \
  SAN_IMPORT __attribute__((tls_model("initial-exec"))) thread_local
#define SAN_STRINGIFY1(S) #S
#define SAN_STRINGIFY(S) SAN_STRINGIFY1(S)
#define SAN_CALLER_PC() reinterpret_cast<uptr>(__builtin_return_address(0))
#define SAN_CURRENT_FRAME() reinterpret_cast<uptr>(__builtin_frame_address(0))
#define SAN_BARRIER() asm volatile("" ::: "memory")
#define SAN_WEAK_DEFAULT __attribute__((weak))
#define SAN_NAKED SAN_NOINSTR __attribute__((naked))
#define SAN_PRESERVE_ALL __attribute__((preserve_all))
#define SAN_SECTION(name) __attribute__((section(#name)))
#define SAN_DECLARE_SECTION_VARS(type, name)    \
  extern type __start_##name[] SAN_WEAK_IMPORT; \
  extern type __stop_##name[] SAN_WEAK_IMPORT
// The priority of __sanitizer_metadata_*() ctor/dtor callbacks in LLVM is 2;
// ensure that all our ctors/dtors run after/before respectively, but still
// earlier/later than most other ctors/dtors.
#define SAN_CONSTRUCTOR __attribute__((constructor(3)))
#define SAN_DESTRUCTOR __attribute__((destructor(3)))
#define SAN_EXPORT SAN_USED __attribute__((visibility("default")))
#define SAN_IMPORT __attribute__((visibility("default")))
#define SAN_LOCAL __attribute__((visibility("hidden")))
#define SAN_WEAK_EXPORT SAN_EXPORT SAN_WEAK_DEFAULT
#define SAN_WEAK_IMPORT SAN_IMPORT SAN_WEAK_DEFAULT
#define SAN_WEAK_LOCAL SAN_LOCAL SAN_WEAK_DEFAULT
#define SAN_INTERFACE extern "C" SAN_EXPORT

// SAN_INVISIBLE_GOTO() should be used (approximately) where we may "invisibly",
// such as through signal handler, jump to another code location.
//
// Extended Asm ("asm goto") ensures that the compiler doesn't consider the code
// at the label as dead, and keeps it as a result. The clobber ensures the
// compiler doesn't try to optimize the code at the label in any way based on
// state here. Right after the label, a SAN_BARRIER() should be used.
#define SAN_INVISIBLE_GOTO(label) asm volatile goto("" ::: "memory" : label);

// See compiler-rt's interception.h comments for Linux. To implement an
// interceptor in GWPSan:
//
//    SAN_DECLARE_INTERCEPTOR(ret_type, func, ...func args...)
//
// and elsewhere, implement __interceptor_func. Before forwarding to the "real"
// implementation, check if ___interceptor_func is non-null, and if so call it
// instead (forwarding to compiler-rt sanitizer).
#define SAN_DECLARE_INTERCEPTOR(ret_type, func, ...)                      \
  SAN_INTERFACE ret_type __interceptor_##func(__VA_ARGS__);               \
  extern "C" SAN_WEAK_IMPORT ret_type ___interceptor_##func(__VA_ARGS__); \
  SAN_INTERFACE SAN_WEAK_DEFAULT ret_type func(__VA_ARGS__)               \
      SAN_ALIAS(__interceptor_##func)

// For functions that should not receive any compiler generated instrumentation
// inserted _into_ the function itself, while still avoiding false positives.
// Note, disable_sanitizer_instrumentation can produce false positives, and also
// disable binary metadata generation, which we want to retain.
#define SAN_NOINSTR                                            \
  SAN_NOINLINE __attribute__((no_profile_instrument_function)) \
  __attribute__((no_instrument_function))                      \
  __attribute__((no_sanitize("address")))                      \
  __attribute__((no_sanitize("hwaddress")))                    \
  __attribute__((no_sanitize("thread")))                       \
  __attribute__((no_sanitize("memory")))                       \
  __attribute__((no_sanitize("undefined")))                    \
  __attribute__((no_sanitize("coverage")))

// Use this only where SAN_NOINSTR does not work. In particular, MSan still
// emits instrumentation in few cases with no_sanitize to avoid false positives.
// Care must be taken to avoid MSan false positives.
#define SAN_NOINSTR_BRITTLE \
  SAN_NOINSTR __attribute__((disable_sanitizer_instrumentation))

#define SAN_DIAGNOSE_AS1(name) \
  __attribute__((diagnose_as_builtin(__builtin_##name, 1)));
#define SAN_DIAGNOSE_AS2(name) \
  __attribute__((diagnose_as_builtin(__builtin_##name, 1, 2)));
#define SAN_DIAGNOSE_AS3(name) \
  __attribute__((diagnose_as_builtin(__builtin_##name, 1, 2, 3)));

#define SAN_PUSH_DIAG(diag)                                         \
  _Pragma("clang diagnostic push");                                 \
  _Pragma("clang diagnostic ignored \"-Wunknown-warning-option\""); \
  _Pragma(SAN_STRINGIFY(clang diagnostic ignored diag))
#define SAN_POP_DIAG() _Pragma("clang diagnostic pop")

namespace gwpsan SAN_LOCAL {

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned long long u64;
typedef signed long long s64;
typedef unsigned __int128 u128;
typedef signed __int128 s128;
typedef unsigned long uptr;
typedef signed long sptr;

inline constexpr uptr kByteBits = 8;
inline constexpr uptr kWordBits = kByteBits * sizeof(uptr);
inline constexpr uptr kPageSize = 4 << 10;

void* internal_memchr(const void* s, int c, uptr n) SAN_DIAGNOSE_AS3(memchr);
int internal_memcmp(const void* s1, const void* s2, uptr n)
    SAN_DIAGNOSE_AS3(memcmp);
void* internal_memcpy(void* dest, const void* src, uptr n)
    SAN_DIAGNOSE_AS3(memcpy);
void* internal_memset(void* s, int c, uptr n) SAN_DIAGNOSE_AS3(memset);
int internal_strcmp(const char* s1, const char* s2) SAN_DIAGNOSE_AS2(strcmp);
char* internal_strchr(const char* s, int c) SAN_DIAGNOSE_AS2(strchr);
char* internal_strrchr(const char* s, int c) SAN_DIAGNOSE_AS2(strrchr);
uptr internal_strlen(const char* s) SAN_DIAGNOSE_AS1(strlen);
char* internal_strncpy(char* dst, const char* src, uptr n)
    SAN_DIAGNOSE_AS3(strncpy);
char* internal_strstr(const char* str, const char* what)
    SAN_DIAGNOSE_AS2(strstr);

// Note: Avoid using SAN_BUG() and prefer SAN_WARN() where the code can possibly
// recover - we should avoid crashing production binaries!
#define SAN_BUG(msg, ...)                                                      \
  BugImpl("T%u " __FILE_NAME__ ":" SAN_STRINGIFY(__LINE__) ": BUG: " msg "\n", \
          GetTid(), ##__VA_ARGS__)

#define SAN_WARN_IMPL(condition, condition_str, msg, ...)              \
  (SAN_UNLIKELY(condition)                                             \
       ? (WarnImpl("T%u " __FILE_NAME__                                \
                   ":" SAN_STRINGIFY(__LINE__) ": WARN: %s " msg "\n", \
                   GetTid(), condition_str, ##__VA_ARGS__),            \
          true)                                                        \
       : false)
#define SAN_WARN(condition, ...) \
  SAN_WARN_IMPL(condition, "(" #condition ")", "" __VA_ARGS__)
#define SAN_WARN_IF_ERR_IMPL(condition, condition_str, res, msg, ...) \
  SAN_WARN_IMPL(condition, condition_str, msg, (res).err(), ##__VA_ARGS__)
#define SAN_WARN_IF_ERR(res, ...) \
  SAN_WARN_IF_ERR_IMPL(!(res), #res, (res), "failed (errno=%d) " __VA_ARGS__)

// Note: Avoid using SAN_CHECK*() and prefer SAN_WARN() where the code can
// possibly recover - we should avoid crashing production binaries!
#define SAN_CHECK_IMPL(condition, str, msg, ...)                        \
  do {                                                                  \
    if (SAN_UNLIKELY(!(condition))) {                                   \
      BugImpl("T%u %s:%d: CHECK: %s (false) " msg " in %s\n", GetTid(), \
              __FILE_NAME__, __LINE__, str, ##__VA_ARGS__,              \
              __PRETTY_FUNCTION__);                                     \
    }                                                                   \
  } while (false)
#define SAN_CHECK_OP_IMPL(c1, op, c2, cs1, cs2)                              \
  do {                                                                       \
    if (SAN_UNLIKELY(!((c1)op(c2)))) {                                       \
      BugImpl("T%u %s:%d: CHECK: %s %s %s (%lld %s %lld) in %s\n", GetTid(), \
              __FILE_NAME__, __LINE__, cs1, #op, cs2, (s64)(c1), #op,        \
              (s64)(c2), __PRETTY_FUNCTION__);                               \
    }                                                                        \
  } while (false)
#define SAN_CHECK(a, ...) SAN_CHECK_IMPL(a, #a, "" __VA_ARGS__)
#define SAN_CHECK_EQ(a, b) SAN_CHECK_OP_IMPL((a), ==, (b), #a, #b)
#define SAN_CHECK_NE(a, b) SAN_CHECK_OP_IMPL((a), !=, (b), #a, #b)
#define SAN_CHECK_LT(a, b) SAN_CHECK_OP_IMPL((a), <, (b), #a, #b)
#define SAN_CHECK_LE(a, b) SAN_CHECK_OP_IMPL((a), <=, (b), #a, #b)
#define SAN_CHECK_GT(a, b) SAN_CHECK_OP_IMPL((a), >, (b), #a, #b)
#define SAN_CHECK_GE(a, b) SAN_CHECK_OP_IMPL((a), >=, (b), #a, #b)

#if GWPSAN_DEBUG
#define SAN_DCHECK(a, ...) SAN_CHECK_IMPL(a, #a, "" __VA_ARGS__)
#define SAN_DCHECK_EQ(a, b) SAN_CHECK_OP_IMPL((a), ==, (b), #a, #b)
#define SAN_DCHECK_NE(a, b) SAN_CHECK_OP_IMPL((a), !=, (b), #a, #b)
#define SAN_DCHECK_LT(a, b) SAN_CHECK_OP_IMPL((a), <, (b), #a, #b)
#define SAN_DCHECK_LE(a, b) SAN_CHECK_OP_IMPL((a), <=, (b), #a, #b)
#define SAN_DCHECK_GT(a, b) SAN_CHECK_OP_IMPL((a), >, (b), #a, #b)
#define SAN_DCHECK_GE(a, b) SAN_CHECK_OP_IMPL((a), >=, (b), #a, #b)
#else  // GWPSAN_DEBUG
#define SAN_DCHECK(a, ...) \
  do {                     \
  } while (false)
#define SAN_DCHECK_EQ(a, b) \
  do {                      \
  } while (false)
#define SAN_DCHECK_NE(a, b) \
  do {                      \
  } while (false)
#define SAN_DCHECK_LT(a, b) \
  do {                      \
  } while (false)
#define SAN_DCHECK_LE(a, b) \
  do {                      \
  } while (false)
#define SAN_DCHECK_GT(a, b) \
  do {                      \
  } while (false)
#define SAN_DCHECK_GE(a, b) \
  do {                      \
  } while (false)
#endif  // GWPSAN_DEBUG

// Most of our code should be signal-handler safe, since most of what we execute
// is happening in signal handlers. However, some code cannot run in signal
// handlers (e.g. calls into external library functions). Use this check in code
// that _cannot_ run inside signal handlers. A macro, so that it gives us better
// line numbers and diagnostics.
#define SAN_DCHECK_NOT_SIGNAL_HANDLER() SAN_DCHECK_EQ(InSignalHandler(), 0)

// Use this to make safe external library calls, e.g. to standard libraries.
#define SAN_LIBCALL(lib_call)        \
  ({                                 \
    SAN_DCHECK_NOT_SIGNAL_HANDLER(); \
    ::lib_call;                      \
  })

void Printf(const char* format, ...) SAN_FORMAT(1, 2);
[[noreturn]] void BugImpl(const char* msg, ...) SAN_FORMAT(1, 2);
void WarnImpl(const char* msg, ...) SAN_FORMAT(1, 2);
int GetTid();
// Returns which signal handler we're currently in; 0 otherwise.
int InSignalHandler();

template <typename T>
struct remove_reference {
  using type = T;
};
template <typename T>
struct remove_reference<T&> {
  using type = T;
};
template <typename T>
struct remove_reference<T&&> {
  using type = T;
};
template <typename T>
using remove_reference_t = typename remove_reference<T>::type;

template <typename T>
struct remove_cv {
  using type = T;
};
template <typename T>
struct remove_cv<const T> {
  using type = T;
};
template <typename T>
struct remove_cv<volatile T> {
  using type = T;
};
template <typename T>
struct remove_cv<const volatile T> {
  using type = T;
};
template <typename T>
using remove_cv_t = typename remove_cv<T>::type;

template <typename T>
struct remove_cvref {
  typedef remove_cv_t<remove_reference_t<T>> type;
};
template <typename T>
using remove_cvref_t = typename remove_cvref<T>::type;

template <typename T>
constexpr T* addressof(T& x) {
  return __builtin_addressof(x);
}

template <typename To, typename From>
constexpr To bit_cast(const From& src) {
  static_assert(sizeof(To) == sizeof(From));
  return __builtin_bit_cast(To, src);
}

template <bool B, typename T = void>
struct enable_if {};
template <typename T>
struct enable_if<true, T> {
  typedef T type;
};
template <bool B, typename T = void>
using enable_if_t = typename enable_if<B, T>::type;

template <typename T, typename U>
inline constexpr bool is_same_v = __is_same(T, U);

template <typename T>
inline constexpr bool is_trivially_copyable_v = __is_trivially_copyable(T);

template <typename T>
[[nodiscard]] remove_reference_t<T>&& move(T&& t) {
  return static_cast<remove_reference_t<T>&&>(t);
}

template <typename T>
[[nodiscard]] constexpr T&& forward(remove_reference_t<T>& t) {
  return static_cast<T&&>(t);
}

template <typename T>
[[nodiscard]] constexpr T&& forward(remove_reference_t<T>&& t) {
  return static_cast<T&&>(t);
}

template <typename T>
constexpr T min(T a, T b) {
  return a < b ? a : b;
}
template <typename T>
constexpr T max(T a, T b) {
  return a > b ? a : b;
}

template <typename T>
void swap(T& a, T& b) {
  T tmp = move(a);
  a = move(b);
  b = move(tmp);
}

template <typename T>
constexpr bool IsPowerOfTwo(T x) {
  return (x & (x - 1)) == 0;
}

template <typename T>
constexpr T RoundDownTo(T size, T boundary) {
  SAN_DCHECK(IsPowerOfTwo(boundary), "boundary=%zu",
             static_cast<uptr>(boundary));
  return size & ~(boundary - 1);
}

template <typename T>
constexpr T RoundUpTo(T size, T boundary) {
  return RoundDownTo(size + boundary - 1, boundary);
}

template <typename T>
constexpr bool IsAligned(T a, T alignment) {
  SAN_DCHECK(IsPowerOfTwo(alignment), "alignment=%zu",
             static_cast<uptr>(alignment));
  return (a & (alignment - 1)) == 0;
}

// Syscall execution result.
// Holds the syscall result or errno value (if err != 0).
template <typename T>
class Result {
 public:
  explicit Result(uptr res) {
    if (res < static_cast<uptr>(-4095))
      val_ = (T)res;
    else
      err_ = static_cast<int>(-res);
  }

  template <typename Y>
  Result<Y> CastError() const {
    SAN_CHECK(err_);
    return Result<Y>(static_cast<uptr>(-err_));
  }

  bool operator!() const {
    return err_;
  }

  T val() const {
    SAN_CHECK_EQ(err_, 0);
    return val_;
  }

  T val_or(T def_val) const {
    return err_ ? def_val : val_;
  }

  int err() const {
    return err_;
  }

 private:
  T val_ = 0;
  int err_ = 0;
};

// Internal replacement for std::pair.
template <typename T1, typename T2>
struct Pair {
  using first_type = T1;
  using second_type = T2;
  T1 first;
  T2 second;
};
template <typename T1, typename T2>
Pair(T1, T2) -> Pair<T1, T2>;

// Function reference, type-erased callable reference. Not fully featured, but
// sufficient for our use cases (pass function pointers, capturing lambdas).
//
// Ensure that the lifetime of a callable object referenced by FunctionRef lives
// at least as long as the FunctionRef object!
template <typename T>
class FunctionRef;
template <typename Ret, typename... Args>
class FunctionRef<Ret(Args...)> {
 public:
  constexpr FunctionRef() = delete;
  constexpr FunctionRef(const FunctionRef& rhs) = default;

  template <typename F,
            enable_if_t<!is_same_v<FunctionRef, remove_cvref_t<F>>>* = nullptr>
  constexpr FunctionRef(F&& f) {
    // Store type-erased pointer to object, which is passed to proxy function
    // created here that casts the pointer back to the correct type.
    obj_ = const_cast<void*>(reinterpret_cast<const void*>(addressof(f)));
    proxy_ = [](void* obj, Args... args) {
      return (*reinterpret_cast<remove_reference_t<F>*>(obj))(
          forward<Args>(args)...);
    };
  }

  constexpr FunctionRef& operator=(const FunctionRef& rhs) = default;

  Ret operator()(Args... args) const {
    return proxy_(obj_, forward<Args>(args)...);
  }

 private:
  void* obj_;
  Ret (*proxy_)(void* obj, Args...);
};
// FunctionRef template deduction for function pointers.
template <typename Ret, typename... Args>
FunctionRef(Ret (*)(Args...)) -> FunctionRef<Ret(Args...)>;

// Calls a FunctionRef on destruction. Ensure that a callable object referenced
// by CleanupRef lives at least as long as the CleanupRef instance!
class CleanupRef {
 public:
  explicit CleanupRef(const FunctionRef<void()>& cleanup)
      : cleanup_(cleanup) {}

  ~CleanupRef() {
    cleanup_();
  }

 private:
  const FunctionRef<void()> cleanup_;

  CleanupRef(const CleanupRef&) = delete;
  CleanupRef& operator=(const CleanupRef&) = delete;
};

class Placed {
 public:
  template <typename T>
  explicit Placed(T* ptr)
      : ptr_(reinterpret_cast<void*>(ptr)) {}
  void* ptr() {
    return ptr_;
  }

 private:
  void* ptr_;
};

}  // namespace gwpsan SAN_LOCAL

// Overload placement new with gwpsan::Placed, since we can't redefine the
// standard version with void*.
inline void* operator new(gwpsan::uptr sz, gwpsan::Placed placed) {
  return placed.ptr();
}

#endif  // GWPSAN_BASE_COMMON_H_
