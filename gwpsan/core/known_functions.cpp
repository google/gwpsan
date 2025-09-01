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

#include "gwpsan/core/known_functions.h"

#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>

#include <cstddef>
#include <new>

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/units.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/meta.h"

namespace gwpsan {

// These are defined in C23, but tcmalloc already intercepts them.
extern "C" SAN_WEAK_IMPORT void free_sized(void*, size_t)
#ifdef __GLIBC__
    noexcept
#endif
    ;
extern "C" SAN_WEAK_IMPORT void free_aligned_sized(void*, size_t, size_t)
#ifdef __GLIBC__
    noexcept
#endif
    ;

extern "C" SAN_WEAK_IMPORT void gwpsan_real_memset();
extern "C" SAN_WEAK_IMPORT void gwpsan_real_memcpy();
extern "C" SAN_WEAK_IMPORT void __asan_memset();
extern "C" SAN_WEAK_IMPORT void __asan_memcpy();
extern "C" SAN_WEAK_IMPORT void __asan_memmove();
extern "C" SAN_WEAK_IMPORT void __msan_memset();
extern "C" SAN_WEAK_IMPORT void __msan_memcpy();
extern "C" SAN_WEAK_IMPORT void __msan_memmove();
// It's not possible to take memchr address because of strange overloads.
void memchr_alias() asm("memchr");

// In Asan opt build code that calls free() somehow ends up calling
// __interceptor_free() instead. This happens on KnownFunctions.IsFreePC test,
// which does not detect free() call. The test ends up with this call:
//   8e273e:       e8 5d 12 fa ff          call   8839a0 <___interceptor_free>
// This is not the free symbol, it points only to:
//   00000000008839a0 0000000000000175 T ___interceptor_free
//   00000000008839a0 0000000000000175 W __interceptor_free
// while the actual free symbol is:
//   0000000000883948 <__interceptor_trampoline_free>:
//     883948:       e9 53 00 00 00          jmp    8839a0 <___interceptor_free>
// It's unclear why this happens, for now we check these interceptors as well.
extern "C" SAN_WEAK_IMPORT void __interceptor_free();
extern "C" SAN_WEAK_IMPORT void __interceptor_malloc();
extern "C" SAN_WEAK_IMPORT void __interceptor_calloc();
extern "C" SAN_WEAK_IMPORT void __interceptor_memchr();
extern "C" SAN_WEAK_IMPORT void __interceptor_strncmp();

namespace {
template <typename F, typename... Fs>
bool Match(uptr pc, F f, Fs... fs) {
  if constexpr (sizeof...(fs))
    if (Match(pc, fs...))
      return true;
  return pc == reinterpret_cast<uptr>(f);
}
}  // namespace

bool IsMallocPC(const CPUContext& ctx, uptr& size, bool& uninit) {
  // TODO(dvyukov): other malloc-related functions we need to support/consider:
  // - realloc: both free+malloc and returns partially uninit memory.
  // - cfree: tcmalloc redefines it, but it's not defined in any headers.
  // - sdallocx: tcmalloc redefines it, something from jemalloc interface.
  // - posix_memalign: the resulting pointer is returned differently.
  // - malloc_size/malloc_usable_size: if we do OOB detection, we need handle
  //   then to "extend" object size.
  uninit = true;
  const uptr pc = ctx.reg(kPC).val;
  if (Match(
          pc, ::malloc, __interceptor_malloc, ::valloc, ::pvalloc,
          static_cast<void* (*)(std::size_t)>(&operator new),
          static_cast<void* (*)(std::size_t, const std::nothrow_t&)>(
              &operator new),
          static_cast<void* (*)(std::size_t, std::align_val_t)>(&operator new),
          static_cast<void* (*)(std::size_t, std::align_val_t,
                                const std::nothrow_t&)>(&operator new),
          static_cast<void* (*)(std::size_t)>(&operator new[]),
          static_cast<void* (*)(std::size_t, const std::nothrow_t&)>(
              &operator new[]),
          static_cast<void* (*)(std::size_t, std::align_val_t)>(
              &operator new[]),
          static_cast<void* (*)(std::size_t, std::align_val_t,
                                const std::nothrow_t&)>(&operator new[]))) {
    size = ctx.reg(kArgRegs[0]).val;
  } else if (Match(pc, ::memalign, ::aligned_alloc)) {
    size = ctx.reg(kArgRegs[1]).val;
  } else if (Match(pc, ::calloc, __interceptor_calloc)) {
    uninit = false;
    size = ctx.reg(kArgRegs[0]).val * ctx.reg(kArgRegs[1]).val;
  } else {
    return false;
  }
  SAN_LOG("detected start of malloc");
  return true;
}

bool IsFreePC(const CPUContext& ctx, uptr& ptr, uptr& size) {
  ptr = ctx.reg(kArgRegs[0]).val;
  size = 0;
  const uptr pc = ctx.reg(kPC).val;
  if (Match(
          pc, ::free, __interceptor_free,
          static_cast<void (*)(void*)>(&operator delete),
          static_cast<void (*)(void*, const std::nothrow_t&)>(&operator delete),
          static_cast<void (*)(void*, std::align_val_t)>(&operator delete),
          static_cast<void (*)(void*, std::align_val_t, const std::nothrow_t&)>(
              &operator delete),
          static_cast<void (*)(void*)>(&operator delete[]),
          static_cast<void (*)(void*, const std::nothrow_t&)>(
              &operator delete[]),
          static_cast<void (*)(void*, std::align_val_t)>(&operator delete[]),
          static_cast<void (*)(void*, std::align_val_t, const std::nothrow_t&)>(
              &operator delete[]))) {
  } else if (Match(pc, free_sized
#if __cpp_sized_deallocation
                   ,
                   static_cast<void (*)(void*, size_t)>(&operator delete),
                   static_cast<void (*)(void*, size_t, std::align_val_t)>(
                       &operator delete),
                   static_cast<void (*)(void*, size_t)>(&operator delete[]),
                   static_cast<void (*)(void*, size_t, std::align_val_t)>(
                       &operator delete[])
#endif
                       )) {
    size = ctx.reg(kArgRegs[1]).val;
  } else if (Match(pc, free_aligned_sized)) {
    size = ctx.reg(kArgRegs[2]).val;
  } else {
    return false;
  }
  SAN_LOG("detected start of free");
  return true;
}

bool IsMemAccessFunc(uptr pc) {
  return Match(pc, ::memset, gwpsan_real_memset, __asan_memset, __msan_memset,
               ::memcpy, ::memmove, gwpsan_real_memcpy, __asan_memcpy,
               __asan_memmove, __msan_memcpy, __msan_memmove, memchr_alias,
               ::strncmp, __interceptor_memchr, __interceptor_strncmp);
}

bool IsMemAccessFunc(const CPUContext& ctx,
                     const FunctionRef<void(const MemAccess&)>& cb) {
  const uptr pc = ctx.reg(kPC).val;
  if (!IsMemAccessFunc(pc))
    return false;
  auto note = [&](uptr ptr_arg, uptr size_arg, bool write, bool use) {
    Addr ptr(ctx.reg(kArgRegs[ptr_arg]).val);
    ByteSize size(ctx.reg(kArgRegs[size_arg]).val);
    if (ptr != 0 && size != 0)
      cb({.pc = pc,
          .addr = ptr,
          .size = size,
          .is_read = !write,
          .is_write = write,
          .is_use = use,
          .is_atomic = false});
  };
  auto use = [&](uptr ptr, uptr size) { note(ptr, size, false, true); };
  auto read = [&](uptr ptr, uptr size) { note(ptr, size, false, false); };
  auto write = [&](uptr ptr, uptr size) { note(ptr, size, true, false); };
  if (Match(pc, ::memset, gwpsan_real_memset, __asan_memset, __msan_memset)) {
    SAN_LOG("detected start of memset");
    write(0, 2);
  } else if (Match(pc, ::memcpy, ::memmove, gwpsan_real_memcpy, __asan_memcpy,
                   __asan_memmove, __msan_memcpy, __msan_memmove)) {
    SAN_LOG("detected start of memcpy/memmove");
    write(0, 2);
    read(1, 2);
  } else if (Match(pc, memchr_alias, __interceptor_memchr)) {
    SAN_LOG("detected start of memchr");
    use(0, 2);
  } else if (Match(pc, ::strncmp, __interceptor_strncmp)) {
    SAN_LOG("detected start of strncmp");
    use(0, 2);
    use(1, 2);
  } else {
    SAN_WARN(true, "unmatched memory access function");
    return false;
  }
  return true;
}

uptr ExtractSyscallAccesses(const CPUContext& ctx,
                            const FunctionRef<void(const MemAccess&)>& cb) {
  const uptr pc = ctx.reg(kPC).val;
  uptr const nr = ctx.reg(kSyscallNumReg).val;
  auto note = [&](uptr ptr_arg, uptr size_arg, bool write) {
    Addr addr(ctx.reg(kArgRegs[ptr_arg]).val);
    ByteSize size(ctx.reg(kArgRegs[size_arg]).val);
    if (addr != 0 && size != 0)
      cb({.pc = pc,
          .addr = addr,
          .size = size,
          .is_read = !write,
          .is_write = write,
          .is_use = !write,
          .is_atomic = false});
  };
  auto read = [&](uptr ptr, uptr size) { note(ptr, size, false); };
  auto write = [&](uptr ptr, uptr size) { note(ptr, size, true); };
  switch (nr) {
  case SYS_read:
    write(1, 2);
    break;
  case SYS_recvfrom:
    write(1, 2);
    read(4, 5);
    break;
  case SYS_write:
    read(1, 2);
    break;
  case SYS_sendto:
    read(1, 2);
    read(3, 4);
    break;
  }
  SAN_LOG("detected syscall %zu", nr);
  return nr;
}

}  // namespace gwpsan
