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

#include "gwpsan/uar/uar.h"

#include <signal.h>
#include <stdlib.h>

#include <new>

#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/memory.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/module_list.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/printf.h"
#include "gwpsan/base/sanitizer.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/span.h"
#include "gwpsan/base/syscall.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/context.h"
#include "gwpsan/core/flags.h"
#include "gwpsan/core/report.h"
#include "gwpsan/core/semantic_metadata.h"
#include "gwpsan/unified/tool.h"

namespace gwpsan {

DEFINE_METRIC(uar_init_ok, 0, "Initialization succeeded");
DEFINE_METRIC(uar_init_fail, 0, "Initialization failed");
DEFINE_METRIC(uar_guarded, 0, "Number of guarded stack frames");
DEFINE_METRIC(uar_detected, 0, "Detected use-after-returns");
DEFINE_METRIC(uar_detected_guard, 0,
              "Detected accesses to the middle guard page");
DEFINE_METRIC(uar_odd_stack_size, 0,
              "Unchecked threads due to oddly-sized stack size");
DEFINE_METRIC(uar_set_vma_name_unsupported, 0,
              "prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME) is unsupported");

constinit const ToolDesc kUarTool = {
    .name = "uar",
    .enabled = &Flags::uar,
    .init_ok = metric_uar_init_ok,
    .init_fail = metric_uar_init_fail,
    .semantic_flags = kSemanticUAR,
    .make_unique =
        +[] {
          if (!UarDetector::singleton().try_emplace())
            return UniquePtr<Tool>{};
          return UniquePtr<Tool>{&*UarDetector::singleton(), [](Tool*) {
                                   UarDetector::singleton().reset();
                                 }};
        },
};

namespace {

constexpr uptr kStackAlignment = 16;

bool IsStackAligned(uptr sp) {
  // While we should check SP at the first instruction of a function, on x86 the
  // breakpoint will fire _after_ the push instruction, and therefore we have to
  // add an 8 byte offset.
  return (sp & (kStackAlignment - 1)) == (GWPSAN_X64 ? 8 : 0);
}

bool GetMainStackBounds(uptr& addr, uptr& size, uptr& reserved) {
  auto stack = GetStackBounds();
  if (SAN_WARN(!stack))
    return false;
  struct rlimit rl;
  if (SAN_WARN_IF_ERR(sys_getrlimit(RLIMIT_STACK, &rl)))
    return false;
  MSAN_UNPOISON_MEMORY_REGION(&rl, sizeof(rl));
  // Give the thread 64MB in case of unlimited stack
  // (should be enough for everyone!).
  constexpr uptr kMaxStackSize = 64 << 20;
  const uptr limit = rl.rlim_cur != RLIM_INFINITY ? rl.rlim_cur : kMaxStackSize;
  addr = max(stack->first, stack->second - limit);
  size = stack->second - addr;
  reserved = addr - stack->first;
  return true;
}

Optional<Span<char>> GetThreadStackBounds() {
  pthread_attr_t attr;
  if (SAN_LIBCALL(pthread_attr_init(&attr))) {
    SAN_LOG("pthread_attr_init failed");
    return {};
  }
  if (SAN_LIBCALL(pthread_getattr_np(pthread_self(), &attr))) {
    SAN_LOG("pthread_getattr_np failed");
    SAN_LIBCALL(pthread_attr_destroy(&attr));
    return {};
  }
  char* addr;
  uptr size;
  if (SAN_LIBCALL(pthread_attr_getstack(&attr, reinterpret_cast<void**>(&addr),
                                        &size))) {
    SAN_LOG("pthread_attr_getstack failed");
    SAN_LIBCALL(pthread_attr_destroy(&attr));
    return {};
  }
  SAN_LIBCALL(pthread_attr_destroy(&attr));
  if (!addr || !size || !(addr + size)) {
    SAN_LOG("pthread_attr_getstack returned zero addr/size");
    return {};
  }
  return Span<char>{addr, size};
}

// SAN_PRESERVE_ALL: see the comment in gwpsan_uar_switch_stack.
//
// SAN_USED: in LTO builds functions called only from gwpsan_uar_switch_stack
// assembly are removed by compiler and lead to undefined symbols during
// linking.
//
// In LTO builds this function has 600 byte stack frame (for saving all
// registers including XMM/YMM). Maybe preserve_most will work as well
// (does not save XMM/YMM), or potentially we can use compiler metadata
// to filter out functions that has strange calling conventions.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wframe-larger-than"
SAN_PRESERVE_ALL SAN_USED extern "C" void gwpsan_uar_switch_back() {
  [[clang::noinline]] UarDetector::SwitchBack();
}
#pragma clang diagnostic pop

SAN_USED extern "C" void gwpsan_uar_switch_target() {}

// Size of the first 4 instructions in gwpsan_uar_switch_stack.
constexpr uptr kSwitchBackPrologue = 16;

SAN_NAKED extern "C" void gwpsan_uar_switch_stack() {
  // TODO(dvyukov): does this need CFI annotations? If yes, how can we
  // annotate the variable-size frame?
  // Note: CFI annotations need to be guarded with
  // #ifdef __GCC_HAVE_DWARF2_CFI_ASM. Otherwise they will break compilation
  // with -fasynchronous-unwind-tables or with -fno-asynchronous-unwind-tables.
  // Also gdb can't unwind from SwitchBack, need to be more careful with how
  // we maintain RSP/RBP.
  asm volatile(
#if GWPSAN_X64
      // The first 4 instructions are not executed, but we keep them so that
      // it does not appear that the call was made from outside of a function.
      // Note: if you update this prologue, update kSwitchBackPrologue const.
      R"(
      push %rbp
      mov %rsp, %rbp
      sub $0x10000, %rsp
      call gwpsan_uar_switch_target
      // Execution starts here:
      // Switch to the main stack
      mov %rbp, %rsp
      // We don't know the calling convention of the called function,
      // so conservatively preserve all registers. Attribute preserve_all
      // takes care of all registers except for R11.
      push %r11
      push %r11
      call gwpsan_uar_switch_back
      pop %r11
      pop %r11
      pop %rbp
      ret
      )");
#elif GWPSAN_ARM64
      R"(
      // Not executed part:
      stp x29, x30, [sp, #-16]!
      mov x29, sp
      sub sp, sp, #0x10000
      bl gwpsan_uar_switch_target
      // Execution starts here:
      sub sp, x29, 96
      // preserve_all does not preserve x0-x8 and x16-x18, preserve them here.
      stp x0, x1, [sp]
      stp x2, x3, [sp, #16]
      stp x4, x5, [sp, #32]
      stp x6, x7, [sp, #48]
      stp x8, x16, [sp, #64]
      stp x17, x18, [sp, #80]
      bl gwpsan_uar_switch_back
      ldp x0, x1, [sp]
      ldp x2, x3, [sp, #16]
      ldp x4, x5, [sp, #32]
      ldp x6, x7, [sp, #48]
      ldp x8, x16, [sp, #64]
      ldp x17, x18, [sp, #80]
      ldp x29, x30, [sp, #96]
      add sp, sp, 112
      ret
      )");
#endif  // GWPSAN_ARM64
}
}  // namespace

bool SetVMANameSupported() {
  const uptr addr = RoundDownTo(SAN_CURRENT_FRAME(), kPageSize);
  if (!sys_prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, kPageSize,
                 "gwpsan stack")) {
    metric_uar_set_vma_name_unsupported.Add(1);
    return false;
  }
  SAN_WARN_IF_ERR(
      sys_prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, kPageSize, nullptr));
  return true;
}

UarDetector::Thread::Thread(UarDetector* detector, ThreadRoutine routine,
                            void* arg, uptr stack_size, uptr guard_size)
    : detector_(detector)
    , routine_(routine)
    , arg_(arg)
    , stack_size_(stack_size)
    , guard_size_(guard_size) {}

UarDetector::Thread::~Thread() {
  // Unprotect the stack as it was originally. Pthread can reuse it.
  // Note: it's possible that our assumptions about the stack size/layout
  // were wrong, then we must not unprotect it. Or otherwise we may unprotect
  // random memory.
  if (stack_protected_)
    UnprotectSecondStack();
  if (stack_named_)
    NameSecondStack(false);
}

bool UarDetector::Thread::Prepare(uptr stack_addr) {
  tid_ = GetTid();
  stack_addr_ = stack_addr;
  // Sanity check that we are on the main stack.
  const uptr sp = SAN_CURRENT_FRAME();
  if (SAN_WARN(sp < MainStackBegin() || sp >= MainStackEnd(),
               "sp=0x%zx begin=0x%zx end=0x%zx", sp, MainStackBegin(),
               MainStackEnd()))
    return false;
  return true;
}

bool UarDetector::Thread::ProtectSecondStack() {
  stack_protected_ = true;
  return !SAN_WARN_IF_ERR(sys_mprotect(reinterpret_cast<void*>(stack_addr_),
                                       stack_size_ + guard_size_, PROT_NONE));
}

bool UarDetector::Thread::UnprotectSecondStack() {
  // Ideally the middle guard page should stay protected.
  // However stack unwinding code can read it. We used to mark it as PROT_READ
  // to catch some additional out-of-bounds on the stack.
  // But now we mark both stack and guard page as RW for performance reasons
  // (single mprotect call instead of two, older kernels also do TLB flush
  // on such mprotects, which is espcially harmful).
  return !SAN_WARN_IF_ERR(sys_mprotect(reinterpret_cast<void*>(stack_addr_),
                                       stack_size_ + guard_size_,
                                       PROT_READ | PROT_WRITE));
}

void UarDetector::Thread::NameSecondStack(bool name) {
  stack_named_ = true;
  SAN_WARN_IF_ERR(sys_prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, stack_addr_,
                            stack_size_ + guard_size_,
                            name ? "gwpsan stack" : nullptr));
}

uptr UarDetector::Thread::MainStackBegin() const {
  return stack_addr_ + stack_size_ + guard_size_;
}

uptr UarDetector::Thread::MainStackEnd() const {
  return stack_addr_ + 2 * stack_size_ + guard_size_;
}

uptr UarDetector::Thread::SecondStackBegin() const {
  return stack_addr_;
}

uptr UarDetector::Thread::SecondStackEnd() const {
  return stack_addr_ + stack_size_;
}

UarDetector::UarDetector(bool& ok)
    : Tool(kUarTool.name)
    , set_vma_name_supported_(SetVMANameSupported()) {
  if (!GetFlags().uar_check_every_nth_thread) {
    SAN_LOG("uar_check_every_nth_thread is disabled");
    ok = false;
    return;
  }
  // SA_ONSTACK to use an altstack for stack overflows; SA_NODEFER to forward
  // signal to default handler immediately.
  sigset_t sigset;
  SAN_LIBCALL(sigfillset)(&sigset);
  SAN_LIBCALL(sigdelset)(&sigset, SIGSEGV);
  SAN_LIBCALL(sigdelset)(&sigset, SIGBUS);
  if (!InstallSignalHandler(SA_ONSTACK | SA_NODEFER, sigset)) {
    SAN_LOG("failed to install SIGSEGV handler");
    ok = false;
    return;
  }
  if (ShouldSampleThread(nullptr))
    SampleMainThread();
}

void UarDetector::SampleMainThread() {
  uptr stack_addr = 0, stack_size = 0, stack_reserved = 0;
  if (!GetMainStackBounds(stack_addr, stack_size, stack_reserved))
    return;
  SAN_LOG("stack bounds: 0x%zx-0x%zx-0x%zx (%zu)", stack_addr - stack_reserved,
          stack_addr, stack_addr + stack_size, stack_size);
  if (!IsAligned(stack_size, kPageSize)) {
    SAN_LOG("thread has odd stack size %zu: not checking", stack_size);
    metric_uar_odd_stack_size.Add(1);
    return;
  }
  const uptr guard_size = kPageSize;
  const uptr mmap_size = stack_size + 2 * guard_size;
  if (mmap_size > stack_reserved) {
    SAN_LOG("reserved space %zu, need %zu: not checking", stack_reserved,
            mmap_size);
    return;
  }
  // TODO(dvyukov): use MAP_FIXED_NOREPLACE when available.
  const uptr mmap_addr = stack_addr - mmap_size;
  auto mmaped = sys_mmap(reinterpret_cast<void*>(mmap_addr), mmap_size,
                         PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
  if (SAN_WARN_IF_ERR(mmaped))
    return;
  if (SAN_WARN(mmaped.val() != reinterpret_cast<void*>(mmap_addr))) {
    SAN_WARN_IF_ERR(sys_munmap(mmaped.val(), mmap_size));
    return;
  }
  auto* thr = new Thread(this, nullptr, nullptr, stack_size, guard_size);
  if (!thr->Prepare(reinterpret_cast<uptr>(mmap_addr) + guard_size)) {
    delete thr;
    SAN_WARN_IF_ERR(sys_munmap(mmaped.val(), mmap_size));
    return;
  }
  current_ = thr;
  SAN_LOG("checking the main thread");
}

bool UarDetector::ShouldSampleThread(const pthread_attr_t* attr) {
  if (!rand_.OneOf(GetFlags().uar_check_every_nth_thread))
    return false;
  if (attr) {
    void* saddr = nullptr;
    uptr ssize = 0;
    if (SAN_WARN(SAN_LIBCALL(pthread_attr_getstack(attr, &saddr, &ssize))))
      return false;
    if (reinterpret_cast<uptr>(saddr) + ssize) {
      SAN_LOG("thread has custom stack: not checking");
      return false;
    }
    // It's unclear how to layout stacks if we have an odd size.
    // Since it's uncommon, we just ignore such cases for now.
    if (!IsAligned(ssize, kPageSize)) {
      SAN_LOG("thread has odd stack size %zu: not checking", ssize);
      metric_uar_odd_stack_size.Add(1);
      return false;
    }
  }
  return true;
}

bool UarDetector::ModifyThread(pthread_attr_t* attr, ThreadRoutine* routine,
                               void** arg) {
  uptr stack_size = 0;
  uptr guard_size = 0;
  if (pthread_attr_getstacksize(attr, &stack_size) ||
      pthread_attr_getguardsize(attr, &guard_size)) {
    SAN_LOG("pthread_attr_getstack/guardsize failed");
    return false;
  }
  if (pthread_attr_setstacksize(attr, 2 * stack_size + guard_size)) {
    SAN_LOG("pthread_attr_setstacksize failed");
    return false;
  }
  auto* thr =
      new (std::nothrow) Thread(this, *routine, *arg, stack_size, guard_size);
  if (!thr) {
    SAN_LOG("thread description allocation failed");
    return false;
  }
  *routine = ThreadWrapper;
  *arg = thr;
  return true;
}

void* UarDetector::ThreadWrapper(void* arg) {
  auto* thr = static_cast<Thread*>(arg);
  auto routine = thr->routine_;
  auto orig_arg = thr->arg_;
  if (!thr->detector_->PrepareThread(thr)) {
    current_ = nullptr;
    delete thr;
  }
  SAN_MUSTTAIL return routine(orig_arg);
}

bool UarDetector::PrepareThread(Thread* thr) {
  auto stack = GetThreadStackBounds();
  if (SAN_WARN(!stack))
    return false;
  uptr stack_addr = reinterpret_cast<uptr>(stack->data());
  uptr stack_size = stack->size();
  SAN_LOG(
      "stack_addr=0x%zx stack_size=0x%zx original_size=0x%zx guard_size=0x%zx",
      stack_addr, stack_size, thr->stack_size_, thr->guard_size_);
  const sptr diff = stack_size - (2 * thr->stack_size_ + thr->guard_size_);
  if (SAN_WARN(diff < 0))
    return false;
  if (diff > 0) {
    // Pthread can give more stack than was asked for (due to stack reuse).
    // It's unclear what exactly we should do with the excess.
    // We could increase size of the stacks, but currently we assume
    // that main and second stacks have the same size, so if we got odd
    // number of additional pages, we can't do that.
    // For now we just increase size of the middle guard range.
    SAN_LOG("stack is larger than requested, adjusted guard by 0x%zx", diff);
    thr->guard_size_ += diff;
  }
  if (!thr->Prepare(stack_addr))
    return false;
  current_ = thr;
  mgr().RegisterCurrentThread();
  // Protecting the second stack helps to detect incompatible programs faster.
  // This can happen in the release build as well if we get the timer signal
  // right after thread start, switch to the second stack and back.
  // But probability of this is low, so in debug build we protect the second
  // stack right away.
  if (GWPSAN_DEBUG)
    thr->ProtectSecondStack();
  return true;
}

void UarDetector::OnThreadExit() {
  auto* thr = current_;
  // This is possible if the break manager registered the thread destructor
  // in a timer signal arrived on a non-checked thread. Or if we registered
  // the thread, but then failed later in the thread initialization sequence.
  if (!thr)
    return;
  // Note: theoretically we can be on the second stack right now
  // (if the thread has called pthread_exit on the second stack).
  // But it should be OK.
  current_ = nullptr;
  delete thr;
}

bool UarDetector::IsInteresting(const CPUContext& ctx) {
  auto* thr = current_;
  if (!thr)
    return false;
  if (__atomic_load_n(&thr->switched_, __ATOMIC_RELAXED))
    return false;
  // If the program is already crashing, no point in switching.
  // We can also mess the report (previous switch stack),
  // if an external signal handler is used.
  if (InSignalHandler())
    return false;
  // Check that we are on the main stack.
  const uptr sp = ctx.reg(kSP).val;
  if (sp < thr->MainStackBegin() || sp >= thr->MainStackEnd()) {
    SAN_LOG("not on the main stack: sp=0x%zx stack [0x%zx-0x%zx]", sp,
            thr->MainStackBegin(), thr->MainStackEnd());
    return false;
  }
  // Some calls don't follow the ABI for 16-byte aligned SP.
  // One case is tcmalloc_internal_tls_fetch_pic call in tcmalloc.
  // We need to call SwitchStackThunk on an aligned stack since it can use
  // XMM registers. Potentially we can realign stack here, or in
  // SwitchStackThunk. But it's unclear if it's worth it.
  if (!IsStackAligned(sp)) {
    SAN_LOG("unaligned stack");
    return false;
  }
  // Check that we are at the beginning of a suitable function.
  if (!IsUARFunctionStart(ctx.reg(kPC).val)) {
    SAN_LOG("not a start of a suitable function");
    return false;
  }
  return true;
}

bool UarDetector::Check(CPUContext& ctx) {
  auto* thr = current_;
  auto stack_args_size = IsUARFunctionStart(ctx.reg(kPC).val);
  // We already checked this in IsInteresting, but it still can fail
  // if the semantic metadata mutex TryLock fails.
  if (!stack_args_size)
    return false;
  if (SAN_WARN(*stack_args_size % kStackAlignment, "pc=0x%zx args=%zu",
               ctx.reg(kPC).val, *stack_args_size))
    return false;
  // Set a name for the region we are going to protect/unprotect.
  // This avoids constant VMA merging/unmerging. Since this is just
  // an optimization, skip it if PR_SET_VMA support is missing/not enabled.
  if (set_vma_name_supported_ && !thr->stack_named_)
    thr->NameSecondStack(true);
  if (!thr->UnprotectSecondStack())
    return false;
  UnwindStack(thr->switch_stack_, ctx.uctx());
  // Arrange call of gwpsan_uar_switch_stack on the return path
  // (model first non-executed instructions of gwpsan_uar_switch_stack).
  const uptr sp0 = ctx.reg(kSP).val;
  // Setup frame pointer:
#if GWPSAN_X64
  // push %rbp
  uptr sp = sp0 - sizeof(uptr);
  reinterpret_cast<uptr*>(sp)[0] = ctx.reg(kRBP).val;
  // mov %rsp, %rbp
  ctx.UpdateRegister(kRBP, sp);
#elif GWPSAN_ARM64
  // stp x29, x30, [sp, #-16]!
  uptr sp = sp0 - 2 * sizeof(uptr);
  reinterpret_cast<uptr*>(sp)[0] = ctx.reg(kX29).val;
  reinterpret_cast<uptr*>(sp)[1] = ctx.reg(kLR).val;
  // mov x29, sp
  ctx.UpdateRegister(kX29, sp);
#endif  // GWPSAN_ARM64
  // Switch to the second stack.
  sp = thr->SecondStackEnd();
  // Copy stack arguments to the new location.
  // Note: Return values on the stack (ABI class MEMORY) are referenced via
  // RDI indirection rather than RSP. So we don't need to do anything special.
  // RDI still points to the main stack part.
  if (*stack_args_size) {
    sp -= *stack_args_size;
    // We may copy poisoned redzones.
    ASAN_UNPOISON_MEMORY_REGION(reinterpret_cast<void*>(sp), *stack_args_size);
    ASAN_UNPOISON_MEMORY_REGION(reinterpret_cast<void*>(sp0 + sizeof(uptr)),
                                *stack_args_size);
    internal_memcpy(reinterpret_cast<void*>(sp),
                    reinterpret_cast<void*>(sp0 + sizeof(uptr)),
                    *stack_args_size);
  }
  // Setup return address to gwpsan_uar_switch_stack.
  uptr return_pc =
      reinterpret_cast<uptr>(gwpsan_uar_switch_stack) + kSwitchBackPrologue;
#if GWPSAN_X64
  sp -= sizeof(uptr);
  reinterpret_cast<uptr*>(sp)[0] = return_pc;
#elif GWPSAN_ARM64
  ctx.UpdateRegister(kLR, return_pc);
#endif  // GWPSAN_ARM64
  SAN_CHECK(IsStackAligned(sp));
  ctx.UpdateRegister(kSP, sp);
  SAN_LOG(
      "switch stack: main=0x%zx-0x%zx second=0x%zx-0x%zx args=%zu "
      "sp=0x%zx->0x%zx",
      thr->MainStackBegin(), thr->MainStackEnd(), thr->SecondStackBegin(),
      thr->SecondStackEnd(), *stack_args_size, sp0, sp);
  __atomic_store_n(&thr->switched_, true, __ATOMIC_RELAXED);
  metric_uar_guarded.ExclusiveAdd(1);
  return false;
}

void UarDetector::SwitchBack() {
  auto* thr = current_;
  if (SAN_WARN(!thr))
    return;
  thr->detector_->SwitchBack(thr);
}

void UarDetector::SwitchBack(Thread* thr) {
  // We are already on the main stack, protect the second stack.
  SAN_LOG("switch back:  main=0x%zx-0x%zx second=0x%zx-0x%zx sp=%p pc=%p",
          thr->MainStackBegin(), thr->MainStackEnd(), thr->SecondStackBegin(),
          thr->SecondStackEnd(), reinterpret_cast<void*>(SAN_CURRENT_FRAME()),
          reinterpret_cast<void*>(SAN_CALLER_PC()));
  thr->ProtectSecondStack();
  SAN_DCHECK(thr->switched_);
  __atomic_store_n(&thr->switched_, false, __ATOMIC_RELAXED);
}

bool UarDetector::OnSignal(int signo, siginfo_t* siginfo, void* uctxp) {
  auto& uctx = *static_cast<ucontext_t*>(uctxp);
  auto* thr = current_;
  if (signo != SIGSEGV || !thr)
    return false;
  const uptr addr = reinterpret_cast<uptr>(siginfo->si_addr);
  // Access to the second stack?
  if (addr < thr->SecondStackBegin() || addr >= thr->SecondStackEnd()) {
    // If this is an access to the guard page, most likely this is
    // a stack overflow, or for the middle guard it can be a stack
    // out-of-bounds.
    // Don't print UAR report, but still print some info for 2 reasons:
    // (1) we may give a bit more info than a standard handler,
    // (2) to indicate in the crash that we messed with the stack
    //     (theoretically it may be our bug).
    if ((addr >= thr->SecondStackEnd() &&
         addr < thr->SecondStackEnd() + thr->guard_size_) ||
        (addr >= thr->SecondStackBegin() - thr->guard_size_ &&
         addr < thr->SecondStackBegin())) {
      metric_uar_detected_guard.Add(1);
      Printf(
          "GWPSan: access to the stack guard page, stack overflow or stack "
          "out-of-bounds?\n");
      UnwindStack(current_stack_, &uctx);
      PrintStackTrace(current_stack_, "    ");
      Printf("\n");
      PrintStackInfo(thr, uctx, addr);
    }
    return false;
  }
  ReportPrinter printer("use-after-return", metric_uar_detected, &uctx);
  printer.CurrentStack();
  Printf("\nThe variable was allocated within:\n");
  PrintStackTrace(thr->switch_stack_, "    ");
  Printf("\n");
  PrintStackInfo(thr, uctx, addr);
  thr->UnprotectSecondStack();
  return true;  // Since we unprotected the stack, we can resume.
}

void UarDetector::PrintStackInfo(Thread* thr, const ucontext_t& uctx,
                                 uptr addr) {
  Printf("Access address:  0x%zx\n", addr);
  Printf("Current SP:      0x%zx\n", ExtractSP(uctx));
  Printf("Main stack:      0x%zx-0x%zx\n", thr->MainStackBegin(),
         thr->MainStackEnd());
  Printf("Second stack:    0x%zx-0x%zx\n", thr->SecondStackBegin(),
         thr->SecondStackEnd());
}

bool UarDetector::GetStackLimits(uptr* lo, uptr* hi) {
  Thread* thr = current_;
  if (!thr)
    return false;
  if (__atomic_load_n(&thr->switched_, __ATOMIC_RELAXED)) {
    *lo = thr->SecondStackBegin();
    *hi = thr->SecondStackEnd();
  } else {
    *lo = thr->MainStackBegin();
    *hi = thr->MainStackEnd();
  }
  return true;
}

SAN_THREAD_LOCAL UarDetector::Thread* UarDetector::current_;

SAN_EXPORT bool IsOnTheSecondStack() {
  return UarDetector::current_ &&
         __atomic_load_n(&UarDetector::current_->switched_, __ATOMIC_RELAXED);
}

// Returns the current stack limits for either main or secondary stack
// (whichever we are currently on) for sampled threads.
SAN_INTERFACE bool gwpsan_get_stack_limits(uptr* lo, uptr* hi) {
  ScopedAsyncSignalSafe async_signal_safe;
  return UarDetector::GetStackLimits(lo, hi);
}

}  // namespace gwpsan
