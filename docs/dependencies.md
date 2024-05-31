# Dependencies

GWPSan was co-designed along with necessary compiler and OS kernel support.
Development of the runtime informed new compiler and kernel support, which we
developed and upstreamed to LLVM and the Linux kernel.

Other platforms that do not meet the below requirements are unsupported.

### Compiler Support

To perform certain detailed runtime binary analysis on an otherwise unmodified
binary, semantic metadata is required that is lost when generating machine
code. For example, data race detection requires knowledge of atomic accesses to
avoid false positives. For deployment in production, however, this metadata
needs to be stored in the binary and needs to be accessible efficiently at
runtime: the presence of the metadata should not affect performance of the
binary unless it is accessed, and overall binary size should be minimally
Impacted. We implemented support in the [LLVM Compiler
Infrastructure](https://llvm.org).

The implementation consists of a new [middle-end
pass](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Transforms/Instrumentation/SanitizerBinaryMetadata.cpp),
and [backend
pass](https://github.com/llvm/llvm-project/blob/main/llvm/lib/CodeGen/SanitizerBinaryMetadata.cpp),
which rely on [PC Sections
Metadata](https://llvm.org/docs/PCSectionsMetadata.html) ([LLVM
RFC](https://discourse.llvm.org/t/rfc-pc-keyed-metadata-at-runtime/64191)) to
emit the metadata into separate ELF binary sections.

Currently we store PC-keyed metadata for atomic operations and functions
suitable for use-after-return detection. But other types of metadata can be
added in future if required (for example, signed int operations that are
subject for overflow checking, or fixed-array indexing for the purposes of
out-of-bounds checking).

Also see the runtime
[implementation](https://github.com/google/gwpsan/blob/master/gwpsan/core/semantic_metadata.cpp)
that parses and makes the PC-keyed metadata queryable.

Clang 18 or later includes all the above changes, which can be enabled with
`-fexperimental-sanitize-metadata`. Some earlier versions of Clang already
support `-fexperimental-sanitize-metadata`, but do not include optimizations
and necessary fixes. Since the compiler support is still marked experimental,
the runtime does not support earlier versions of the metadata (but we detect if
an older version is present and fail initialization).

### Linux Kernel Support

Several new features, performance optimizations, and fixes were contributed to
the [Linux kernel](https://kernel.org) to support GWPSan and similar use cases.

**Efficient process-wide hardware breakpoint and watchpoint support.** Prior to
these changes, each thread would have had to create its own
`PERF_TYPE_BREAKPOINT` perf event. Manually managing perf events of all running
threads would have been too slow and complex in heavily multi-threaded
applications. See runtime implementation
[here](https://github.com/google/gwpsan/blob/master/gwpsan/core/breakmanager.cpp).

   1. [perf: Rework perf_event_exit_event()](https://git.kernel.org/torvalds/c/ef54c1a476ae)
   2. [perf: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children](https://git.kernel.org/torvalds/c/47f661eca070)
   3. [perf: Support only inheriting events if cloned with CLONE_THREAD](https://git.kernel.org/torvalds/c/2b26f0aa0049)
   4. [perf: Add support for event removal on exec](https://git.kernel.org/torvalds/c/2e498d0a74e5)
   5. [signal: Introduce TRAP_PERF si_code and si_perf to siginfo](https://git.kernel.org/torvalds/c/fb6cc127e0b6)
   6. [perf: Add support for SIGTRAP on perf events](https://git.kernel.org/torvalds/c/97ba62b27867)
   7. [selftests/perf_events: Add kselftest for process-wide sigtrap handling](https://git.kernel.org/torvalds/c/f2c3c32f4500)
   8. [selftests/perf_events: Add kselftest for remove_on_exec](https://git.kernel.org/torvalds/c/6216798bf98e)
   9. [signal, perf: Fix siginfo_t by avoiding u64 on 32-bit architectures](https://git.kernel.org/torvalds/c/3ddb3fd8cdb0)
   10. [signal, perf: Add missing TRAP_PERF case in siginfo_layout()](https://git.kernel.org/torvalds/c/ed8e50800bf4)
   11. [signal: Factor force_sig_perf out of perf_sigtrap](https://git.kernel.org/torvalds/c/af5eeab7e8e8)
   12. [signal: Deliver all of the siginfo perf data in \_perf](https://git.kernel.org/torvalds/c/0683b53197b5)
   13. [perf: Fix required permissions if sigtrap is requested](https://git.kernel.org/torvalds/c/9d7a6c95f62b)
   14. [perf: Ignore sigtrap for tracepoints destined for other tasks](https://git.kernel.org/torvalds/c/73743c3b0922)
   15. [perf test sigtrap: Add basic stress test for sigtrap handling](https://git.kernel.org/torvalds/c/5504f6794448)
   16. [perf: Copy perf_event_attr::sig_data on modification](https://git.kernel.org/torvalds/c/3c25fc97f559)
   17. [signal: Deliver SIGTRAP on perf event asynchronously if blocked](https://git.kernel.org/torvalds/c/78ed93d72ded)
   18. [perf: Fix missing SIGTRAPs](https://git.kernel.org/torvalds/c/ca6c21327c6a)
   19. [perf: Improve missing SIGTRAP checking](https://git.kernel.org/torvalds/c/bb88f9695460)
   20. [perf: Fix perf_pending_task() UaF](https://git.kernel.org/torvalds/c/517e6a301f34)

**Optimizing breakpoint accounting in the kernel.** Prior to these changes,
enabling/disabling breakpoints had noticeable performance impact on systems
with high CPU counts. These changes did not change the kernel ABI, but prior to
these changes we do *not* recommend enabling GWPSan.

   1. [perf/hw_breakpoint: Add KUnit test for constraints accounting](https://git.kernel.org/torvalds/c/724c299c6a0e)
   2. [perf/hw_breakpoint: Provide hw_breakpoint_is_used() and use in test](https://git.kernel.org/torvalds/c/c5b81449f915)
   3. [perf/hw_breakpoint: Clean up headers](https://git.kernel.org/torvalds/c/089cdcb0cd1c)
   4. [perf/hw_breakpoint: Optimize list of per-task breakpoints](https://git.kernel.org/torvalds/c/0370dc314df3)
   5. [perf/hw_breakpoint: Mark data \__ro_after_init](https://git.kernel.org/torvalds/c/db5f6f853194)
   6. [perf/hw_breakpoint: Optimize constant number of breakpoint slots](https://git.kernel.org/torvalds/c/be3f152568cc)
   7. [perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable](https://git.kernel.org/torvalds/c/9caf87be118f)
   8. [perf/hw_breakpoint: Remove useless code related to flexible breakpoints](https://git.kernel.org/torvalds/c/24198ad373ad)
   9. [powerpc/hw_breakpoint: Avoid relying on caller synchronization](https://git.kernel.org/torvalds/c/f95e5a3d5901)
   10. [locking/percpu-rwsem: Add percpu_is_write_locked() and percpu_is_read_locked()](https://git.kernel.org/torvalds/c/01fe8a3f818e)
   11. [perf/hw_breakpoint: Reduce contention with large number of tasks](https://git.kernel.org/torvalds/c/0912037fec11)
   12. [perf/hw_breakpoint: Introduce bp_slots_histogram](https://git.kernel.org/torvalds/c/16db2839a5a5)
   13. [perf/hw_breakpoint: Optimize max_bp_pinned_slots() for CPU-independent task targets](https://git.kernel.org/torvalds/c/9b1933b864a1)
   14. [perf/hw_breakpoint: Optimize toggle_bp_slot() for CPU-independent task targets](https://git.kernel.org/torvalds/c/ecdfb8896f2a)
   15. [perf, hw_breakpoint: Fix use-after-free if perf_event_open() fails](https://git.kernel.org/torvalds/c/4674ffe2fcad)
   16. [perf/hw_breakpoint: Annotate tsk->perf_event_mutex vs ctx->mutex](https://git.kernel.org/torvalds/c/82aad7ff7ac2)

**Low-overhead POSIX timer based sampling.** Prior to this change, the kernel
would prefer the main thread to deliver the signal to, in which case the
runtime would fallback to a slightly more expensive manual signal distribution
algorithm. See runtime implementation
[here](https://github.com/google/gwpsan/blob/master/gwpsan/base/timer.cpp).

   1. [posix-timers: Prefer delivery of signals to the current thread](https://git.kernel.org/torvalds/c/bcb7ee79029d)

Linux kernel 6.4 or later includes all the above changes.
