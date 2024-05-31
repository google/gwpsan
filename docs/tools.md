# Tools

Here we briefly describe each GWPSan tool in more detail.

> Note: The lower-case short name of each tool also corresponds to the
> `GWPSAN_OPTIONS` variable.

## UAR: Use-after-return detector

[Source](https://github.com/google/gwpsan/blob/master/gwpsan/uar/uar.cpp)

*UAR* detects use-after-return bugs for stack variables. It can be enabled with
`GWPSAN_OPTIONS=uar=1`.

In a nutshell, it doubles the size of a thread stack and effectively creates
two stacks within: the main stack where the thread starts running and a second
stack that is used for use-after-return detection:

```
╔═════════════╦═══════════════╦═════════════╦═══════════════╗
║   guard     ║ second stack  ║   guard     ║  main stack   ║
║(guard_size_)║ (stack_size_) ║(guard_size_)║ (stack_size_) ║
╚═════════════╩═══════════════╩═════════════╩═══════════════╝
```

Then the tool catches function entry with timer sampling and switches execution
to the second stack. On return from the function execution is switched back to
the main stack, and the second stack is protected as `PROT_NONE`. Any
subsequent accesses via dangling references to the second stack will cause a
paging fault.

The changed stack layout may cause issues for programs that track
used/remaining stack space, and try to do other unusual things with stack.

## TSan: Data-race detector

[Source](https://github.com/google/gwpsan/blob/master/gwpsan/tsan/tsan.cpp)

*TSan (Thread Sanitizer)* detects [data
races](https://en.cppreference.com/w/cpp/language/multithread). It can be
enabled with `GWPSAN_OPTIONS=tsan=1`.

> Note: The name "TSan" is inspired by the similarly named
> compiler-instrumentation based tool [ThreadSanitizer
> (TSan)](https://clang.llvm.org/docs/ThreadSanitizer.html). While both detect
> data races, their runtime properties and implementations are completely
> different.

The basic algorithm is based on the idea described by [Data
Collider](https://www.usenix.org/legacy/event/osdi10/tech/full_papers/Erickson.pdf).
In a nutshell, it stops a thread at a memory access, arms a hardware watchpoint
for the address of the memory access, and pauses the thread for a bit. If the
watchpoint fires in another thread, we caught a data race. Compiler-based
metadata is used to filter out atomic accesses.

## LMSan: Use-of-uninitialized memory detector

[Source](https://github.com/google/gwpsan/blob/master/gwpsan/lmsan/lmsan.cpp)

*LMSan (Lightweight Memory Sanitizer)* detects uses of uninitialized memory.
*Currently experimental and not yet ready for use.*
