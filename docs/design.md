# Runtime Design

GWPSan [depends](dependencies.md) on specific features of compiler, and kernel,
with the runtime implementing a binary analysis framework based on decoding and
emulating instructions. In the below we describe the runtime components.

### Binary Analysis

Machine code is decoded into abstract ISA instructions (`Instr` class in
`instruction.h`) by `InstrDecoder::Decode` method using
[DynamoRIO](https://dynamorio.org/) framework. Abstract instructions are
executed/emulated by `CPUContext::Execute`. `CPUContext` class holds machine
context (registers) along with meta information (taint bits/origins). `Env`
class abstracts machine memory (e.g. can do actual stores to memory, or discard
stores) and stores meta information for values in memory.

### Unified Tool

The [unified
tool](https://github.com/google/gwpsan/blob/master/gwpsan/unified/unified.cpp) receives
periodic timer signals, and speculatively executes some amount of instructions
for the thread. As it executes instructions it looks for potential instructions
of interest (memory accesses for data races detection, etc). If it finds any,
it dispatches to the concrete tools to do the checking.
