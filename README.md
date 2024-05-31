# GWPSan: Sampling-Based Sanitizer Framework

GWPSan is a framework for low-overhead sampling-based dynamic binary
instrumentation, designed for implementing various bug detectors (also called
"sanitizers") suitable for production uses. GWPSan does not modify the executed
code, but instead performs dynamic analysis from signal handlers.

> Note: GWPSan is inspired by
> [GWP-ASan](https://github.com/google/sanitizers/tree/master/gwp-asan/icse2024),
> but their design and implementation are completely different.

More documentation can be found [here](docs/).

## Usage

To use GWPSan, you have to build GWPSan and link it (statically or dynamically)
into a binary of interest. For most GWPSan "tools", the target binary must be
compiled with additional compiler flags, to add required [metadata
sections](https://llvm.org/docs/PCSectionsMetadata.html). GWPSan currently
requires Clang 18 or later, and Linux kernel 6.4 or later
([details](docs/dependencies.md)); support for the x86-64 and arm64
architectures is currently implemented. [Bazel](https://bazel.build/) is
required to build GWPSan.

To build GWPSan static and dynamic runtime libraries:

```
CC=<path to clang-18 or later>
CXX=<path to clang++-18 or later>
bazel build --action_env=CC="$CC" --action_env=CXX="$CXX" -c opt \
		$( [[ $(uname -m) == "x86_64" ]] && echo --config=x86_64 ) \
		//gwpsan/unified:libgwpsan.so //gwpsan/unified:gwpsan_archive
```

If the `clang` and `clang++` binaries in your `PATH` are already version 18 or
later, you may omit explicitly setting CC and CXX.

To build the target binary with statically linked runtime (adapt to your build
system):

```
GWPSAN_CFLAGS=-fexperimental-sanitize-metadata=atomics,uar
clang++ $GWPSAN_CFLAGS -c example.cpp -o example.o
...
clang++ -o example example.o ... \
        -Wl,--whole-archive "${GWPSAN_ROOT}/bazel-bin/gwpsan/unified/libgwpsan.a" -Wl,--no-whole-archive
```

To use the dynamically linked GWPSan runtime with a binary that has been build
with `GWPSAN_CFLAGS` but does not link the runtime statically:

```
clang++ $GWPSAN_CFLAGS -c example.cpp -o example.o
...
clang++ -o example example.o ...
LD_PRELOAD="${GWPSAN_ROOT}/bazel-bin/gwpsan/unified/libgwpsan.so" ./example
```

### Tunable flags

GWPSan has a number of tunable flags with reasonable defaults. If necessary,
the flags can be tuned with `GWPSAN_OPTIONS` environment variable. To see all
available flags, set `GWPSAN_OPTIONS=help` and run a binary with the GWPSan
runtime linked in; this will show help for all flags and immediately exit
without running the main program. Multiple flags can be separated by `:`.

> Note: Boolean flags can be enabled with either `GWPSAN_OPTIONS=foobar` or
> `GWPSAN_OPTIONS=foobar=1`; to explicitly disable, `GWPSAN_OPTIONS=foobar=0`.

### Enabling sampling and tools

By default, GWPSan is completely disabled and none of its bug detectors (also
called *tools*) are enabled. To enable GWPSan sampling, and crash on errors (in
production you may not always want to set `halt_on_error`):

```
# Sample once per second, and crash on detected errors:
export GWPSAN_OPTIONS=sample_interval_usec=1000000:halt_on_error
```

With that, GWPSan only enables period sampling, but no tools are enabled yet.

> Note: Sampling without enabled tools may be useful to test that a program
> tolerates receiving signals while in system calls. Error handling of system
> calls and C library functions must properly handle EINTR; retrying on EINTR
> should be sufficient (see
> [TEMP_FAILURE_RETRY](https://www.gnu.org/software/libc/manual/html_node/Interrupted-Primitives.html)).

The following [tools](docs/tools.md) are available:

-   `tsan` detects data races. Enabled/disabled with `GWPSAN_OPTIONS=tsan=0/1`.
-   `uar` detects use-after-return bugs. Enabled/disabled with
    `GWPSAN_OPTIONS=uar=0/1`.
-   `lmsan` detects uses of uninit values (experimental). Enabled/disabled with
    `GWPSAN_OPTIONS=lmsan=0/1`.

For example, to enable all tools:

```
# Sample once per second, crash on detected errors, and enable all tools:
export GWPSAN_OPTIONS=sample_interval_usec=1000000:halt_on_error:tsan:uar:lmsan
```

## Testing

To test GWPSan changes, or new toolchains and kernels:

```
CC=<path to clang-18 or later>
CXX=<path to clang++-18 or later>
bazel test --action_env=CC="$CC" --action_env=CXX="$CXX" --config=dev \
		$( [[ $(uname -m) == "x86_64" ]] && echo --config=x86_64 ) \
        //gwpsan/...
```

## License

The GWPSan library is licensed under the terms of the Apache license. See
LICENSE for more information.

## Disclaimer

This is not an officially supported Google product.
