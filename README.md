# memwatch

## Introduction

On specific processor, hardware breakpoint registers are supported to monitor
memory access or instruction execution in hardware manner. The great advantage
of using these is that it causes little overhead compared to the normal
execution.

With the `memwatch` tool, you can easily install a hardware
breakpoint/watchpoint in Linux kernel, as long as it is supported for your
platform. This enable to trace/debug the running Linux kernel without KGDB or
hardware debugger.

## Usage

### Prerequisite

`memwatch` relies on
[eBPF CO-RE(Compile Once – Run Everywhere)](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html#bpf-co-re-compile-once-run-everywhere)
to enable complete kernel tracing, so the following kernel config **must**
be required.

```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
```

You may want to expose more kernel symbols with the following configs.
These will be convenient for you to find the address of kernel symbols. It is
also useful to trace kernel with
[KASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
enabled or percpu variables.

```
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
```

### Build

These dependencies are required to build memwatch.

```
$ apt install clang llvm libelf1 libelf-dev zlib1g-dev
```

You will also need bpftool for the generating of vmlinux.h.

```
$ git clone https://github.com/libbpf/bpftool.git
$ cd bpftool
$ git submodule update --init
$ cd src
$ make
$ sudo make install
```

After the installation of these dependencies, you should be able to build
`memwatch` now.

```
$ make
```

### Execute

```
$ memwatch --help

Usage: memwatch [OPTIONS] <BP> <SYMBOL>

Arguments:
  <BP>      [possible values: r1, w1, rw1, x1, r2, w2, rw2, x2, r4, w4, rw4, x4, r8, w8, rw8, x8]
  <SYMBOL>  kernel symbol to attach the watchpoint

Options:
  -v, --vmlinux <VMLINUX>  vmlinux path of running kernel(need nokaslr)
  -h, --help               Print help
```

Since `memwatch` relies on eBPF to collect kernel informations, it needs to be
run as root. The type and the symbol/address to attach the breakpoint must
be required as command line arguments.

The related vmlinux file for the running kernel is optional. If you don't give
it to `memwatch`, `memwatch` will fallback to find address of the symbol from
`/proc/kallsyms` which may only have a limited subset of symbol information.
Besides, you need to add `nokaslr` to kernel bootargs when using vmlinux for
symbol information, because the address on specific kernel symbol will be
random without it.

For example, if you want to trace the execution of kernel function
`schduler_tick()`.

```
$ sudo memwatch x8 scheduler_tick
```

Or if you want to trace the read and write access for kernel parameters
`sysctl_sched_cfs_bandwidth_slice`

```
$ sudo memwatch rw4 sysctl_sched_cfs_bandwidth_slice -v vmlinux

# You can run the following command to trigger the watchpoint!
$ cat /proc/sys/kernel/sched_cfs_bandwidth_slice_us
```

Currently, only the stack backtrace is showed when hitting the watchpoint. Any
requirement for the extra kernel information that you would like to see are
welcome to comment!
