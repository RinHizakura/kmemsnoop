# kmemsnoop

## Introduction

On specific processors, hardware breakpoint registers are supported to monitor
memory access or instruction execution in hardware manner. The great advantage
of using these is that it causes little overhead on trace.

With the `kmemsnoop`, you can easily install a hardware
breakpoint/watchpoint in Linux kernel, as long as it is supported for your
platform. This enables us to trace/debug the running Linux kernel without KGDB
or hardware debugger.

## Usage

### Prerequisite

`kmemsnoop` relies on
[eBPF CO-RE(Compile Once – Run Everywhere)](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html#bpf-co-re-compile-once-run-everywhere)
to enable complete kernel tracing, so the following kernel config **must**
be required.

```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
```

Besides, you may want to expose more kernel symbols to userspace with the
following settings. These are convenient for you to find the address of
kernel symbols from `/proc/kallsyms` instead of inspecting the vmlinux source.
On top of that, `/proc/kallsyms` makes kernel tracing with
[KASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
enabled possible.

```
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
```

(Optional) `kmemsnoop` tool support a special type of expression called
**kexpr**. It allows you to access specific kind of object in the kernel(e.g.
a `sturct task_struct` from task pid), and set watchpoint on the object member
with the given expression. In order to use this feature, you need to enable
`/proc/kcore` to make access the kernel objects possible.

```
CONFIG_PROC_KCORE=y
```

### Build

These dependencies are required to build kmemsnoop.

```
$ sudo apt install clang llvm libelf1 libelf-dev zlib1g-dev
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
`kmemsnoop` now.

```
# Build for kernel symbol and address expression only
$ make
```

### Execute

```
$ kmemsnoop --help

Usage: kmemsnoop [OPTIONS] <BP> <EXPR>

Arguments:
  <BP>    type of the watchpoint [possible values: r1, w1, rw1, x1, r2, w2, rw2, x2, r4, w4, rw4, x4, r8, w8, rw8, x8]
  <EXPR>  expression of watchpoint(kernel symbol or addess by default)

Options:
  -v, --vmlinux <VMLINUX>    vmlinux path of running kernel(need nokaslr)
  -p, --pid-task <PID_TASK>  kexpr: use 'struct task_struct' from pid
  -h, --help                 Print help
```

* `EXPR` is the expression to describe the watchpoint. Without "special option"
(e.g. `-p`), it can be the name of kernel symbol or addess value in hex. If
using the special option, it is the expression dereference from the
given structure according the option.
* `BP` is the type of watchpoint. For example, r8 means to watch a read
opperation from the base of `SYMBOL` with 8 bytes length.

Options:
* `VMLINUX` is the path of `vmlinux` file for getting the address of kernel
symbol instead of using `/proc/kallsyms`.
* `PID_TASK` enables to use kexpr on `EXPR`. This allow you to access
the field which is dereference from a `struct task_struct`
by `EXPR` as watchpoint. The `struct task_struct` comes from the task whose
pid is `PID_TASK`.

Since `kmemsnoop` relies on eBPF to collect kernel informations, it needs to be
run as root. The type and the symbol/address to attach the breakpoint must
be required as command line arguments.

The related vmlinux file for the running kernel is optional. If you don't give
it to `kmemsnoop`, `kmemsnoop` will fallback to find address of the symbol from
`/proc/kallsyms` which may only have a limited subset of symbol information.
Besides, you need to add `nokaslr` to kernel bootargs when using vmlinux for
symbol information, because the address on specific kernel symbol will be
random without it.

### Examples

For example, if you want to trace the execution of kernel function
`schduler_tick()`:

```
$ sudo kmemsnoop x8 scheduler_tick
```

If you want to trace the read and write access for kernel parameters
`sysctl_sched_cfs_bandwidth_slice`:

```
$ sudo kmemsnoop rw4 sysctl_sched_cfs_bandwidth_slice -v vmlinux

# You can run the following command to trigger the watchpoint!
$ cat /proc/sys/kernel/sched_cfs_bandwidth_slice_us
```

If you want to trace the object under `struct task_struct`, for example, the
`&task->on_rq` of task pid 1:

```
$ sudo kmemsnoop -p 1 rw4 on_rq
```

If you want to trace the pointer under `task_struct` instead, for example,
the `task->parent` of task pid 1:

```
$ sudo kmemsnoop -p 1 rw8 *parent
```

Currently, only the stack backtrace is showed when hitting the watchpoint. Any
requirement for the extra kernel information that you would like to see are
welcome to comment!
