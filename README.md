# kmemsnoop

## Introduction

On specific processor, hardware breakpoint registers are supported to monitor
memory access or instruction execution in hardware manner. The great advantage
of using these is that it causes little overhead on trace.

With the `kmemsnoop`, you can easily install a hardware
breakpoint/watchpoint in Linux kernel, as long as it is supported for your
platform. This enable to trace/debug the running Linux kernel without KGDB or
hardware debugger.

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
kernel symbols from /proc/kallsyms instead of inspecting the vmlinux source.
On top of that, /proc/kallsyms makes kernel tracing with
[KASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
enabled possible.

```
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
```

### Build

These dependencies are required to build kmemsnoop.

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
`kmemsnoop` now.

```
$ make
```

### Execute

```
$ kmemsnoop --help

Usage: kmemsnoop [OPTIONS] <BP> <SYMBOL>

Arguments:
  <BP>      The type of the watchpoint [possible values: r1, w1, rw1, x1, r2, w2, rw2, x2, r4, w4, rw4, x4, r8, w8, rw8, x8]
  <SYMBOL>  kernel symbol or address to attach the watchpoint

Options:
  -v, --vmlinux <VMLINUX>  vmlinux path of running kernel(need nokaslr)
  -h, --help               Print help
```

* `SYMBOL` is the name of kernel symbol to attach the watchpoint. Using the
address value in hex is also availible.
* `BP` is the type of watchpoint. For example, r8 means to watch a read
opperation from the base of `SYMBOL` with 8 bytes length.

Since `kmemsnoop` relies on eBPF to collect kernel informations, it needs to be
run as root. The type and the symbol/address to attach the breakpoint must
be required as command line arguments.

The related vmlinux file for the running kernel is optional. If you don't give
it to `kmemsnoop`, `kmemsnoop` will fallback to find address of the symbol from
`/proc/kallsyms` which may only have a limited subset of symbol information.
Besides, you need to add `nokaslr` to kernel bootargs when using vmlinux for
symbol information, because the address on specific kernel symbol will be
random without it.

For example, if you want to trace the execution of kernel function
`schduler_tick()`.

```
$ sudo kmemsnoop x8 scheduler_tick
```

Or if you want to trace the read and write access for kernel parameters
`sysctl_sched_cfs_bandwidth_slice`

```
$ sudo kmemsnoop rw4 sysctl_sched_cfs_bandwidth_slice -v vmlinux

# You can run the following command to trigger the watchpoint!
$ cat /proc/sys/kernel/sched_cfs_bandwidth_slice_us
```

Currently, only the stack backtrace is showed when hitting the watchpoint. Any
requirement for the extra kernel information that you would like to see are
welcome to comment!

## How to I know the address of target?

From `/proc/kallsyms`, we know the address of exported symbol. However,
sometime we may have interest for the struct that dynamic allocated in the
kernel. For example, `struct task_struct` for task pid 1, or
`struct usb_driver` for the USB keyboard device.

With [drgn](https://github.com/osandov/drgn/), all these requirement can be
achieved simply! Under the `tools` directory, some helper scripts are provided
for you to inspect more on the kernel.

Let's say we want to track the migration of task pid=36395. To meet the
purpose, we can set a watchpoint on `nr_migrations` of that task's
`sched_entity`. This can be done by the following steps:

1. We can know the address of task-36395's `task_struct` with the `task.py`
script.
```
$ drgn ./tools/task.py -p 36395 | grep task_struct
task_struct@0xffff8881a5773f00:
...
```
2. Get offset of member `se` in `task_struct`.
```
$ drgn ./tools/struct_off.py "struct task_struct" "se"
offset of 'se' in 'struct task_struct' = 192
```
3. Get offset of member `nr_migrations` in `sched_entity`.
```
$ drgn ./tools/struct_off.py "struct sched_entity" "nr_migrations"
offset of 'nr_migrations' in 'struct sched_entity' = 96
```
4. With these steps, we know the watchpoint should be set on
0xffff8881a5773f00 + 192 + 96 = 0xffff8881a5774020.
```
$ sudo ./kmemsnoop w8 ffff8881a5774020

Watchpoint attached on ffff8881a5774020
Get message id=1
0xffffffff8113637e: set_task_cpu @ 0xffffffff81136300+0x7e
0xffffffff81137928: try_to_wake_up @ 0xffffffff811377f0+0x138
0xffffffff8133a764: pollwake @ 0xffffffff8133a6f0+0x74
0xffffffff811518fd: __wake_up_common @ 0xffffffff81151880+0x7d
0xffffffff81151a8c: __wake_up_common_lock @ 0xffffffff81151a10+0x7c
0xffffffff81938c97: n_tty_receive_buf_common @ 0xffffffff819386e0+0x5b7
0xffffffff8193c50d: tty_port_default_receive_buf @ 0xffffffff8193c4d0+0x3d
0xffffffff8193c087: flush_to_ldisc @ 0xffffffff8193bff0+0x97
0xffffffff8111d698: process_one_work @ 0xffffffff8111d4b0+0x1e8
0xffffffff8111d893: worker_thread @ 0xffffffff8111d840+0x53
0xffffffff81124854: kthread @ 0xffffffff81124730+0x124
0xffffffff810018df: ret_from_fork @ 0xffffffff810018c0+0x1f
```

So whenever the migration happens, the watchpoint can be triggered!
Run the command `drgn ./tools/task.py -p 36395` again, you should also
be able to see the increase of `nr_migrations`.
