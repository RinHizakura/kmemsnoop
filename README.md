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
a `struct task_struct` from task pid), and set watchpoint on the object member
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
      --pid-task <PID_TASK>  kexpr: use 'struct task_struct' from pid
      --pci-dev <PCI_DEV>    kexpr: 'struct pci_dev' from the device name
      --usb-dev <USB_DEV>    kexpr: 'struct usb_device' from the device name
      --plat-dev <PLAT_DEV>  kexpr: 'struct platform_device' from the device name
  -h, --help                 Print help
```

* `EXPR` is the expression to describe the watchpoint. If not using the "kexpr"
options(e.g. `--pid-task`), it can be the name of kernel symbol or addess value
in hex. If using the "kexpr", it is the expression dereferenced from the
given structure according the option.
* `BP` is the type of watchpoint. For example, r8 means to watch a read
operation from the base of `EXPR` with 8 bytes length.

Options:
* `VMLINUX` is the path of `vmlinux` file for getting the address of kernel
symbol instead of using `/proc/kallsyms`. To use this option, you need to
add `nokaslr` to kernel bootargs because the address on kernel symbol will be
random without it.
* `PID_TASK` allows you to watch the field which is dereferenced from a
`struct task_struct` by `EXPR`. The `struct task_struct` comes from the task
whose pid is `PID_TASK`.
* `PCI_DEV` allows you to watch the field which is dereferenced from a
`struct pci_dev` by `EXPR`. The `struct pci_dev` comes from the device with
name `PCI_DEV`. Check `/sys/bus/pci/devices/` for the valid name.
* `USB_DEV` allows you to watch the field which is dereferenced from a
`struct usb_device` by `EXPR`. The `struct usb_device` comes from the device with
name `USB_DEV`. Check `/sys/bus/usb/devices/` for the valid name.
* `PLAT_DEV` allows you to watch the field which is dereferenced from a
`struct platform_device` by `EXPR`. The `struct platform_device` comes from the
device with name `PLAT_DEV`. Check `/sys/bus/platform/devices/` for the valid name.

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

If you want to watch the object under `struct task_struct`, for example, the
`&task->on_rq` of task pid 1:

```
$ sudo kmemsnoop --pid-task 1 rw4 on_rq
```


If you want to watch the object point by a pointer under `task_struct` instead,
for example, the `task->parent` of task pid 1:

```
$ sudo kmemsnoop --pid-task 1 rw8 *parent
```

If you want to watch the field inside the struct in `task_struct`. For example
`&task->se.nr_migrations`.

```
$ sudo kmemsnoop --pid-task 1 rw8 se.nr_migrations
```

If you want to watch the field inside the struct which can be referenced from
the `task_struct`. For example `&task->mm->task_size`.

```
$ sudo kmemsnoop --pid-task 1 rw8 mm->task_size
```

If you want to trace the field `vendor` under `struct pci_dev` for PCI device
`0001:00:00.0`:

```
$ sudo kmemsnoop --pci-dev 0000:00:00.0 rw2 vendor

# You can run the following command to trigger the watchpoint!
$ cat /sys/bus/pci/devices/0000:00:00.0/vendor
```
