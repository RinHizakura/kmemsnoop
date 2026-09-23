# kmemsnoop

A CLI that installs a hardware breakpoint in the running Linux kernel and
reports every hit from userspace.

## Language

**Watchpoint**:
A hardware breakpoint installed on one kernel address, with an access kind
(read, write, read/write, execute) and a length (1, 2, 4 or 8 bytes).
_Avoid_: breakpoint (reserved for the hardware register itself), tracepoint

**Target**:
Where a watchpoint expression starts from: the kernel itself, the task with a
given pid, or a named device on a Bus.
_Avoid_: source, root object

**Expression** (`expr`):
The user's description of the watchpoint address, relative to a Target. For
the kernel Target it is a symbol name or a `0x` address; for task and device
Targets it is a kexpr.

**kexpr**:
A C-style member access written against a Target's struct
(`&se.nr_migrations`, `mm->task_size`) that resolves to one kernel address.
_Avoid_: path, field expression

**Bus**:
The kernel bus a device Target lives on (pci, usb, platform). It decides where
the device name is looked up and which struct embeds its `struct device`.

**SymKind**:
Whether a kernel symbol is a function or data. Execute watchpoints look up
functions; all others look up data.
_Avoid_: symbol type

**Msg**:
One record sent from the BPF side to userspace when a watchpoint hits, either
a stack (kernel call chain) or data (accessed address and value).
_Avoid_: event, sample
