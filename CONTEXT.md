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
The user's description of the watchpoint address, relative to a Target,
parsed once when the Target is built. For the kernel it is a symbol name
(Ksym) or a `0x` address (Kaddr); for task and device Targets it is a kexpr.

**kexpr**:
A C-style member access written against a Target's struct
(`&se.nr_migrations`, `mm->task_size`) that resolves to one kernel address.
Parsed into an `Expr`, then evaluated over a Walk to get the address.
_Avoid_: path, field expression

**Walk**:
The interface of a kernel struct object a kexpr is evaluated over: take a
member, deref a member, take the address, read the value. drgn's Object
implements it in production; tests use a fake struct tree.
_Avoid_: node, walker, object

**Bus**:
The kernel bus a device Target lives on (pci, usb, platform). It decides where
the device name is looked up and which struct embeds its `struct device`.

**SymKind**:
Whether a kernel symbol is a function or data. Execute watchpoints look up
functions; all others look up data. In kallsyms, `t`/`T` and the weak
`w`/`W` are functions; everything else is data.
_Avoid_: symbol type

**Msg**:
The one record sent from the BPF side to userspace for each watchpoint hit:
the kernel call chain, plus the accessed address and value for data
watchpoints. Its id counts hits, so a gap means dropped hits.
_Avoid_: event, sample
