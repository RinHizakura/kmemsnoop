/* TODO: These definitions are retrieved from linux source codes.
 * Any good library which we can refer to directly? */

use libc::{c_long, c_ulong};

/* FIXME: Consider different platform for these magic bits */
const _IOC_NRBITS: c_ulong = 8;
const _IOC_TYPEBITS: c_ulong = 8;
const _IOC_SIZEBITS: c_ulong = 14;
const _IOC_DIRBITS: c_long = 2;

const _IOC_NRMASK: c_ulong = (1 << _IOC_NRBITS) - 1;
const _IOC_TYPEMASK: c_ulong = (1 << _IOC_TYPEBITS) - 1;
const _IOC_SIZEMASK: c_ulong = (1 << _IOC_SIZEBITS) - 1;
const _IOC_DIRMASK: c_ulong = (1 << _IOC_DIRBITS) - 1;

const _IOC_NRSHIFT: c_ulong = 0;
const _IOC_TYPESHIFT: c_ulong = _IOC_NRSHIFT + _IOC_NRBITS;
const _IOC_SIZESHIFT: c_ulong = _IOC_TYPESHIFT + _IOC_TYPEBITS;
const _IOC_DIRSHIFT: c_ulong = _IOC_SIZESHIFT + _IOC_SIZEBITS;

const _IOC_NONE: c_ulong = 0;
const _IOC_WRITE: c_ulong = 1;
const _IOC_READ: c_ulong = 2;

/* https://github.com/torvalds/linux/blob/master/include/uapi/linux/perf_event.h*/
pub const PERF_EVENT_IOC_ENABLE: c_ulong = _IO(b'$', 0);
pub const PERF_EVENT_IOC_RESET: c_ulong = _IO(b'$', 3);
pub const PERF_EVENT_IOC_SET_BPF: c_ulong = _IOW::<u32>(b'$', 8);

/* These are originated from Linux. They don't follow snake case to
 * align definition in Linux.
 * https://github.com/torvalds/linux/blob/master/rust/kernel/ioctl.rs */
#[allow(non_snake_case)]
const fn _IOC(dir: c_ulong, ty: u8, nr: c_ulong, size: usize) -> c_ulong {
    (dir << _IOC_DIRSHIFT)
        | ((ty as c_ulong) << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | ((size as c_ulong) << _IOC_SIZESHIFT)
}

#[allow(non_snake_case)]
const fn _IO(ty: u8, nr: c_ulong) -> c_ulong {
    _IOC(_IOC_NONE, ty, nr, 0)
}

#[allow(non_snake_case)]
const fn _IOR<T>(ty: u8, nr: c_ulong) -> c_ulong {
    _IOC(_IOC_READ, ty, nr, core::mem::size_of::<T>())
}

#[allow(non_snake_case)]
const fn _IOW<T>(ty: u8, nr: c_ulong) -> c_ulong {
    _IOC(_IOC_WRITE, ty, nr, core::mem::size_of::<T>())
}

#[allow(non_snake_case)]
fn _IOC_TYPE(nr: c_ulong) -> u8 {
    ((nr >> _IOC_TYPESHIFT) & _IOC_TYPEMASK) as u8
}
