use std::env;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::bump_memlock_rlimit::*;
use crate::ioctl::*;

use anyhow::{anyhow, Result};
use libbpf_rs::libbpf_sys::PERF_FLAG_FD_CLOEXEC;
use libbpf_rs::skel::*;
use libc::ioctl;
use perf_event_open_sys::bindings::{perf_event_attr, HW_BREAKPOINT_RW, PERF_TYPE_BREAKPOINT};
use perf_event_open_sys::perf_event_open;

mod bump_memlock_rlimit;
mod ioctl;

#[path = "../bpf/.output/memwatch.skel.rs"]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod memwatch;
use memwatch::*;

fn load_ebpf_prog() -> Result<MemwatchSkel<'static>> {
    /* We may have to bump RLIMIT_MEMLOCK for libbpf explicitly */
    if cfg!(bump_memlock_rlimit_manually) {
        bump_memlock_rlimit()?;
    }

    let builder = MemwatchSkelBuilder::default();
    /* Open BPF application */
    let open_skel = builder.open()?;
    /* Load & verify BPF programs */
    open_skel.load().map_err(anyhow::Error::msg)
}

fn attach_breakpoint(symbol_addr: usize, prog_fd: i32) -> Result<()> {
    let mut attr = perf_event_attr::default();
    attr.size = size_of::<perf_event_attr>() as u32;
    attr.type_ = PERF_TYPE_BREAKPOINT;
    attr.__bindgen_anon_3.bp_addr = symbol_addr as u64;
    attr.__bindgen_anon_4.bp_len = 4; // 4 bytes breakpoint
    attr.bp_type = HW_BREAKPOINT_RW;
    attr.__bindgen_anon_1.sample_period = 1; // response to every event
    attr.__bindgen_anon_2.wakeup_events = 1;
    attr.set_precise_ip(2); // request synchronous delivery

    let efd = unsafe { perf_event_open(&mut attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC as u64) };
    if efd < 0 {
        return Err(anyhow!("perf_event_open() fail"));
    }

    let err = unsafe { ioctl(efd, PERF_EVENT_IOC_RESET, 0) };
    if err < 0 {
        return Err(anyhow!("ioctl(PERF_EVENT_IOC_RESET) fail"));
    }

    let err = unsafe { ioctl(efd, PERF_EVENT_IOC_ENABLE, 0) };
    if err < 0 {
        return Err(anyhow!("ioctl(PERF_EVENT_IOC_ENABLE) fail"));
    }

    let err = unsafe { ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog_fd) };
    if err < 0 {
        return Err(anyhow!("ioctl(PERF_EVENT_IOC_SET_BPF) fail"));
    }

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 1 {
        return Err(anyhow!("usage: memwatch <addr>"));
    }

    let addr = usize::from_str_radix(&args[0], 16).expect("The input address is invalid");

    println!("Attach breakpoint on address {:x}", addr);

    let mut skel = load_ebpf_prog()?;
    let _ = skel.attach()?;
    let prog_fd = skel.progs().perf_event_handler().as_fd().as_raw_fd();
    attach_breakpoint(addr, prog_fd)?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {}

    Ok(())
}
