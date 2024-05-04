use std::env;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::bump_memlock_rlimit::*;
use crate::utils::*;

use libbpf_rs::libbpf_sys::PERF_FLAG_FD_CLOEXEC;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::{skel::*, Link, Program};

use anyhow::{anyhow, Result};
use libc::getchar;
use perf_event_open_sys::bindings::{perf_event_attr, HW_BREAKPOINT_RW, PERF_TYPE_BREAKPOINT};
use perf_event_open_sys::perf_event_open;
use plain::Plain;

mod bump_memlock_rlimit;
mod utils;

#[path = "../bpf/.output/memwatch.skel.rs"]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod memwatch;
use memwatch::*;

fn parse_args() -> Result<usize> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 1 {
        return Err(anyhow!("usage: memwatch <addr>"));
    }

    let addr = usize::from_str_radix(&args[0], 16).expect("The input address is invalid");

    Ok(addr)
}

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

fn attach_breakpoint(symbol_addr: usize, prog: &mut Program) -> Result<Link> {
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

    let link = prog.attach_perf_event(efd)?;
    Ok(link)
}

#[repr(C)]
struct MsgEnt {
    id: u64,
}
unsafe impl Plain for MsgEnt {}

pub fn msg_handler(bytes: &[u8]) -> i32 {
    let ent: &MsgEnt = cast(bytes);

    println!("Get message id={}", ent.id);

    return 0;
}

fn test_main(val: &mut i32) -> Result<()> {
    let mut c = unsafe { getchar() };
    while c != -1 {
        c = unsafe { getchar() };
        *val = c;
    }

    Ok(())
}

fn main() -> Result<()> {
    let mut test_mode = false;
    let mut addr = parse_args()?;
    let mut val = 0;

    /* FIXME: We use address 0 as a hint to test the watchpoint, which
     * is achieved by tracing the internal variable which can be written
     * by user input. This is not elegant and should be removed when
     * the project get stable. */
    if addr == 0 {
        test_mode = true;
        addr = &val as *const i32 as usize;
    }

    let mut skel = load_ebpf_prog()?;
    let _ = skel.attach()?;

    let mut progs = skel.progs_mut();
    let prog = progs.perf_event_handler();
    /* The link should be hold to represent the lifetime of
     * breakpoint. */
    let _link = attach_breakpoint(addr, prog)?;

    if test_mode {
        return test_main(&mut val);
    }

    println!("Attach breakpoint on address {:x}", addr);

    let mut builder = RingBufferBuilder::new();
    let binding = skel.maps();
    builder.add(binding.msg_ringbuf(), msg_handler)?;
    let msg = builder.build()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        let result = msg.poll(Duration::MAX);
        if let Err(_r) = &result {
            return result.map_err(anyhow::Error::msg);
        }
    }

    Ok(())
}
