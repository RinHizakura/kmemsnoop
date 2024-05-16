use std::env;
use std::io::Error;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::bump_memlock_rlimit::*;
use crate::utils::*;

use blazesym::symbolize::Sym;
use blazesym::symbolize::{CodeInfo, Input, Kernel, Source, Symbolized, Symbolizer};
use blazesym::Addr;

use libbpf_rs::libbpf_sys::PERF_FLAG_FD_CLOEXEC;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::{skel::*, Link, Program};

use anyhow::{anyhow, Result};
use libc::{c_int, pid_t};
use perf_event_open_sys::bindings::{
    perf_event_attr, HW_BREAKPOINT_RW, HW_BREAKPOINT_X, PERF_SAMPLE_CALLCHAIN, PERF_TYPE_BREAKPOINT,
};
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

fn attach_perf_event(
    attr: &mut perf_event_attr,
    pid: pid_t,
    cpu: c_int,
    group_fd: c_int,
    prog: &mut Program,
) -> Result<Link> {
    let efd = unsafe {
        perf_event_open(
            attr as *mut perf_event_attr,
            pid,
            cpu,
            group_fd,
            PERF_FLAG_FD_CLOEXEC as u64,
        )
    };

    if efd < 0 {
        println!("efd = {}", efd);
        return Err(anyhow!(format!(
            "perf_event_open() fail: {}",
            Error::last_os_error()
        )));
    }

    let link = prog.attach_perf_event(efd)?;
    Ok(link)
}

fn attach_breakpoint(symbol_addr: usize, prog: &mut Program) -> Result<Vec<Link>> {
    let mut attr = perf_event_attr::default();
    attr.size = size_of::<perf_event_attr>() as u32;
    attr.type_ = PERF_TYPE_BREAKPOINT;
    attr.__bindgen_anon_3.bp_addr = symbol_addr as u64;
    attr.__bindgen_anon_4.bp_len = 8;
    attr.bp_type = HW_BREAKPOINT_X;
    // response to every event
    attr.__bindgen_anon_1.sample_period = 1;
    attr.__bindgen_anon_2.wakeup_events = 1;
    // request synchronous delivery
    attr.set_precise_ip(2);
    /* On perf_event with precise_ip, calling bpf_get_stack()
     * may trigger unwinder warnings and occasional crashes.
     * bpf_get_[stack|stackid] works around this issue by using
     * callchain attached to perf_sample_data. */
    attr.sample_type = PERF_SAMPLE_CALLCHAIN as u64;

    let mut links = Vec::new();
    for cpu in get_online_cpus() {
        let link = attach_perf_event(&mut attr, -1, cpu, -1, prog)?;
        links.push(link);
    }

    Ok(links)
}

const MSG_TYPE_STACK: u64 = 0;

#[repr(C)]
struct MsgEnt {
    id: u64,
    typ: u64,
}
unsafe impl Plain for MsgEnt {}

const PERF_MAX_STACK_DEPTH: usize = 127;
type Stack = [u64; PERF_MAX_STACK_DEPTH];

#[repr(C)]
struct StackMsg {
    kstack_sz: u64,
    kstack: Stack,
}
unsafe impl Plain for StackMsg {}

const ADDR_WIDTH: usize = 16;

fn print_frame(name: &str, input_addr: Addr, addr: Addr, offset: usize) {
    println!(
        "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}",
        width = ADDR_WIDTH
    )
}

fn stack_msg_handler(bytes: &[u8]) -> i32 {
    let msg: &StackMsg = cast(bytes);
    let stack_sz = msg.kstack_sz as usize / size_of::<u64>();
    let addrs = &msg.kstack[..stack_sz];

    let src = Source::Kernel(Kernel::default());
    let symbolizer = Symbolizer::new();
    let syms = symbolizer.symbolize(&src, Input::AbsAddr(addrs)).unwrap();

    for (input_addr, sym) in addrs.iter().copied().zip(syms) {
        match sym {
            Symbolized::Sym(Sym {
                name, addr, offset, ..
            }) => {
                print_frame(&name, input_addr, addr, offset);
            }
            Symbolized::Unknown(..) => {
                println!("{input_addr:#0width$x}: <no-symbol>", width = ADDR_WIDTH)
            }
        }
    }

    0
}

pub fn msg_handler(bytes: &[u8]) -> i32 {
    let ent_size = size_of::<MsgEnt>();
    let ent = &bytes[0..ent_size];
    let inner = &bytes[ent_size..];

    let ent: &MsgEnt = cast(ent);
    println!("Get message id={}", ent.id);

    match ent.typ {
        MSG_TYPE_STACK => stack_msg_handler(inner),
        _ => 0,
    }
}

fn main() -> Result<()> {
    let addr = parse_args()?;

    let mut skel = load_ebpf_prog()?;
    let _ = skel.attach()?;

    let mut progs = skel.progs_mut();
    let prog = progs.perf_event_handler();
    /* The link should be hold to represent the lifetime of
     * breakpoint. */
    let _link = attach_breakpoint(addr, prog)?;

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
