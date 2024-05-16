use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::bump_memlock_rlimit::*;
use crate::ksym::KSymResolver;
use crate::msg::*;
use crate::perf::attach_breakpoint;

use libbpf_rs::skel::*;
use libbpf_rs::RingBufferBuilder;

use anyhow::{anyhow, Result};

mod bump_memlock_rlimit;
mod ksym;
mod msg;
mod perf;
mod utils;

#[path = "../bpf/.output/memwatch.skel.rs"]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod memwatch;
use libc::sleep;
use memwatch::*;

fn ksym2addr(sym: &str) -> Result<usize> {
    let kresolver = KSymResolver::new();
    kresolver
        .find_ksym(sym)
        .ok_or(anyhow!(format!("Failed to address of symbol {sym}")))
}

fn parse_args() -> Result<usize> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 1 {
        return Err(anyhow!("usage: memwatch <addr/symbol_name>"));
    }

    if let Ok(addr) = usize::from_str_radix(&args[0], 16) {
        return Ok(addr);
    }

    ksym2addr(&args[0])
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

fn main() -> Result<()> {
    let addr = parse_args()?;

    let mut skel = load_ebpf_prog()?;
    let _ = skel.attach()?;

    let mut progs = skel.progs_mut();
    let prog = progs.perf_event_handler();
    /* The link should be hold to represent the lifetime of
     * breakpoint. */
    let _link = attach_breakpoint(addr, prog)?;

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
