use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::bump_memlock_rlimit::*;
use crate::ksym::{KSymResolver, KSYM_FUNC};
use crate::msg::*;
use crate::perf::attach_breakpoint;

use libbpf_rs::skel::*;
use libbpf_rs::RingBufferBuilder;

use anyhow::{anyhow, Result};
use clap::{CommandFactory, Parser};

use blazesym::inspect;
use blazesym::inspect::Inspector;

mod bump_memlock_rlimit;
mod ksym;
mod msg;
mod perf;
mod utils;

#[path = "../bpf/.output/memwatch.skel.rs"]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod memwatch;
use memwatch::*;

fn vmlinux2addr(sym: &str, vmlinux: &str) -> Result<usize> {
    let src = inspect::Source::Elf(inspect::Elf::new(vmlinux));
    let inspector = Inspector::new();
    let results = inspector.lookup(&src, &[sym])?;

    let results = results.into_iter().flatten().collect::<Vec<_>>();

    if results.len() != 1 {
        return Err(anyhow!(format!("Failed to get address of symbol {sym}")));
    }

    let addr = results[0].addr as usize;

    Ok(addr)
}

fn ksym2addr(sym: &str) -> Result<usize> {
    let kresolver = KSymResolver::new();
    kresolver
        .find_ksym(sym, KSYM_FUNC)
        .ok_or(anyhow!(format!("Failed to get address of symbol {sym}")))
}

#[derive(Parser)]
struct Cli {
    #[arg(help = "kernel symbol to attach the watchpoint")]
    symbol: Option<String>,

    #[arg(short, long, help = "vmlinux path of running kernel(need nokaslr)")]
    vmlinux: Option<String>,
}

fn parse_args() -> Result<usize> {
    let cli = Cli::parse();
    let symbol = cli.symbol;

    if symbol.is_none() {
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        return Err(anyhow!("cmdline error"));
    }

    let symbol = symbol.unwrap();
    if let Ok(addr) = usize::from_str_radix(&symbol, 16) {
        return Ok(addr);
    }

    let vmlinux = cli.vmlinux;
    if let Some(vmlinux) = vmlinux {
        vmlinux2addr(&symbol, &vmlinux)
    } else {
        ksym2addr(&symbol)
    }
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
    println!("Watchpoint attached on {addr:x}");

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
