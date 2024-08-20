use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::bump_memlock_rlimit::*;
use crate::kexpr::*;
use crate::ksym::{KSymResolver, KSYM_FUNC};
use crate::msg::*;
use crate::perf::{attach_breakpoint, BpType};
use crate::utils::hexstr2int;

use ksym::KSYM_DATA;
use libbpf_rs::skel::*;
use libbpf_rs::RingBufferBuilder;

use anyhow::{anyhow, Result};
use clap::Parser;

use blazesym::inspect;
use blazesym::inspect::Inspector;

mod bump_memlock_rlimit;
mod kexpr;
mod ksym;
mod msg;
mod perf;
mod utils;

#[path = "../bpf/.output/kmemsnoop.skel.rs"]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod kmemsnoop;
use kmemsnoop::*;

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

fn ksym2addr(sym: &str, bp: &BpType) -> Result<usize> {
    let kresolver = KSymResolver::new();

    let sym_typ = match bp {
        BpType::X1 | BpType::X2 | BpType::X4 | BpType::X8 => KSYM_FUNC,
        _ => KSYM_DATA,
    };

    kresolver
        .find_ksym(sym, sym_typ)
        .ok_or(anyhow!(format!("Failed to get address of symbol {sym}")))
}

#[derive(Parser)]
struct Cli {
    #[arg(value_enum, help = "type of the watchpoint")]
    bp: BpType,

    #[arg(help = "expression of watchpoint(kernel symbol or addess by default)")]
    expr: String,

    #[arg(short, long, help = "vmlinux path of running kernel(need nokaslr)")]
    vmlinux: Option<String>,

    #[arg(short, long, help = "kexpr: use 'struct task_struct' from pid")]
    pid_task: Option<u64>,
}

fn parse_addr(bp: &BpType) -> Result<usize> {
    let cli = Cli::parse();
    let expr = cli.expr;
    let pid_task = cli.pid_task;
    let vmlinux = cli.vmlinux;

    /* Use kexpr if special option is specified */
    if let Some(pid) = pid_task {
        return task_kexpr2addr(pid, &expr);
    }

    if let Ok(addr) = hexstr2int(&expr) {
        return Ok(addr);
    }

    /* Use vmlinux to know the address by symbol */
    if let Some(vmlinux) = vmlinux {
        return vmlinux2addr(&expr, &vmlinux);
    }

    ksym2addr(&expr, &bp)
}

fn parse_bp() -> BpType {
    let cli = Cli::parse();
    cli.bp
}

fn load_ebpf_prog() -> Result<KmemsnoopSkel<'static>> {
    /* We may have to bump RLIMIT_MEMLOCK for libbpf explicitly */
    if cfg!(bump_memlock_rlimit_manually) {
        bump_memlock_rlimit()?;
    }

    let builder = KmemsnoopSkelBuilder::default();
    /* Open BPF application */
    let open_skel = builder.open()?;
    /* Load & verify BPF programs */
    open_skel.load().map_err(anyhow::Error::msg)
}

fn main() -> Result<()> {
    let bp = parse_bp();
    let addr = parse_addr(&bp)?;

    println!("Watchpoint attached on {addr:x}");

    let mut skel = load_ebpf_prog()?;
    let _ = skel.attach()?;

    let mut progs = skel.progs_mut();
    let prog = progs.perf_event_handler();
    /* The link should be hold to represent the lifetime of
     * breakpoint. */
    let _link = attach_breakpoint(addr, bp, prog)?;

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

    println!("Terminate kmemsnoop");
    Ok(())
}
