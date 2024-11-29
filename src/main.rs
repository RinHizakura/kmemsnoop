use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::bump_memlock_rlimit::*;
use crate::kexpr::*;
use crate::ksym::{KSymResolver, KSYM_FUNC};
use crate::msg::*;
use crate::perf::attach_breakpoint;
use crate::utils::hexstr2int;

use ksym::KSYM_DATA;
use libbpf_rs::skel::*;
use libbpf_rs::RingBufferBuilder;

use anyhow::{anyhow, Result};
use clap::Parser;

use perf_event_open_sys::bindings::{
    HW_BREAKPOINT_R, HW_BREAKPOINT_RW, HW_BREAKPOINT_W, HW_BREAKPOINT_X,
};

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

#[derive(clap::ValueEnum, Clone)]
enum BpType {
    R1,
    W1,
    RW1,
    X1,
    R2,
    W2,
    RW2,
    X2,
    R4,
    W4,
    RW4,
    X4,
    R8,
    W8,
    RW8,
    X8,
}

fn ksym2addr(sym: &str, bp: u32) -> Result<usize> {
    let kresolver = KSymResolver::new();

    let sym_typ = match bp {
        HW_BREAKPOINT_X => KSYM_FUNC,
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

    #[arg(long, help = "kexpr: use 'struct task_struct' from pid")]
    pid_task: Option<u64>,

    #[arg(long, help = "kexpr: 'struct pci_dev' from the device name")]
    pci_dev: Option<String>,

    #[arg(long, help = "kexpr: 'struct usb_device' from the device name")]
    usb_dev: Option<String>,

    #[arg(long, help = "kexpr: 'struct platform_device' from the device name")]
    plat_dev: Option<String>,
}

fn parse_addr(bp_type: u32) -> Result<usize> {
    let cli = Cli::parse();
    let expr = cli.expr;
    let pid_task = cli.pid_task;
    let pci_dev = cli.pci_dev;
    let usb_dev = cli.usb_dev;
    let plat_dev = cli.plat_dev;
    let vmlinux = cli.vmlinux;

    /* Use kexpr if special option is specified.
     * FIXME: If several kexpr option is specified, kmemsnoop
     * only takes one of it by order. Do we want to avoid this? */
    if let Some(pid) = pid_task {
        return task_kexpr2addr(pid, &expr);
    }

    if let Some(pci_dev) = pci_dev {
        return pcidev_kexpr2addr(&pci_dev, &expr);
    }

    if let Some(usb_dev) = usb_dev {
        return usbdev_kexpr2addr(&usb_dev, &expr);
    }

    if let Some(plat_dev) = plat_dev {
        return platdev_kexpr2addr(&plat_dev, &expr);
    }

    if let Ok(addr) = hexstr2int(&expr) {
        return Ok(addr);
    }

    /* Use vmlinux to know the address by symbol */
    if let Some(vmlinux) = vmlinux {
        return vmlinux2addr(&expr, &vmlinux);
    }

    ksym2addr(&expr, bp_type)
}

fn parse_bp() -> (u32, u64) {
    let cli = Cli::parse();
    let bp = cli.bp;

    let bp_len = match bp {
        BpType::R1 | BpType::W1 | BpType::RW1 | BpType::X1 => 1,
        BpType::R2 | BpType::W2 | BpType::RW2 | BpType::X2 => 2,
        BpType::R4 | BpType::W4 | BpType::RW4 | BpType::X4 => 4,
        BpType::R8 | BpType::W8 | BpType::RW8 | BpType::X8 => 8,
    };
    let bp_type = match bp {
        BpType::X1 | BpType::X2 | BpType::X4 | BpType::X8 => HW_BREAKPOINT_X,
        BpType::R1 | BpType::R2 | BpType::R4 | BpType::R8 => HW_BREAKPOINT_R,
        BpType::W1 | BpType::W2 | BpType::W4 | BpType::W8 => HW_BREAKPOINT_W,
        BpType::RW1 | BpType::RW2 | BpType::RW4 | BpType::RW8 => HW_BREAKPOINT_RW,
    };

    (bp_type, bp_len)
}

fn main() -> Result<()> {
    let (bp_type, bp_len) = parse_bp();
    let addr = parse_addr(bp_type)?;

    println!("Watchpoint attached on {addr:x}");

    /* We may have to bump RLIMIT_MEMLOCK for libbpf explicitly */
    if cfg!(bump_memlock_rlimit_manually) {
        bump_memlock_rlimit()?;
    }

    let mut open_object = MaybeUninit::uninit();
    let builder = KmemsnoopSkelBuilder::default();
    /* Open BPF application */
    let open_skel = builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.bp_type = bp_type;
    open_skel.maps.rodata_data.bp_len = bp_len;

    /* Load & verify BPF programs */
    let mut skel = open_skel.load()?;
    let _ = skel.attach()?;

    let progs = skel.progs;
    let mut prog = progs.perf_event_handler;

    /* The link should be hold to represent the lifetime of
     * breakpoint. */
    let _link = attach_breakpoint(addr, bp_type, bp_len, &mut prog)?;

    let mut builder = RingBufferBuilder::new();
    let msg_ringbuf = skel.maps.msg_ringbuf;
    builder.add(&msg_ringbuf, msg_handler)?;
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
