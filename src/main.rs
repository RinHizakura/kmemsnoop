use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::bump_memlock_rlimit::*;
use crate::msg::Decoder;
use crate::perf::attach_breakpoint;
use crate::target::{Bus, SymKind, Target};

use libbpf_rs::skel::*;
use libbpf_rs::RingBufferBuilder;

use anyhow::{anyhow, Result};
use clap::Parser;

use perf_event_open_sys::bindings::{
    HW_BREAKPOINT_R, HW_BREAKPOINT_RW, HW_BREAKPOINT_W, HW_BREAKPOINT_X,
};

mod bump_memlock_rlimit;
mod msg;
mod perf;
mod target;
mod utils;

#[path = "../bpf/.output/kmemsnoop.skel.rs"]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod kmemsnoop;
use kmemsnoop::*;

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

/* The options in group "target" are mutually exclusive */
#[derive(Parser)]
struct Cli {
    #[arg(value_enum, help = "type of the watchpoint")]
    bp: BpType,

    #[arg(help = "expression of watchpoint(kernel symbol or 0x address by default)")]
    expr: String,

    #[arg(
        short,
        long,
        group = "target",
        help = "vmlinux path of running kernel(need nokaslr)"
    )]
    vmlinux: Option<PathBuf>,

    #[arg(
        long,
        group = "target",
        help = "kexpr: use 'struct task_struct' from pid"
    )]
    pid_task: Option<u64>,

    #[arg(
        long,
        group = "target",
        help = "kexpr: 'struct pci_dev' from the device name"
    )]
    pci_dev: Option<String>,

    #[arg(
        long,
        group = "target",
        help = "kexpr: 'struct usb_device' from the device name"
    )]
    usb_dev: Option<String>,

    #[arg(
        long,
        group = "target",
        help = "kexpr: 'struct platform_device' from the device name"
    )]
    plat_dev: Option<String>,
}

impl From<&Cli> for Target {
    fn from(cli: &Cli) -> Self {
        if let Some(pid) = cli.pid_task {
            return Target::Task(pid);
        }
        if let Some(dev) = &cli.pci_dev {
            return Target::BusDev(Bus::Pci, dev.clone());
        }
        if let Some(dev) = &cli.usb_dev {
            return Target::BusDev(Bus::Usb, dev.clone());
        }
        if let Some(dev) = &cli.plat_dev {
            return Target::BusDev(Bus::Platform, dev.clone());
        }

        Target::Kernel {
            vmlinux: cli.vmlinux.clone(),
        }
    }
}

fn parse_bp(cli: &Cli) -> (u32, u64) {
    let bp = &cli.bp;

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

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() -> Result<()> {
    let cli = Cli::parse();

    if sudo::check() != sudo::RunningAs::Root {
        println!("(kmemsnoop: need to escalate for root permission)");
        sudo::escalate_if_needed().map_err(|e| anyhow!("Failed to escalate to root: {e}"))?;
    }

    let (bp_type, bp_len) = parse_bp(&cli);
    let sym_kind = if bp_type == HW_BREAKPOINT_X {
        SymKind::Func
    } else {
        SymKind::Data
    };
    let addr = Target::from(&cli).resolve(&cli.expr, sym_kind)?;

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
    let _links = attach_breakpoint(addr, bp_type, bp_len, &mut prog)?;

    /* Declared before the builder: the callback borrows it for as long
     * as the ring buffer lives. */
    let decoder = Decoder::new();
    let mut builder = RingBufferBuilder::new();
    let msg_ringbuf = skel.maps.msg_ringbuf;
    builder.add(&msg_ringbuf, |bytes| {
        match decoder.decode(bytes) {
            Ok(msg) => println!("{msg}"),
            Err(e) => eprintln!("kmemsnoop: {e}"),
        }
        0
    })?;
    let msg = builder.build()?;

    ctrlc::set_handler(|| {
        RUNNING.store(false, Ordering::SeqCst);
    })?;

    while RUNNING.load(Ordering::SeqCst) {
        match msg.poll(Duration::from_millis(100)) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => {}
            Err(e) => return Err(anyhow::Error::msg(e)),
        }
    }

    println!("Terminate kmemsnoop");
    Ok(())
}
