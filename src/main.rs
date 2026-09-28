use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::msg::Decoder;
use crate::target::{Bus, Target};
use crate::watchpoint::{Access, Bp, Watchpoint};

use anyhow::{anyhow, Result};
use clap::Parser;

mod msg;
mod target;
mod watchpoint;

#[path = "../bpf/.output/kmemsnoop.skel.rs"]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod kmemsnoop;

/* The options in group "target" are mutually exclusive: clap rejects
 * the command line if more than one of them is given. */
#[derive(Parser)]
struct Cli {
    #[arg(help = "type of the watchpoint: r, w, rw or x followed by 1, 2, 4 or 8, e.g. rw4")]
    bp: Bp,

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

impl TryFrom<&Cli> for Target {
    type Error = anyhow::Error;

    fn try_from(cli: &Cli) -> Result<Self> {
        let expr = &cli.expr;
        if let Some(pid) = cli.pid_task {
            return Target::task(pid, expr);
        }
        if let Some(dev) = &cli.pci_dev {
            return Target::busdev(Bus::Pci, dev, expr);
        }
        if let Some(dev) = &cli.usb_dev {
            return Target::busdev(Bus::Usb, dev, expr);
        }
        if let Some(dev) = &cli.plat_dev {
            return Target::busdev(Bus::Platform, dev, expr);
        }
        Target::kernel(cli.vmlinux.clone(), expr, cli.bp.access == Access::X)
    }
}

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() -> Result<()> {
    let cli = Cli::parse();

    if sudo::check() != sudo::RunningAs::Root {
        println!("(kmemsnoop: need to escalate for root permission)");
        sudo::escalate_if_needed().map_err(|e| anyhow!("Failed to escalate to root: {e}"))?;
    }

    let addr = Target::try_from(&cli)?.resolve()?;
    let wp = Watchpoint::attach(addr, cli.bp)?;
    println!("Watchpoint attached on {addr:x}");

    ctrlc::set_handler(|| {
        RUNNING.store(false, Ordering::SeqCst);
    })?;

    let decoder = Decoder::new();
    watchpoint::poll(&[wp], &RUNNING, |bytes| match decoder.decode(bytes) {
        Ok(msg) => println!("{msg}"),
        Err(e) => eprintln!("kmemsnoop: {e}"),
    })?;

    println!("Terminate kmemsnoop");
    Ok(())
}
