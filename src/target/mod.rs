//! Watchpoint target resolution: turn the user's expression into a
//! kernel address. Everything the CLI needs to know lives in `Target`,
//! `Bus` and `SymKind`; kallsyms, vmlinux and kexpr are adapters behind
//! `Target::resolve()`.

mod ksym;

#[cfg(feature = "kexpr")]
mod kexpr;

#[cfg(not(feature = "kexpr"))]
mod kexpr {
    use super::Bus;
    use anyhow::{anyhow, Result};

    pub fn task(_pid: u64, _expr: &str) -> Result<usize> {
        Err(anyhow!("kexpr is not configured"))
    }

    pub fn busdev(_bus: Bus, _dev_name: &str, _expr: &str) -> Result<usize> {
        Err(anyhow!("kexpr is not configured"))
    }
}

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use blazesym::inspect::{self, Inspector};

use crate::utils::hexstr2int;

/// Kind of kernel symbol to look up in kallsyms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SymKind {
    Func,
    Data,
}

/// Kernel bus a kexpr device target lives on.
#[derive(Clone, Copy, Debug)]
pub enum Bus {
    Pci,
    Usb,
    Platform,
}

impl Bus {
    /// (bus name under /sys/bus, struct that embeds `struct device` as `dev`)
    #[cfg_attr(not(feature = "kexpr"), allow(dead_code))]
    fn table(self) -> (&'static str, &'static str) {
        match self {
            Bus::Pci => ("pci", "struct pci_dev"),
            Bus::Usb => ("usb", "struct usb_device"),
            Bus::Platform => ("platform", "struct platform_device"),
        }
    }
}

/// Where the watchpoint expression starts from.
#[derive(Debug)]
pub enum Target {
    /// The kernel itself: `expr` is a `0x` address or a symbol name.
    Kernel { vmlinux: Option<PathBuf> },
    /// `struct task_struct` of the given pid: `expr` is a kexpr.
    Task(u64),
    /// The device with the given name on `Bus`: `expr` is a kexpr.
    BusDev(Bus, String),
}

impl Target {
    pub fn resolve(&self, expr: &str, kind: SymKind) -> Result<usize> {
        match self {
            Target::Task(pid) => kexpr::task(*pid, expr),
            Target::BusDev(bus, name) => kexpr::busdev(*bus, name, expr),
            Target::Kernel { vmlinux } => {
                /* Only a 0x prefix means address; anything else is a symbol. */
                if expr.starts_with("0x") {
                    return hexstr2int(expr);
                }

                match vmlinux {
                    Some(path) => vmlinux2addr(expr, path),
                    None => ksym::KSymResolver::new()?
                        .find_ksym(expr, kind)
                        .ok_or_else(|| anyhow!("Failed to get address of symbol {expr}")),
                }
            }
        }
    }
}

fn vmlinux2addr(sym: &str, vmlinux: &Path) -> Result<usize> {
    let src = inspect::Source::Elf(inspect::Elf::new(vmlinux));
    let inspector = Inspector::new();
    let results = inspector.lookup(&src, &[sym])?;

    let results = results.into_iter().flatten().collect::<Vec<_>>();

    if results.len() != 1 {
        return Err(anyhow!(format!("Failed to get address of symbol {sym}")));
    }

    Ok(results[0].addr as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_target_address_needs_0x_prefix() -> Result<()> {
        let kernel = Target::Kernel { vmlinux: None };
        assert_eq!(0x1234, kernel.resolve("0x1234", SymKind::Data)?);
        /* "cad" is a symbol name, never the address 0xcad. */
        assert_ne!(Some(0xcad), kernel.resolve("cad", SymKind::Data).ok());
        Ok(())
    }
}

#[cfg(all(test, feature = "kexpr"))]
mod kexpr_tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    macro_rules! exec {
        ($args:expr) => {
            hexstr2int(
                &String::from_utf8(
                    Command::new("./tests/kexpr.py")
                        .args($args)
                        .output()
                        .expect("Fail to execute kexpr")
                        .stdout,
                )
                .expect("Invalid output from kexpr.py")
                .trim()
                .to_string(),
            )
            .expect("Fail to convert kexpr output to usize")
        };
    }

    #[test]
    fn test_task_struct_kexpr() -> Result<()> {
        let task = Target::Task(1);
        let expect = exec!(["--pid", "1", "&on_rq"]);
        assert_eq!(expect, task.resolve("&on_rq", SymKind::Data)?);
        let expect = exec!(["--pid", "1", "parent"]);
        assert_eq!(expect, task.resolve("parent", SymKind::Data)?);

        Ok(())
    }

    fn check_busdev(bus: Bus, opt: &str, expr: &str) -> Result<()> {
        let (bus_name, _) = bus.table();
        let devices = fs::read_dir(format!("/sys/bus/{bus_name}/devices/")).unwrap();
        for dev in devices {
            let dev_name = dev.unwrap().file_name();
            let dev = dev_name.to_str().unwrap();
            let expect = exec!([opt, dev, expr]);
            let target = Target::BusDev(bus, dev.to_string());
            assert_eq!(expect, target.resolve(expr, SymKind::Data)?);
        }

        Ok(())
    }

    #[test]
    fn test_pcidev_kexpr() -> Result<()> {
        check_busdev(Bus::Pci, "--pci_dev", "&subsystem_vendor")
    }

    #[test]
    fn test_usbdev_kexpr() -> Result<()> {
        check_busdev(Bus::Usb, "--usb_dev", "&devaddr")
    }

    #[test]
    fn test_platdev_kexpr() -> Result<()> {
        check_busdev(Bus::Platform, "--plat_dev", "&id")
    }
}
