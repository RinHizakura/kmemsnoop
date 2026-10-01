//! Watchpoint target resolution: turn the user's expression into a
//! kernel address. Everything the CLI needs to know lives in `Target`
//! and `Bus`; symbol lookup and kexpr are adapters behind
//! `Target::resolve()`.

/* Walk and Expr::eval have no caller until the kexpr adapter is built. */
#[cfg_attr(not(feature = "kexpr"), allow(dead_code))]
mod expr;

#[cfg(feature = "kexpr")]
mod kexpr;

use anyhow::Result;

use crate::symbols::{SymKind, Symbols};
use expr::Expr;

/// Kernel bus a kexpr device target lives on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Where the watchpoint expression starts from, holding the expression
/// already parsed for that kind of Target.
#[derive(Debug, PartialEq)]
#[cfg_attr(not(feature = "kexpr"), allow(dead_code))]
pub enum Target {
    /// A `0x` address in the kernel.
    Kaddr(usize),
    /// A kernel symbol, looked up through `Symbols`.
    Ksym { name: String, kind: SymKind },
    /// `struct task_struct` of the given pid.
    Task { pid: u64, expr: Expr },
    /// The device with the given name on `Bus`.
    BusDev { bus: Bus, name: String, expr: Expr },
}

impl Target {
    /// Only a 0x prefix means address; anything else is a symbol, unchecked
    /// because kallsyms names carry suffixes like `.cold` or `.isra.0`.
    /// `execute` tells which symbol namespace the name lives in.
    pub fn kernel(expr: &str, execute: bool) -> Result<Target> {
        if expr.starts_with("0x") {
            Ok(Target::Kaddr(hexstr2int(expr)?))
        } else {
            Ok(Target::Ksym {
                name: expr.to_string(),
                kind: if execute {
                    SymKind::Func
                } else {
                    SymKind::Data
                },
            })
        }
    }

    pub fn task(pid: u64, expr: &str) -> Result<Target> {
        Ok(Target::Task {
            pid,
            expr: Expr::parse(expr)?,
        })
    }

    pub fn busdev(bus: Bus, name: &str, expr: &str) -> Result<Target> {
        Ok(Target::BusDev {
            bus,
            name: name.to_string(),
            expr: Expr::parse(expr)?,
        })
    }

    pub fn resolve(&self, syms: &Symbols) -> Result<usize> {
        match self {
            Target::Kaddr(addr) => Ok(*addr),
            Target::Ksym { name, kind } => syms.addr(name, *kind),
            #[cfg(feature = "kexpr")]
            Target::Task { pid, expr } => kexpr::task(*pid, expr),
            #[cfg(feature = "kexpr")]
            Target::BusDev { bus, name, expr } => kexpr::busdev(*bus, name, expr),
            #[cfg(not(feature = "kexpr"))]
            Target::Task { .. } | Target::BusDev { .. } => {
                Err(anyhow::anyhow!("kexpr is not configured"))
            }
        }
    }
}

fn hexstr2int(hex: &str) -> Result<usize> {
    Ok(usize::from_str_radix(hex.trim_start_matches("0x"), 16)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_target_address_needs_0x_prefix() -> Result<()> {
        assert_eq!(
            0x1234,
            Target::kernel("0x1234", false)?.resolve(&Symbols::new(None))?
        );
        /* "cad" is a symbol name, never the address 0xcad. */
        assert_eq!(
            Target::Ksym {
                name: "cad".into(),
                kind: SymKind::Data,
            },
            Target::kernel("cad", false)?
        );
        /* Execute watchpoints look up functions. */
        assert_eq!(
            Target::Ksym {
                name: "ksys_sync".into(),
                kind: SymKind::Func,
            },
            Target::kernel("ksys_sync", true)?
        );
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
        let syms = Symbols::new(None);
        let expect = exec!(["--pid", "1", "&on_rq"]);
        assert_eq!(expect, Target::task(1, "&on_rq")?.resolve(&syms)?);
        let expect = exec!(["--pid", "1", "parent"]);
        assert_eq!(expect, Target::task(1, "parent")?.resolve(&syms)?);

        Ok(())
    }

    fn check_busdev(bus: Bus, opt: &str, expr: &str) -> Result<()> {
        let syms = Symbols::new(None);
        let (bus_name, _) = bus.table();
        let devices = fs::read_dir(format!("/sys/bus/{bus_name}/devices/")).unwrap();
        for dev in devices {
            let dev_name = dev.unwrap().file_name();
            let dev = dev_name.to_str().unwrap();
            let expect = exec!([opt, dev, expr]);
            let target = Target::busdev(bus, dev, expr)?;
            assert_eq!(expect, target.resolve(&syms)?);
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
