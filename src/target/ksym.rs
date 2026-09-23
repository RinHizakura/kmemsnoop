use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufRead, BufReader};

use anyhow::{Context, Result};

use super::SymKind;

#[derive(Debug)]
struct Ksym {
    name: String,
    kind: SymKind,
    addr: usize,
}

impl Ksym {
    fn by_name_cmp(&self, other: &Ksym) -> Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.name.cmp(&other.name))
    }
}

/* FIXME: This is a naive symbol resolver which is created from
 * /proc/kallsyms. We can optimize it to parse the interesting
 * information quickly. */
pub struct KSymResolver {
    syms: Vec<Ksym>,
}

impl KSymResolver {
    pub fn new() -> Result<Self> {
        let f =
            File::open("/proc/kallsyms").context("/proc/kallsyms is needed for KSymResolver")?;
        let reader = BufReader::new(f);

        let mut syms = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let mut tokens = line.split_whitespace();
            let (Some(addr), Some(kind), Some(name)) =
                (tokens.next(), tokens.next(), tokens.next())
            else {
                continue;
            };

            let Ok(addr) = usize::from_str_radix(addr, 16) else {
                continue;
            };
            if addr == 0 {
                continue;
            }

            let kind = if kind == "t" || kind == "T" {
                SymKind::Func
            } else {
                SymKind::Data
            };
            syms.push(Ksym {
                name: name.to_owned(),
                kind,
                addr,
            });
        }

        syms.sort_by(|a, b| a.by_name_cmp(b));

        Ok(Self { syms })
    }

    pub fn find_ksym(&self, sym: &str, kind: SymKind) -> Option<usize> {
        let probe = Ksym {
            name: sym.to_owned(),
            kind,
            addr: 0,
        };

        self.syms
            .binary_search_by(|a| a.by_name_cmp(&probe))
            .ok()
            .map(|idx| self.syms[idx].addr)
    }
}
