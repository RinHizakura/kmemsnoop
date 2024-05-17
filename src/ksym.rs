use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub const KSYM_INVALID: u8 = 0;
pub const KSYM_FUNC: u8 = 1;
pub const KSYM_DATA: u8 = 2;

#[derive(Debug)]
struct Ksym {
    name: String,
    kind: u8,
    addr: usize,
}

impl Ksym {
    fn by_name_cmp(&self, other: &Ksym) -> Ordering {
        if self.kind != other.kind {
            return self.kind.cmp(&other.kind);
        }

        self.name.cmp(&other.name)
    }
}

/* FIXME: This is a naive symbol resolver which is created from
 * /proc/kallsyms. We can optimize it to parse the interesting
 * information quickly. */
pub struct KSymResolver {
    syms: Vec<Ksym>,
}

impl KSymResolver {
    pub fn new() -> Self {
        let f = File::open("/proc/kallsyms").expect("/proc/kallsyms is needed for KSymResolver");
        let mut reader = BufReader::new(f);

        let mut line = String::new();
        let mut syms = Vec::new();

        loop {
            line.clear();
            let sz = reader.read_line(&mut line).unwrap();
            if sz == 0 {
                break;
            }

            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.len() < 3 {
                break;
            }

            let (addr, kind, func) = (tokens[0], tokens[1], tokens[2]);
            let name = func.to_owned();
            let addr = usize::from_str_radix(addr, 16).unwrap();
            if addr == 0 {
                continue;
            }
            let kind = if kind == "t" || kind == "T" {
                KSYM_FUNC
            } else {
                KSYM_DATA
            };
            let sym = Ksym { name, kind, addr };
            syms.push(sym);
        }

        syms.sort_by(|a, b| a.by_name_cmp(&b));

        Self { syms }
    }

    pub fn find_ksym(&self, sym: &str, kind: u8) -> Option<usize> {
        let sym = Ksym {
            name: sym.to_owned(),
            kind: kind,
            addr: 0,
        };
        let symidx = self.syms.binary_search_by(|a| a.by_name_cmp(&sym));

        if let Ok(idx) = symidx {
            return Some(self.syms[idx].addr);
        }

        None
    }
}
