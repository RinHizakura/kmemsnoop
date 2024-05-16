use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

/* FIXME: This is a naive symbol resolver which is created from
 * /proc/kallsyms. We can optimize it to parse the interesting
 * information quickly. */
pub struct KSymResolver {
    syms: HashMap<String, usize>,
}

impl KSymResolver {
    pub fn new() -> Self {
        let f = File::open("/proc/kallsyms").expect("/proc/kallsyms is needed for KSymResolver");
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        let mut syms = HashMap::new();

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
            let (addr, _symbol, func) = (tokens[0], tokens[1], tokens[2]);
            let addr = usize::from_str_radix(addr, 16).unwrap();
            if addr == 0 {
                continue;
            }
            let name = String::from(func);
            syms.insert(name, addr);
        }

        Self { syms }
    }

    pub fn find_ksym(&self, sym: &str) -> Option<usize> {
        self.syms.get(sym).copied()
    }
}
