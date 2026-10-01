use std::fs::File;
use std::io::{BufRead, BufReader};

use anyhow::{Context, Result};

use super::SymKind;

/// Address of `sym` in /proc/kallsyms, among symbols of the given kind.
pub fn find_ksym(sym: &str, kind: SymKind) -> Result<Option<usize>> {
    let f = File::open("/proc/kallsyms").context("/proc/kallsyms is needed to resolve symbols")?;
    find_ksym_in(BufReader::new(f), sym, kind)
}

/// One pass over kallsyms-format text (`addr kind name [module]` per line),
/// stopping at the first match: reading the file dominates, so no table is
/// built for a single lookup. `t`/`T` and the weak `w`/`W` (nm marks weak
/// objects `v`/`V` instead) are functions, everything else data; address 0
/// (kptr_restrict) and unparsable lines are skipped.
pub fn find_ksym_in(reader: impl BufRead, sym: &str, kind: SymKind) -> Result<Option<usize>> {
    for line in reader.lines() {
        let line = line?;
        let mut tokens = line.split_whitespace();
        let (Some(addr), Some(typ), Some(name)) = (tokens.next(), tokens.next(), tokens.next())
        else {
            continue;
        };
        if name != sym {
            continue;
        }

        let line_kind = match typ {
            "t" | "T" | "w" | "W" => SymKind::Func,
            _ => SymKind::Data,
        };
        if line_kind != kind {
            continue;
        }

        match usize::from_str_radix(addr, 16) {
            Ok(0) | Err(_) => continue,
            Ok(addr) => return Ok(Some(addr)),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KALLSYMS: &str = "\
0000000000000000 A fixed_percpu_data
ffffffff81000000 T _stext
ffffffff81000100 t local_func
ffffffff81000180 W weak_func
ffffffff81000190 V weak_data
ffffffff82000000 D same_name
ffffffff81000200 T same_name
this line is not kallsyms
ffffffff83000000 B nr_threads	[mod]
";

    fn find(sym: &str, kind: SymKind) -> Result<Option<usize>> {
        find_ksym_in(KALLSYMS.as_bytes(), sym, kind)
    }

    #[test]
    fn text_and_weak_are_functions_everything_else_is_data() -> Result<()> {
        assert_eq!(find("_stext", SymKind::Func)?, Some(0xffffffff81000000));
        assert_eq!(find("local_func", SymKind::Func)?, Some(0xffffffff81000100));
        assert_eq!(find("weak_func", SymKind::Func)?, Some(0xffffffff81000180));
        assert_eq!(find("weak_data", SymKind::Data)?, Some(0xffffffff81000190));
        assert_eq!(find("weak_func", SymKind::Data)?, None);
        assert_eq!(find("nr_threads", SymKind::Data)?, Some(0xffffffff83000000));
        assert_eq!(find("nr_threads", SymKind::Func)?, None);
        assert_eq!(find("_stext", SymKind::Data)?, None);
        Ok(())
    }

    #[test]
    fn same_name_is_told_apart_by_kind() -> Result<()> {
        assert_eq!(find("same_name", SymKind::Data)?, Some(0xffffffff82000000));
        assert_eq!(find("same_name", SymKind::Func)?, Some(0xffffffff81000200));
        Ok(())
    }

    #[test]
    fn address_zero_and_bad_lines_are_skipped() -> Result<()> {
        assert_eq!(find("fixed_percpu_data", SymKind::Data)?, None);
        assert_eq!(find("missing", SymKind::Data)?, None);
        /* Parsing continued past the bad line. */
        assert!(find("nr_threads", SymKind::Data)?.is_some());
        Ok(())
    }
}
