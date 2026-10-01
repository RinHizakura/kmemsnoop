//! Where kernel symbols come from: /proc/kallsyms by default, or the
//! vmlinux of the running kernel when given (DWARF, so stack frames get
//! source lines; needs nokaslr because ELF addresses are taken as the
//! runtime ones). Target resolves names and Msg symbolizes stacks through
//! the same `Symbols`, so the choice is made once.

use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use blazesym::inspect::{self, Inspector};
use blazesym::symbolize::{self, Input, Source, Symbolized, Symbolizer};
use blazesym::SymType;

/// Kind of kernel symbol to look up: execute watchpoints sit on
/// functions, the others on data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SymKind {
    Func,
    Data,
}

impl SymKind {
    fn describe(self) -> &'static str {
        match self {
            SymKind::Func => "function",
            SymKind::Data => "data symbol",
        }
    }
}

pub struct Symbols {
    symbolizer: Symbolizer,
    src: Source<'static>,
}

impl Symbols {
    pub fn new(vmlinux: Option<PathBuf>) -> Symbols {
        let src = match vmlinux {
            Some(path) => Source::Elf(symbolize::Elf::new(path)),
            None => Source::Kernel(symbolize::Kernel::default()),
        };
        Symbols {
            symbolizer: Symbolizer::new(),
            src,
        }
    }

    /// Address of the symbol `name` among symbols of the given kind.
    pub fn addr(&self, name: &str, kind: SymKind) -> Result<usize> {
        match &self.src {
            Source::Elf(elf) => vmlinux_addr(&elf.path, name, kind),
            _ => {
                let f = File::open("/proc/kallsyms")
                    .context("/proc/kallsyms is needed to resolve symbols")?;
                kallsyms_addr(BufReader::new(f), name, kind)?
                    .ok_or_else(|| anyhow!("no {} {name:?} in kallsyms", kind.describe()))
            }
        }
    }

    /// One Frame per return address, each followed by the calls inlined
    /// into it.
    pub fn frames(&self, addrs: &[u64]) -> Result<Vec<Frame>> {
        /* An ELF source only takes virtual offsets; under nokaslr those are
         * the kernel addresses themselves. */
        let input = match self.src {
            Source::Elf(_) => Input::VirtOffset(addrs),
            _ => Input::AbsAddr(addrs),
        };
        let syms = self.symbolizer.symbolize(&self.src, input)?;

        let mut frames = Vec::new();
        for (input_addr, sym) in addrs.iter().copied().zip(syms) {
            match sym {
                Symbolized::Sym(symbolize::Sym {
                    name,
                    addr,
                    offset,
                    code_info,
                    inlined,
                    ..
                }) => {
                    frames.push(Frame::Sym {
                        input_addr,
                        name: name.into_owned(),
                        addr,
                        offset,
                        code_info: code_info.as_ref().map(CodeInfo::from),
                    });
                    for f in inlined.iter() {
                        frames.push(Frame::Inlined {
                            name: f.name.to_string(),
                            code_info: f.code_info.as_ref().map(CodeInfo::from),
                        });
                    }
                }
                Symbolized::Unknown(..) => frames.push(Frame::Unknown { input_addr }),
            }
        }
        Ok(frames)
    }
}

/// ELF symbols come typed, so a name shared by a function and a variable
/// is told apart by `kind`; more than one match of that kind is an error.
fn vmlinux_addr(vmlinux: &Path, name: &str, kind: SymKind) -> Result<usize> {
    let src = inspect::Source::Elf(inspect::Elf::new(vmlinux));
    let inspector = Inspector::new();
    let results = inspector.lookup(&src, &[name])?;
    let want = match kind {
        SymKind::Func => SymType::Function,
        SymKind::Data => SymType::Variable,
    };
    let addrs: Vec<u64> = results
        .into_iter()
        .flatten()
        .filter(|sym| sym.sym_type == want)
        .map(|sym| sym.addr)
        .collect();
    match addrs[..] {
        [addr] => Ok(addr as usize),
        [] => bail!("no {} {name:?} in {}", kind.describe(), vmlinux.display()),
        _ => bail!(
            "{name:?} is ambiguous in {} ({} matches)",
            vmlinux.display(),
            addrs.len()
        ),
    }
}

/// One pass over kallsyms-format text (`addr kind name [module]` per line),
/// stopping at the first match: reading the file dominates, so no table is
/// built for a single lookup. `t`/`T` and the weak `w`/`W` (nm marks weak
/// objects `v`/`V` instead) are functions, everything else data; address 0
/// (kptr_restrict) and unparsable lines are skipped.
fn kallsyms_addr(reader: impl BufRead, sym: &str, kind: SymKind) -> Result<Option<usize>> {
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

/// One output line of a stack; inlined frames follow their parent.
pub enum Frame {
    Sym {
        input_addr: u64,
        name: String,
        addr: u64,
        offset: usize,
        code_info: Option<CodeInfo>,
    },
    Inlined {
        name: String,
        code_info: Option<CodeInfo>,
    },
    Unknown {
        input_addr: u64,
    },
}

pub struct CodeInfo {
    pub path: PathBuf,
    pub line: Option<u32>,
    pub column: Option<u16>,
}

impl From<&symbolize::CodeInfo<'_>> for CodeInfo {
    fn from(ci: &symbolize::CodeInfo<'_>) -> Self {
        CodeInfo {
            path: ci.to_path().into_owned(),
            line: ci.line,
            column: ci.column,
        }
    }
}

const ADDR_WIDTH: usize = 16;

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Frame::Sym {
                input_addr,
                name,
                addr,
                offset,
                code_info,
            } => {
                write!(
                    f,
                    "\t{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}",
                    width = ADDR_WIDTH
                )?;
                if let Some(ci) = code_info {
                    write!(f, " {ci}")?;
                }
                Ok(())
            }
            Frame::Inlined { name, code_info } => {
                write!(f, "\t{:width$}  {name}", " ", width = ADDR_WIDTH)?;
                if let Some(ci) = code_info {
                    write!(f, " @ {ci}")?;
                }
                write!(f, " [inlined]")
            }
            Frame::Unknown { input_addr } => {
                write!(
                    f,
                    "\t{input_addr:#0width$x}: <no-symbol>",
                    width = ADDR_WIDTH
                )
            }
        }
    }
}

impl fmt::Display for CodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())?;
        match (self.line, self.column) {
            (Some(line), Some(col)) => write!(f, ":{line}:{col}"),
            (Some(line), None) => write!(f, ":{line}"),
            (None, _) => Ok(()),
        }
    }
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
        kallsyms_addr(KALLSYMS.as_bytes(), sym, kind)
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

    fn code_info(line: Option<u32>, column: Option<u16>) -> CodeInfo {
        CodeInfo {
            path: "fs/sync.c".into(),
            line,
            column,
        }
    }

    #[test]
    fn frame_renders_sym_inlined_and_unknown() {
        let sym = Frame::Sym {
            input_addr: 0xffffffff816bfc8e,
            name: "__do_sys_sync".into(),
            addr: 0xffffffff816bfc80,
            offset: 0xe,
            code_info: None,
        };
        assert_eq!(
            sym.to_string(),
            "\t0xffffffff816bfc8e: __do_sys_sync @ 0xffffffff816bfc80+0xe"
        );

        let sym = Frame::Sym {
            input_addr: 0x1234,
            name: "f".into(),
            addr: 0x1230,
            offset: 4,
            code_info: Some(code_info(Some(120), Some(3))),
        };
        assert_eq!(
            sym.to_string(),
            "\t0x00000000001234: f @ 0x1230+0x4 fs/sync.c:120:3"
        );

        let inlined = Frame::Inlined {
            name: "g".into(),
            code_info: None,
        };
        assert_eq!(inlined.to_string(), "\t                  g [inlined]");

        let inlined = Frame::Inlined {
            name: "g".into(),
            code_info: Some(code_info(Some(7), None)),
        };
        assert_eq!(
            inlined.to_string(),
            "\t                  g @ fs/sync.c:7 [inlined]"
        );

        let unknown = Frame::Unknown { input_addr: 0x1234 };
        assert_eq!(unknown.to_string(), "\t0x00000000001234: <no-symbol>");
    }

    #[test]
    fn code_info_drops_missing_line_and_column() {
        assert_eq!(code_info(Some(1), Some(2)).to_string(), "fs/sync.c:1:2");
        assert_eq!(code_info(Some(1), None).to_string(), "fs/sync.c:1");
        assert_eq!(code_info(None, Some(2)).to_string(), "fs/sync.c");
    }
}
