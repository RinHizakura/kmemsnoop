//! Msg decoding: bytes from the BPF ring buffer in, a `Msg` out.
//! The wire layout comes from the skeleton's BTF-generated types, so
//! `bpf/msg.h` is its only definition.

use std::fmt;
use std::mem::size_of;
use std::path::PathBuf;

use anyhow::{bail, Result};
use blazesym::symbolize::{self, Elf, Input, Kernel, Source, Symbolized, Symbolizer};

use crate::kmemsnoop::types::{data_msg, msg_ent, msg_type, stack_msg};

const MSG_TYPE_STACK: u64 = msg_type::MSG_TYPE_STACK as u64;
const MSG_TYPE_DATA: u64 = msg_type::MSG_TYPE_DATA as u64;
/* perf callchains carry context markers (PERF_CONTEXT_KERNEL = -128, ...)
 * that all sit at or above PERF_CONTEXT_MAX; they are not return addresses.
 * See enum perf_callchain_context in <linux/perf_event.h>. */
const PERF_CONTEXT_MAX: u64 = -4095i64 as u64;

pub struct Msg {
    pub id: u64,
    pub pid: u64,
    pub timestamp_ns: u64,
    pub cmd: String,
    pub body: Body,
}

pub enum Body {
    Stack(Vec<Frame>),
    /// bpf_get_stack() reported a negative errno.
    StackFailed {
        errno: i64,
    },
    Data {
        addr: u64,
        val: u64,
    },
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

pub struct Decoder {
    symbolizer: Symbolizer,
    src: Source<'static>,
}

impl Decoder {
    /// Stack frames are symbolized from `vmlinux` (DWARF, so with source
    /// locations; needs nokaslr) when given, else from /proc/kallsyms.
    pub fn new(vmlinux: Option<PathBuf>) -> Self {
        let src = match vmlinux {
            Some(path) => Source::Elf(Elf::new(path)),
            None => Source::Kernel(Kernel::default()),
        };
        Decoder {
            symbolizer: Symbolizer::new(),
            src,
        }
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<Msg> {
        let (ent, inner) = split::<msg_ent>(bytes)?;

        let body = match ent.r#type {
            MSG_TYPE_STACK => self.stack(inner)?,
            MSG_TYPE_DATA => {
                let (msg, _) = split::<data_msg>(inner)?;
                Body::Data {
                    addr: msg.addr,
                    val: msg.val,
                }
            }
            typ => bail!("unknown message type {typ}"),
        };

        Ok(Msg {
            id: ent.id,
            pid: ent.pid,
            timestamp_ns: ent.timestamp,
            cmd: format_cmd(&ent.cmd),
            body,
        })
    }

    fn stack(&self, inner: &[u8]) -> Result<Body> {
        let (msg, _) = split::<stack_msg>(inner)?;

        let kstack_sz = msg.kstack_sz as i64;
        if kstack_sz < 0 {
            return Ok(Body::StackFailed { errno: -kstack_sz });
        }
        let depth = (kstack_sz as usize / size_of::<u64>()).min(msg.kstack.len());
        let addrs: Vec<u64> = msg.kstack[..depth]
            .iter()
            .copied()
            .filter(|&a| a < PERF_CONTEXT_MAX)
            .collect();
        if addrs.is_empty() {
            return Ok(Body::Stack(Vec::new()));
        }

        /* An ELF source only takes virtual offsets; under nokaslr those are
         * the kernel addresses themselves. */
        let input = match self.src {
            Source::Elf(_) => Input::VirtOffset(addrs.as_slice()),
            _ => Input::AbsAddr(addrs.as_slice()),
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

        Ok(Body::Stack(frames))
    }
}

/// Copy the head of `bytes` out as a `T` and return the remainder.
fn split<T: Copy>(bytes: &[u8]) -> Result<(T, &[u8])> {
    let n = size_of::<T>();
    if bytes.len() < n {
        bail!("message too short: {} < {n} bytes", bytes.len());
    }
    /* SAFETY: T is a #[repr(C)] plain-data struct generated from BTF, every
     * bit pattern is valid, and the length was just checked. Unaligned so
     * decode() works on any slice, not only ring buffer records. */
    let t = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) };
    Ok((t, &bytes[n..]))
}

fn format_cmd(buf: &[i8]) -> String {
    let end = buf.iter().position(|&c| c == 0);
    let s: String = buf[..end.unwrap_or(buf.len())]
        .iter()
        .map(|&c| c as u8 as char)
        .collect();
    /* No terminating zero in the buffer: the string is incomplete. */
    let extra = if end.is_none() { "..." } else { "" };
    format!("\"{s}\"{extra}")
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

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t1 = self.timestamp_ns / 1_000_000_000;
        let t2 = self.timestamp_ns % 1_000_000_000;
        write!(
            f,
            "[{t1}.{t2:09}] id={} pid={} ({}):",
            self.id, self.pid, self.cmd
        )?;

        match &self.body {
            Body::Data { addr, val } => write!(f, "\n\tdata@0x{addr:x} = {val:x}"),
            Body::StackFailed { errno } => write!(f, "\n\tfailed to get stack: errno {errno}"),
            Body::Stack(frames) => {
                for frame in frames {
                    write!(f, "\n{frame}")?;
                }
                Ok(())
            }
        }
    }
}

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

    fn header(typ: u64, cmd: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [7u64, typ, 1_500_000_123, 42] {
            v.extend_from_slice(&x.to_ne_bytes());
        }
        let mut c = msg_ent::default().cmd;
        for (dst, &b) in c.iter_mut().zip(cmd) {
            *dst = b as i8;
        }
        v.extend(c.iter().map(|&b| b as u8));
        v
    }

    fn decode(bytes: &[u8]) -> Result<Msg> {
        Decoder::new(None).decode(bytes)
    }

    #[test]
    fn data_msg_renders_like_before() -> Result<()> {
        let mut bytes = header(MSG_TYPE_DATA, b"bash");
        bytes.extend_from_slice(&0xffff0000u64.to_ne_bytes());
        bytes.extend_from_slice(&0x2au64.to_ne_bytes());

        assert_eq!(
            decode(&bytes)?.to_string(),
            "[1.500000123] id=7 pid=42 (\"bash\"):\n\tdata@0xffff0000 = 2a"
        );
        Ok(())
    }

    #[test]
    fn failed_stack_reports_errno() -> Result<()> {
        let mut bytes = header(MSG_TYPE_STACK, b"0123456789abcdef");
        bytes.extend_from_slice(&(-14i64 as u64).to_ne_bytes());
        bytes.extend(
            stack_msg::default()
                .kstack
                .iter()
                .flat_map(|a| a.to_ne_bytes()),
        );

        assert_eq!(
            decode(&bytes)?.to_string(),
            "[1.500000123] id=7 pid=42 (\"0123456789abcdef\"...):\n\tfailed to get stack: errno 14"
        );
        Ok(())
    }

    #[test]
    fn perf_context_markers_are_not_frames() -> Result<()> {
        let mut bytes = header(MSG_TYPE_STACK, b"sync");
        bytes.extend_from_slice(&8u64.to_ne_bytes());
        let mut stack = stack_msg::default().kstack;
        stack[0] = -128i64 as u64;
        bytes.extend(stack.iter().flat_map(|a| a.to_ne_bytes()));

        assert_eq!(
            decode(&bytes)?.to_string(),
            "[1.500000123] id=7 pid=42 (\"sync\"):"
        );
        Ok(())
    }

    #[test]
    fn bad_input_is_err_not_panic() {
        assert!(decode(&header(9, b"x")).is_err());
        assert!(decode(&header(MSG_TYPE_DATA, b"x")[..10]).is_err());
        /* data header without its payload */
        assert!(decode(&header(MSG_TYPE_DATA, b"x")).is_err());
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
