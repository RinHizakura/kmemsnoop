//! Msg decoding: bytes from the BPF ring buffer in, a `Msg` out.
//! The `#[repr(C)]` structs below are the only place that mirrors
//! `bpf/msg.h`; the size asserts catch a drift at compile time.

use std::fmt;
use std::mem::size_of;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};
use blazesym::symbolize::{self, Input, Kernel, Source, Symbolized, Symbolizer};
use plain::Plain;

const MSG_TYPE_STACK: u64 = 0;
const MSG_TYPE_DATA: u64 = 1;
const TASK_COMM_LEN: usize = 16;
const PERF_MAX_STACK_DEPTH: usize = 127;
/* perf callchains carry context markers (PERF_CONTEXT_KERNEL = -128, ...)
 * that all sit at or above PERF_CONTEXT_MAX; they are not return addresses.
 * See enum perf_callchain_context in <linux/perf_event.h>. */
const PERF_CONTEXT_MAX: u64 = -4095i64 as u64;

#[repr(C)]
struct MsgEnt {
    id: u64,
    typ: u64,
    timestamp: u64,
    pid: u64,
    cmd: [u8; TASK_COMM_LEN],
}
unsafe impl Plain for MsgEnt {}

#[repr(C)]
struct StackMsg {
    kstack_sz: u64,
    kstack: [u64; PERF_MAX_STACK_DEPTH],
}
unsafe impl Plain for StackMsg {}

#[repr(C)]
struct DataMsg {
    addr: u64,
    val: u64,
}
unsafe impl Plain for DataMsg {}

const _: () = assert!(size_of::<MsgEnt>() == 48);
const _: () = assert!(size_of::<StackMsg>() == 1024);
const _: () = assert!(size_of::<DataMsg>() == 16);

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
    pub fn new() -> Self {
        Decoder {
            symbolizer: Symbolizer::new(),
            src: Source::Kernel(Kernel::default()),
        }
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<Msg> {
        let (ent, inner) = split::<MsgEnt>(bytes)?;

        let body = match ent.typ {
            MSG_TYPE_STACK => self.stack(inner)?,
            MSG_TYPE_DATA => {
                let (msg, _) = split::<DataMsg>(inner)?;
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
        let (msg, _) = split::<StackMsg>(inner)?;

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

        let syms = self
            .symbolizer
            .symbolize(&self.src, Input::AbsAddr(&addrs))?;

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

/// Reinterpret the head of `bytes` as `T` and return the remainder.
fn split<T: Plain>(bytes: &[u8]) -> Result<(&T, &[u8])> {
    let n = size_of::<T>();
    if bytes.len() < n {
        bail!("message too short: {} < {n} bytes", bytes.len());
    }
    let t = plain::from_bytes(&bytes[..n]).map_err(|e| anyhow!("bad message layout: {e:?}"))?;
    Ok((t, &bytes[n..]))
}

fn format_cmd(buf: &[u8; TASK_COMM_LEN]) -> String {
    let end = buf.iter().position(|&c| c == 0);
    let s: String = buf[..end.unwrap_or(buf.len())]
        .iter()
        .map(|&c| c as char)
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

    /* Ring buffer records are 8-byte aligned; mimic that for from_bytes. */
    #[repr(C, align(8))]
    struct Aligned<const N: usize>([u8; N]);

    fn header(typ: u64, cmd: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [7u64, typ, 1_500_000_123, 42] {
            v.extend_from_slice(&x.to_ne_bytes());
        }
        let mut c = [0u8; TASK_COMM_LEN];
        c[..cmd.len()].copy_from_slice(cmd);
        v.extend_from_slice(&c);
        v
    }

    fn decode(bytes: &[u8]) -> Result<Msg> {
        let mut buf = Aligned([0u8; 2048]);
        buf.0[..bytes.len()].copy_from_slice(bytes);
        Decoder::new().decode(&buf.0[..bytes.len()])
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
        bytes.extend_from_slice(&[0u8; PERF_MAX_STACK_DEPTH * 8]);

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
        let mut stack = [0u8; PERF_MAX_STACK_DEPTH * 8];
        stack[..8].copy_from_slice(&(-128i64 as u64).to_ne_bytes());
        bytes.extend_from_slice(&stack);

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
}
