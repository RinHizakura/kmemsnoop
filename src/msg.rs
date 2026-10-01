//! Msg decoding: bytes from the BPF ring buffer in, a `Msg` out.
//! The wire layout comes from the skeleton's BTF-generated type, so
//! `bpf/msg.h` is its only definition.

use std::cell::Cell;
use std::fmt;
use std::mem::size_of;

use anyhow::{bail, Result};

use crate::kmemsnoop::types::kmemsnoop_msg as wire;
use crate::symbols::{Frame, Symbols};

/* perf callchains carry context markers (PERF_CONTEXT_KERNEL = -128, ...)
 * that all sit at or above PERF_CONTEXT_MAX; they are not return addresses.
 * See enum perf_callchain_context in <linux/perf_event.h>. */
const PERF_CONTEXT_MAX: u64 = -4095i64 as u64;

/// One watchpoint hit.
pub struct Msg {
    pub id: u64,
    /// Hits lost in the ring buffer since the previous Msg.
    pub dropped: u64,
    pub pid: u64,
    pub timestamp_ns: u64,
    pub cmd: String,
    /// Accessed address and value; absent for execute watchpoints.
    pub data: Option<(u64, u64)>,
    pub stack: Stack,
}

pub enum Stack {
    Frames(Vec<Frame>),
    /// bpf_get_stack() reported a negative errno.
    Failed {
        errno: i64,
    },
}

pub struct Decoder<'a> {
    syms: &'a Symbols,
    /// Id of the last decoded Msg, to count the gap before the next one.
    /// Ids are per ring buffer, so one Decoder serves one Watchpoint.
    last_id: Cell<u64>,
}

impl<'a> Decoder<'a> {
    pub fn new(syms: &'a Symbols) -> Self {
        Decoder {
            syms,
            last_id: Cell::new(0),
        }
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<Msg> {
        let (w, _) = split::<wire>(bytes)?;

        let dropped = w.id.saturating_sub(self.last_id.get() + 1);
        self.last_id.set(w.id);

        Ok(Msg {
            id: w.id,
            dropped,
            pid: w.pid,
            timestamp_ns: w.timestamp,
            cmd: format_cmd(&w.cmd),
            data: (w.has_data != 0).then_some((w.addr, w.val)),
            stack: self.stack(w.kstack_sz, &w.kstack)?,
        })
    }

    fn stack(&self, kstack_sz: i64, kstack: &[u64]) -> Result<Stack> {
        if kstack_sz < 0 {
            return Ok(Stack::Failed { errno: -kstack_sz });
        }
        let depth = (kstack_sz as usize / size_of::<u64>()).min(kstack.len());
        let addrs: Vec<u64> = kstack[..depth]
            .iter()
            .copied()
            .filter(|&a| a < PERF_CONTEXT_MAX)
            .collect();
        if addrs.is_empty() {
            return Ok(Stack::Frames(Vec::new()));
        }
        Ok(Stack::Frames(self.syms.frames(&addrs)?))
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

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.dropped > 0 {
            writeln!(f, "({} hits dropped)", self.dropped)?;
        }
        let t1 = self.timestamp_ns / 1_000_000_000;
        let t2 = self.timestamp_ns % 1_000_000_000;
        write!(
            f,
            "[{t1}.{t2:09}] id={} pid={} ({}):",
            self.id, self.pid, self.cmd
        )?;
        if let Some((addr, val)) = self.data {
            write!(f, "\n\tdata@0x{addr:x} = {val:x}")?;
        }
        match &self.stack {
            Stack::Failed { errno } => write!(f, "\n\tfailed to get stack: errno {errno}"),
            Stack::Frames(frames) => {
                for frame in frames {
                    write!(f, "\n{frame}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hit as the BPF side would write it: pid 42, no data, empty stack.
    fn hit(id: u64, cmd: &[u8]) -> wire {
        let mut w = wire::default();
        w.id = id;
        w.timestamp = 1_500_000_123;
        w.pid = 42;
        for (dst, &b) in w.cmd.iter_mut().zip(cmd) {
            *dst = b as i8;
        }
        w
    }

    fn bytes(w: &wire) -> Vec<u8> {
        /* SAFETY: wire is a #[repr(C)] plain-data struct; this is the
         * inverse of split(). */
        unsafe { std::slice::from_raw_parts(w as *const wire as *const u8, size_of::<wire>()) }
            .to_vec()
    }

    fn decode(w: &wire) -> Result<Msg> {
        Decoder::new(&Symbols::new(None)).decode(&bytes(w))
    }

    #[test]
    fn data_hit_renders_data_line_then_stack() -> Result<()> {
        let mut w = hit(1, b"bash");
        w.has_data = 1;
        w.addr = 0xffff0000;
        w.val = 0x2a;

        assert_eq!(
            decode(&w)?.to_string(),
            "[1.500000123] id=1 pid=42 (\"bash\"):\n\tdata@0xffff0000 = 2a"
        );
        Ok(())
    }

    #[test]
    fn execute_hit_has_no_data_line() -> Result<()> {
        let mut w = hit(1, b"sync");
        w.addr = 0xffff0000;
        assert_eq!(
            decode(&w)?.to_string(),
            "[1.500000123] id=1 pid=42 (\"sync\"):"
        );
        Ok(())
    }

    #[test]
    fn failed_stack_reports_errno() -> Result<()> {
        let mut w = hit(1, b"0123456789abcdef");
        w.kstack_sz = -14;

        assert_eq!(
            decode(&w)?.to_string(),
            "[1.500000123] id=1 pid=42 (\"0123456789abcdef\"...):\n\tfailed to get stack: errno 14"
        );
        Ok(())
    }

    #[test]
    fn perf_context_markers_are_not_frames() -> Result<()> {
        let mut w = hit(1, b"sync");
        w.kstack_sz = 8;
        w.kstack[0] = -128i64 as u64;

        assert_eq!(
            decode(&w)?.to_string(),
            "[1.500000123] id=1 pid=42 (\"sync\"):"
        );
        Ok(())
    }

    #[test]
    fn id_gaps_are_reported_as_dropped_hits() -> Result<()> {
        let syms = Symbols::new(None);
        let d = Decoder::new(&syms);
        assert_eq!(d.decode(&bytes(&hit(1, b"a")))?.dropped, 0);
        assert_eq!(d.decode(&bytes(&hit(2, b"a")))?.dropped, 0);
        let m = d.decode(&bytes(&hit(5, b"a")))?;
        assert_eq!(m.dropped, 2);
        assert_eq!(
            m.to_string(),
            "(2 hits dropped)\n[1.500000123] id=5 pid=42 (\"a\"):"
        );
        Ok(())
    }

    #[test]
    fn bad_input_is_err_not_panic() {
        let short = &bytes(&hit(1, b"x"))[..10];
        assert!(Decoder::new(&Symbols::new(None)).decode(short).is_err());
    }
}
