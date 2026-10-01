//! One hardware watchpoint: its own BPF object, the per-CPU perf_event
//! links that keep it armed, and the ring buffer it reports through.
//! Several watchpoints can be polled together with `poll()`, which
//! delivers decoded `Msg`s.

use std::io::Error;
use std::mem::{size_of, MaybeUninit};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use libbpf_rs::libbpf_sys::PERF_FLAG_FD_CLOEXEC;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, OpenObject, ProgramMut, RingBufferBuilder};
use libc::{c_int, pid_t, rlimit, setrlimit, RLIMIT_MEMLOCK, RLIM_INFINITY};
use perf_event_open_sys::bindings::{
    perf_event_attr, HW_BREAKPOINT_R, HW_BREAKPOINT_RW, HW_BREAKPOINT_W, HW_BREAKPOINT_X,
    PERF_SAMPLE_CALLCHAIN, PERF_TYPE_BREAKPOINT,
};
use perf_event_open_sys::perf_event_open;

use crate::kmemsnoop::{KmemsnoopSkel, KmemsnoopSkelBuilder};
use crate::msg::{Decoder, Msg};
use crate::symbols::Symbols;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    R,
    W,
    RW,
    X,
}

/// Watchpoint type as typed on the command line: `rw4`, `x8`, ...
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bp {
    pub access: Access,
    pub len: u8,
}

impl FromStr for Bp {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let split = s.find(|c: char| c.is_ascii_digit()).unwrap_or(s.len());
        let (access, len) = s.split_at(split);

        let access = match access {
            "r" => Access::R,
            "w" => Access::W,
            "rw" => Access::RW,
            "x" => Access::X,
            _ => bail!("access must be r, w, rw or x, got {access:?}"),
        };
        let len = match len {
            "1" => 1,
            "2" => 2,
            "4" => 4,
            "8" => 8,
            _ => bail!("length must be 1, 2, 4 or 8, got {len:?}"),
        };

        Ok(Bp { access, len })
    }
}

impl Bp {
    fn hw_type(self) -> u32 {
        match self.access {
            Access::R => HW_BREAKPOINT_R,
            Access::W => HW_BREAKPOINT_W,
            Access::RW => HW_BREAKPOINT_RW,
            Access::X => HW_BREAKPOINT_X,
        }
    }

    /// The perf event of this breakpoint on `addr`, waking up on every hit.
    /// Up to 6.0, bpf_get_stack() only works without precise_ip; from 6.1
    /// on, precise_ip 2 delivers synchronously and the callchain is
    /// attached to the sample, which bpf_get_stack() then reads instead of
    /// unwinding (which warned and occasionally crashed). See
    /// https://lore.kernel.org/bpf/20220908214104.3851807-1-namhyung@kernel.org/
    fn perf_attr(self, addr: usize, kernel: (u32, u32)) -> perf_event_attr {
        let mut attr = perf_event_attr::default();
        attr.size = size_of::<perf_event_attr>() as u32;
        attr.type_ = PERF_TYPE_BREAKPOINT;
        attr.__bindgen_anon_3.bp_addr = addr as u64;
        attr.__bindgen_anon_4.bp_len = self.len as u64;
        attr.bp_type = self.hw_type();
        attr.__bindgen_anon_1.sample_period = 1;
        attr.__bindgen_anon_2.wakeup_events = 1;

        if kernel <= (6, 0) {
            attr.set_precise_ip(0);
        } else {
            attr.set_precise_ip(2);
            attr.sample_type = PERF_SAMPLE_CALLCHAIN as u64;
        }
        attr
    }
}

pub struct Watchpoint {
    skel: KmemsnoopSkel<'static>,
    /* Each link is one per-CPU perf event; dropping them disarms the
     * watchpoint, so they live exactly as long as the Watchpoint. */
    _links: Vec<Link>,
}

impl Watchpoint {
    pub fn attach(addr: usize, bp: Bp) -> Result<Watchpoint> {
        /* We may have to bump RLIMIT_MEMLOCK for libbpf explicitly */
        if cfg!(bump_memlock_rlimit_manually) {
            bump_memlock_rlimit()?;
        }

        /* ponytail: the skeleton borrows its OpenObject storage for its
         * whole life and a watchpoint lives until exit, so leak the
         * storage instead of threading a lifetime through every caller.
         * Revisit with a self-referential struct if detach ever matters. */
        let storage: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));

        let open_skel = KmemsnoopSkelBuilder::default().open(storage)?;
        /* rodata must be set before load(). */
        open_skel.maps.rodata_data.bp_type = bp.hw_type();
        open_skel.maps.rodata_data.bp_len = bp.len as u64;

        let mut skel = open_skel.load()?;
        skel.attach()?;

        let links = attach_breakpoint(addr, bp, &mut skel.progs.perf_event_handler)?;

        Ok(Watchpoint {
            skel,
            _links: links,
        })
    }
}

/// Deliver every hit from every watchpoint to `on_msg` until `running`
/// turns false. Msg ids count per ring buffer, so each watchpoint gets
/// its own Decoder to tell its dropped hits.
pub fn poll(
    wps: &[Watchpoint],
    running: &AtomicBool,
    syms: &Symbols,
    on_msg: impl Fn(Result<Msg>),
) -> Result<()> {
    let decoders: Vec<Decoder> = wps.iter().map(|_| Decoder::new(syms)).collect();
    let mut builder = RingBufferBuilder::new();
    for (wp, decoder) in wps.iter().zip(&decoders) {
        builder.add(&wp.skel.maps.msg_ringbuf, |bytes| {
            on_msg(decoder.decode(bytes));
            0
        })?;
    }
    let ringbuf = builder.build()?;

    while running.load(Ordering::SeqCst) {
        match ringbuf.poll(Duration::from_millis(100)) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

fn attach_perf_event(
    attr: &mut perf_event_attr,
    pid: pid_t,
    cpu: c_int,
    group_fd: c_int,
    prog: &mut ProgramMut,
) -> Result<Link> {
    let efd = unsafe {
        perf_event_open(
            attr as *mut perf_event_attr,
            pid,
            cpu,
            group_fd,
            PERF_FLAG_FD_CLOEXEC as u64,
        )
    };

    if efd < 0 {
        return Err(anyhow!(format!(
            "perf_event_open() fail: {}",
            Error::last_os_error()
        )));
    }

    let link = prog.attach_perf_event(efd)?;
    Ok(link)
}

/// Arm the breakpoint on every online CPU.
fn attach_breakpoint(addr: usize, bp: Bp, prog: &mut ProgramMut) -> Result<Vec<Link>> {
    let mut attr = bp.perf_attr(addr, kernel_version()?);
    let mut links = Vec::new();
    for cpu in get_online_cpus()? {
        links.push(attach_perf_event(&mut attr, -1, cpu, -1, prog)?);
    }
    Ok(links)
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlim = rlimit {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };

    unsafe {
        let ret = setrlimit(RLIMIT_MEMLOCK, &rlim);
        if ret != 0 {
            return Err(anyhow!(format!(
                "Failed to bump RLIMIT_MEMLOCK: {}",
                Error::last_os_error()
            )));
        }
    }

    Ok(())
}

fn get_online_cpus() -> Result<Vec<c_int>> {
    let list = std::fs::read_to_string("/sys/devices/system/cpu/online")?;
    parse_cpu_list(list.trim())
}

/// "0-3,5" → [0, 1, 2, 3, 5]
fn parse_cpu_list(list: &str) -> Result<Vec<c_int>> {
    let mut cpus = Vec::new();
    for range in list.split(',') {
        match range.split_once('-') {
            Some((start, end)) => cpus.extend(start.parse::<c_int>()?..=end.parse::<c_int>()?),
            None => cpus.push(range.parse()?),
        }
    }
    Ok(cpus)
}

/// (major, minor) of the running kernel, from the same string uname(2)
/// reports as release.
fn kernel_version() -> Result<(u32, u32)> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    parse_release(release.trim())
}

/// "6.18.20.3-microsoft-standard" → (6, 18)
fn parse_release(release: &str) -> Result<(u32, u32)> {
    let mut parts = release.split('.');
    let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
        bail!("Invalid version string {release}");
    };
    Ok((major.parse()?, minor.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bp_parses_every_cli_form() -> Result<()> {
        for (s, access) in [
            ("r", Access::R),
            ("w", Access::W),
            ("rw", Access::RW),
            ("x", Access::X),
        ] {
            for len in [1u8, 2, 4, 8] {
                assert_eq!(format!("{s}{len}").parse::<Bp>()?, Bp { access, len });
            }
        }
        Ok(())
    }

    #[test]
    fn bp_rejects_bad_forms() {
        for bad in ["", "rw", "4", "rw3", "q4", "RW4", "rw16", "rw4x"] {
            assert!(bad.parse::<Bp>().is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn perf_attr_switches_stack_delivery_at_6_1() -> Result<()> {
        let bp: Bp = "rw4".parse()?;

        let old = bp.perf_attr(0x1234, (6, 0));
        assert_eq!(old.type_, PERF_TYPE_BREAKPOINT);
        assert_eq!(old.bp_type, HW_BREAKPOINT_RW);
        /* SAFETY: reading back the union members perf_attr() wrote. */
        unsafe {
            assert_eq!(old.__bindgen_anon_3.bp_addr, 0x1234);
            assert_eq!(old.__bindgen_anon_4.bp_len, 4);
            assert_eq!(old.__bindgen_anon_1.sample_period, 1);
            assert_eq!(old.__bindgen_anon_2.wakeup_events, 1);
        }
        assert_eq!(old.precise_ip(), 0);
        assert_eq!(old.sample_type, 0);

        let new = bp.perf_attr(0x1234, (6, 1));
        assert_eq!(new.precise_ip(), 2);
        assert_eq!(new.sample_type, PERF_SAMPLE_CALLCHAIN as u64);
        assert_eq!(new.bp_type, HW_BREAKPOINT_RW);
        Ok(())
    }

    #[test]
    fn cpu_list_and_release_parse() -> Result<()> {
        assert_eq!(parse_cpu_list("0-3,5")?, vec![0, 1, 2, 3, 5]);
        assert_eq!(parse_cpu_list("0")?, vec![0]);
        assert!(parse_cpu_list("0-").is_err());
        assert_eq!(parse_release("6.18.20.3-microsoft-standard")?, (6, 18));
        assert_eq!(parse_release("5.4.0")?, (5, 4));
        assert!(parse_release("6").is_err());
        Ok(())
    }
}
