//! One hardware watchpoint: its own BPF object, the per-CPU perf_event
//! links that keep it armed, and the ring buffer it reports through.
//! Several watchpoints can be polled together with `poll()`.

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
use crate::target::SymKind;

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
    /// Execute watchpoints sit on functions, the others on data.
    pub fn sym_kind(self) -> SymKind {
        match self.access {
            Access::X => SymKind::Func,
            _ => SymKind::Data,
        }
    }

    fn hw_type(self) -> u32 {
        match self.access {
            Access::R => HW_BREAKPOINT_R,
            Access::W => HW_BREAKPOINT_W,
            Access::RW => HW_BREAKPOINT_RW,
            Access::X => HW_BREAKPOINT_X,
        }
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

/// Deliver every message from every watchpoint to `on_msg` until
/// `running` turns false.
pub fn poll(wps: &[Watchpoint], running: &AtomicBool, on_msg: impl Fn(&[u8])) -> Result<()> {
    let mut builder = RingBufferBuilder::new();
    for wp in wps {
        builder.add(&wp.skel.maps.msg_ringbuf, |bytes| {
            on_msg(bytes);
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

fn attach_breakpoint(symbol_addr: usize, bp: Bp, prog: &mut ProgramMut) -> Result<Vec<Link>> {
    let mut attr = perf_event_attr::default();
    attr.size = size_of::<perf_event_attr>() as u32;
    attr.type_ = PERF_TYPE_BREAKPOINT;
    attr.__bindgen_anon_3.bp_addr = symbol_addr as u64;
    attr.__bindgen_anon_4.bp_len = bp.len as u64;
    attr.bp_type = bp.hw_type();
    // response to every event
    attr.__bindgen_anon_1.sample_period = 1;
    attr.__bindgen_anon_2.wakeup_events = 1;

    /* We need to consider different kernel version here. See:
     * https://lore.kernel.org/bpf/20220908214104.3851807-1-namhyung@kernel.org/     */
    let version = uname_version()?;
    if version <= (6, 0) {
        /* Don't set precise_ip to allow bpf_get_stack(). This
         * is a workaround and should be changed if better
         * solution exist. */
        attr.set_precise_ip(0);
    } else {
        /* request synchronous delivery */
        attr.set_precise_ip(2);
        /* On perf_event with precise_ip, calling bpf_get_stack()
         * may trigger unwinder warnings and occasional crashes.
         * bpf_get_[stack|stackid] works around this issue by using
         * callchain attached to perf_sample_data. */
        attr.sample_type = PERF_SAMPLE_CALLCHAIN as u64;
    }

    let mut links = Vec::new();
    for cpu in get_online_cpus()? {
        let link = attach_perf_event(&mut attr, -1, cpu, -1, prog)?;
        links.push(link);
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

fn uname_version() -> Result<(u32, u32)> {
    let mut n = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::uname(&mut n) };
    if r != 0 {
        return Err(anyhow!("Failed to get uname information"));
    }

    let release = unsafe { std::ffi::CStr::from_ptr(n.release.as_ptr()) }.to_string_lossy();
    parse_release(&release)
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
        assert_eq!("x8".parse::<Bp>()?.sym_kind(), SymKind::Func);
        assert_eq!("rw4".parse::<Bp>()?.sym_kind(), SymKind::Data);
        Ok(())
    }

    #[test]
    fn bp_rejects_bad_forms() {
        for bad in ["", "rw", "4", "rw3", "q4", "RW4", "rw16", "rw4x"] {
            assert!(bad.parse::<Bp>().is_err(), "{bad:?} should not parse");
        }
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
