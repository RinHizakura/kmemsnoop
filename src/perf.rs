use crate::utils::*;

use std::io::Error;
use std::mem::size_of;

use anyhow::{anyhow, Result};
use libbpf_rs::libbpf_sys::PERF_FLAG_FD_CLOEXEC;
use libbpf_rs::{Link, ProgramMut};
use libc::{c_int, pid_t};

use perf_event_open_sys::bindings::{perf_event_attr, PERF_SAMPLE_CALLCHAIN, PERF_TYPE_BREAKPOINT};
use perf_event_open_sys::perf_event_open;

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

pub fn attach_breakpoint(
    symbol_addr: usize,
    bp_type: u32,
    bp_len: u64,
    prog: &mut ProgramMut,
) -> Result<Vec<Link>> {
    let mut attr = perf_event_attr::default();
    attr.size = size_of::<perf_event_attr>() as u32;
    attr.type_ = PERF_TYPE_BREAKPOINT;
    attr.__bindgen_anon_3.bp_addr = symbol_addr as u64;
    attr.__bindgen_anon_4.bp_len = bp_len;
    attr.bp_type = bp_type;
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
    for cpu in get_online_cpus() {
        let link = attach_perf_event(&mut attr, -1, cpu, -1, prog)?;
        links.push(link);
    }

    Ok(links)
}
