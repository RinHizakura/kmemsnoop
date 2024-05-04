
fn bpf_attach_perf_event(prog_fd: i32, pid, cpu, group_fd) -> Result<()> {

    let efd = unsafe { perf_event_open(&mut attr, pid, cpu, group_fd,
                                       PERF_FLAG_FD_CLOEXEC as u64) };
    if efd < 0 {
        return Err(anyhow!("perf_event_open() fail"));
    }

    let err = unsafe { ioctl(efd, PERF_EVENT_IOC_RESET, 0) };
    if err < 0 {
        return Err(anyhow!("ioctl(PERF_EVENT_IOC_RESET) fail"));
    }

    let err = unsafe { ioctl(efd, PERF_EVENT_IOC_ENABLE, 0) };
    if err < 0 {
        return Err(anyhow!("ioctl(PERF_EVENT_IOC_ENABLE) fail"));
    }

    let err = unsafe { ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog_fd) };
    if err < 0 {
        return Err(anyhow!("ioctl(PERF_EVENT_IOC_SET_BPF) fail"));
    }

    Ok(())
}

