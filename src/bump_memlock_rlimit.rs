use anyhow::{anyhow, Result};
use libc::{rlimit, setrlimit, RLIMIT_MEMLOCK, RLIM_INFINITY};
use std::io::Error;

pub fn bump_memlock_rlimit() -> Result<()> {
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
