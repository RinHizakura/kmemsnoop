use libc::{c_char, c_int};

use std::ffi::CStr;
use std::fs;

use anyhow::{anyhow, Result};

pub fn cast<T: plain::Plain>(args: &[u8]) -> &T {
    let size = std::mem::size_of::<T>();
    let slice = &args[0..size];
    return plain::from_bytes::<T>(slice).expect("Fail to cast bytes");
}

pub fn get_online_cpus() -> Vec<c_int> {
    let path = "/sys/devices/system/cpu/online";

    let list = fs::read_to_string(path).expect("Fail to read cpu/online sysfs node");

    let list = list.trim().split(",");

    let mut cpus = Vec::new();
    for range in list {
        if let Some(pos) = range.find('-') {
            let start = range[0..pos].parse::<c_int>().unwrap();
            let end = range[pos + 1..].parse::<c_int>().unwrap();
            for c in start..=end {
                cpus.push(c);
            }
        } else {
            cpus.push(range.parse::<c_int>().unwrap());
        }
    }

    cpus
}

#[inline]
fn to_cstr(buf: &[c_char]) -> &CStr {
    unsafe { CStr::from_ptr(buf.as_ptr()) }
}

pub fn uname_version() -> Result<String> {
    let mut n = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::uname(&mut n) };
    if r != 0 {
        return Err(anyhow!("Failed to get uname information"));
    }

    Ok(to_cstr(&n.version[..]).to_string_lossy().to_string())
}
