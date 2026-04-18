use libc::{c_void, iovec, pid_t, process_vm_readv};
use std::fs;

/// Remote process handle. Reads memory via `process_vm_readv(2)`.
pub struct ProcessHandle {
    pub pid: pid_t,
    pub base: usize,
}

impl ProcessHandle {
    /// Find a process whose cmdline contains `process_name` and resolve its image base.
    pub fn attach(process_name: &str) -> Option<Self> {
        let pid = find_pid(process_name)?;
        let base = find_base(pid, process_name)?;
        Some(Self { pid, base })
    }

    /// Read a `T` from remote process memory.
    pub fn read<T: Copy>(&self, addr: usize) -> Option<T> {
        let mut val = std::mem::MaybeUninit::<T>::uninit();
        let local = iovec {
            iov_base: val.as_mut_ptr().cast(),
            iov_len: std::mem::size_of::<T>(),
        };
        let remote = iovec {
            iov_base: addr as *mut c_void,
            iov_len: std::mem::size_of::<T>(),
        };
        let n = unsafe { process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        (n == std::mem::size_of::<T>() as isize).then(|| unsafe { val.assume_init() })
    }

    /// Read a non-null 64-bit pointer.
    #[inline]
    pub fn ptr(&self, addr: usize) -> Option<usize> {
        self.read::<u64>(addr).and_then(|v| (v != 0).then(|| v as usize))
    }

    /// Read `len` bytes into a Vec.
    pub fn read_bytes(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let local = iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: len,
        };
        let remote = iovec {
            iov_base: addr as *mut c_void,
            iov_len: len,
        };
        let n = unsafe { process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        (n == len as isize).then(|| buf)
    }
}

/// Scan /proc for a process whose cmdline contains `name`.
fn find_pid(name: &str) -> Option<pid_t> {
    let needle = name.as_bytes();
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let fname = entry.file_name();
        let pid: pid_t = match fname.to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        if let Ok(data) = fs::read(format!("/proc/{pid}/cmdline")) {
            if data.windows(needle.len()).any(|w| w == needle) {
                return Some(pid);
            }
        }
    }
    None
}

/// Parse /proc/{pid}/maps for the first mapping of `module` (image base).
fn find_base(pid: pid_t, module: &str) -> Option<usize> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in maps.lines() {
        if line.contains(module) {
            let dash = line.find('-')?;
            return usize::from_str_radix(&line[..dash], 16).ok();
        }
    }
    None
}
