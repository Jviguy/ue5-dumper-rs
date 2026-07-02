//! Remote process memory reader.
//!
//! Linux: `process_vm_readv(2)` + `/proc/<pid>/{cmdline,maps}`.
//! Windows: `ReadProcessMemory` + Toolhelp snapshots.

#[cfg(unix)]
use libc::{c_void, iovec, pid_t, process_vm_readv};
#[cfg(unix)]
use std::fs;

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// Remote process handle.
pub struct ProcessHandle {
    pub pid: u32,
    pub base: usize,
    #[cfg(windows)]
    handle: HANDLE,
}

#[cfg(windows)]
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

impl ProcessHandle {
    /// Find a process whose name contains `process_name` and resolve its image base.
    #[cfg(unix)]
    pub fn attach(process_name: &str) -> Option<Self> {
        let pid = find_pid_unix(process_name)?;
        let base = find_base_unix(pid, process_name)?;
        Some(Self { pid: pid as u32, base })
    }

    #[cfg(windows)]
    pub fn attach(process_name: &str) -> Option<Self> {
        let pid = find_pid_windows(process_name)?;
        let handle =
            unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let base = match find_base_windows(pid, process_name) {
            Some(b) => b,
            None => {
                unsafe { CloseHandle(handle) };
                return None;
            }
        };
        Some(Self { pid, base, handle })
    }

    /// Read a `T` from remote process memory.
    #[cfg(unix)]
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
        let n = unsafe { process_vm_readv(self.pid as pid_t, &local, 1, &remote, 1, 0) };
        (n == std::mem::size_of::<T>() as isize).then(|| unsafe { val.assume_init() })
    }

    #[cfg(windows)]
    pub fn read<T: Copy>(&self, addr: usize) -> Option<T> {
        let mut val = std::mem::MaybeUninit::<T>::uninit();
        let size = std::mem::size_of::<T>();
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const _,
                val.as_mut_ptr().cast(),
                size,
                &mut read,
            )
        };
        (ok != 0 && read == size).then(|| unsafe { val.assume_init() })
    }

    /// Read a non-null 64-bit pointer.
    #[inline]
    pub fn ptr(&self, addr: usize) -> Option<usize> {
        self.read::<u64>(addr).and_then(|v| (v != 0).then(|| v as usize))
    }

    /// Read `len` bytes into a Vec.
    #[cfg(unix)]
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
        let n = unsafe { process_vm_readv(self.pid as pid_t, &local, 1, &remote, 1, 0) };
        (n == len as isize).then(|| buf)
    }

    #[cfg(windows)]
    pub fn read_bytes(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const _,
                buf.as_mut_ptr().cast(),
                len,
                &mut read,
            )
        };
        (ok != 0 && read == len).then(|| buf)
    }
}

// ── Linux process discovery ────────────────────────────────────────

/// Scan /proc for a process whose cmdline contains `name`.
#[cfg(unix)]
fn find_pid_unix(name: &str) -> Option<pid_t> {
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
#[cfg(unix)]
fn find_base_unix(pid: pid_t, module: &str) -> Option<usize> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in maps.lines() {
        if line.contains(module) {
            let dash = line.find('-')?;
            return usize::from_str_radix(&line[..dash], 16).ok();
        }
    }
    None
}

// ── Windows process discovery ──────────────────────────────────────

#[cfg(windows)]
fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    OsString::from_wide(&wide[..end]).to_string_lossy().into_owned()
}

#[cfg(windows)]
fn find_pid_windows(name: &str) -> Option<u32> {
    let needle = name.to_ascii_lowercase();
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap.is_null() || snap == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut result = None;
    if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
        loop {
            let exe = wide_to_string(&entry.szExeFile);
            if exe.to_ascii_lowercase().contains(&needle) {
                result = Some(entry.th32ProcessID);
                break;
            }
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snap) };
    result
}

/// Find the load address of a module (by substring) inside `pid`.
///
/// If no module name matches, falls back to the first module — which Toolhelp
/// always reports as the process's own .exe, the image base the scanner needs.
#[cfg(windows)]
fn find_base_windows(pid: u32, module: &str) -> Option<usize> {
    let needle = module.to_ascii_lowercase();
    let flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    let snap = unsafe { CreateToolhelp32Snapshot(flags, pid) };
    if snap.is_null() || snap == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut matched = None;
    let mut first = None;
    if unsafe { Module32FirstW(snap, &mut entry) } != 0 {
        first = Some(entry.modBaseAddr as usize);
        loop {
            let mod_name = wide_to_string(&entry.szModule);
            if mod_name.to_ascii_lowercase().contains(&needle) {
                matched = Some(entry.modBaseAddr as usize);
                break;
            }
            if unsafe { Module32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snap) };
    matched.or(first)
}
