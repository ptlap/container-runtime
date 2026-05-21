use crate::error::ContainerError;
use crate::fd::set_cloexec;
use anyhow::{Context, Result};
use nix::libc;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

const REEXEC_ENV: &str = "CRUN_RS_SELF_REEXEC";

pub fn ensure_reexecuted_from_memfd() -> Result<()> {
    if std::env::var_os(REEXEC_ENV).is_some() {
        std::env::remove_var(REEXEC_ENV);
        if is_running_from_memfd()? {
            return Ok(());
        }
    }

    let mut source = File::open("/proc/self/exe").context("failed to open /proc/self/exe")?;
    set_cloexec(&source).context("failed to mark /proc/self/exe CLOEXEC")?;
    let mut sealed_exe = create_memfd("crun-rs-self")?;
    io::copy(&mut source, &mut sealed_exe).context("failed to copy self binary into memfd")?;
    sealed_exe
        .seek(SeekFrom::Start(0))
        .context("failed to rewind self memfd")?;
    seal_memfd(sealed_exe.as_raw_fd())?;

    reexec_from_memfd(sealed_exe.as_raw_fd())
}

pub fn current_exe_link() -> Result<PathBuf> {
    std::fs::read_link("/proc/self/exe").context("failed to read /proc/self/exe link")
}

pub fn is_running_from_memfd() -> Result<bool> {
    let exe = current_exe_link()?;
    Ok(exe.as_os_str().as_bytes().starts_with(b"/memfd:"))
}

fn create_memfd(name: &str) -> Result<File> {
    let name = CString::new(name).context("memfd name contains an interior NUL")?;
    let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("memfd_create failed");
    }

    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

fn seal_memfd(fd: i32) -> Result<()> {
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let result = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) };
    if result < 0 {
        return Err(io::Error::last_os_error()).context("failed to seal self memfd");
    }

    Ok(())
}

fn reexec_from_memfd(fd: i32) -> Result<()> {
    let path = CString::new(format!("/proc/self/fd/{fd}")).context("invalid memfd path")?;
    let args = cstring_args()?;
    let env = cstring_env()?;
    let mut argv = ptrs(&args);
    let mut envp = ptrs(&env);

    let result = unsafe { libc::execve(path.as_ptr(), argv.as_mut_ptr(), envp.as_mut_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error()).context("failed to re-exec from sealed memfd");
    }

    Err(ContainerError::ExecveReturned.into())
}

fn cstring_args() -> Result<Vec<CString>> {
    std::env::args_os()
        .map(|arg| CString::new(arg.as_os_str().as_bytes()).context("argument contains NUL byte"))
        .collect()
}

fn cstring_env() -> Result<Vec<CString>> {
    let mut env = Vec::new();
    for (key, value) in std::env::vars_os() {
        if key.as_os_str().as_bytes() == REEXEC_ENV.as_bytes() {
            continue;
        }
        let mut item = Vec::new();
        item.extend_from_slice(key.as_os_str().as_bytes());
        item.push(b'=');
        item.extend_from_slice(value.as_os_str().as_bytes());
        env.push(CString::new(item).context("environment contains NUL byte")?);
    }
    env.push(CString::new(format!("{REEXEC_ENV}=1")).expect("static env marker is valid"));
    Ok(env)
}

fn ptrs(items: &[CString]) -> Vec<*const libc::c_char> {
    let mut ptrs = items.iter().map(|item| item.as_ptr()).collect::<Vec<_>>();
    ptrs.push(std::ptr::null());
    ptrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstring_env_adds_reexec_marker() {
        let env = cstring_env().expect("env should convert");
        let marker = format!("{REEXEC_ENV}=1");

        assert!(env.iter().any(|item| item.to_bytes() == marker.as_bytes()));
    }
}
