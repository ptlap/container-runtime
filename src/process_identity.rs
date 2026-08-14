use crate::error::ProcessIdentityError;
use crate::fd::set_cloexec;
use nix::libc;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Debug)]
pub struct ProcessIdentity {
    pid: i32,
    starttime: u64,
    pidfd: OwnedFd,
}

impl ProcessIdentity {
    pub fn open(pid: i32, expected_starttime: Option<u64>) -> anyhow::Result<Self> {
        let expected = expected_starttime.ok_or(ProcessIdentityError::MissingToken { pid })?;
        let actual = crate::state::process_starttime(pid)?;
        if actual != expected {
            return Err(ProcessIdentityError::Reused { pid }.into());
        }

        let pidfd = pidfd_open(pid)?;
        let identity = Self {
            pid,
            starttime: expected,
            pidfd,
        };
        identity.verify()?;
        Ok(identity)
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        let actual = crate::state::process_starttime(self.pid)?;
        if actual != self.starttime {
            return Err(ProcessIdentityError::Reused { pid: self.pid }.into());
        }
        Ok(())
    }

    pub fn send_signal(&self, signal: i32) -> anyhow::Result<()> {
        self.verify()?;
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result < 0 {
            return Err(ProcessIdentityError::PidfdSignal {
                pid: self.pid,
                errno: io::Error::last_os_error().to_string(),
            }
            .into());
        }
        Ok(())
    }

    pub fn pidfd(&self) -> &OwnedFd {
        &self.pidfd
    }
}

fn pidfd_open(pid: i32) -> anyhow::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(ProcessIdentityError::PidfdOpen {
            pid,
            errno: io::Error::last_os_error().to_string(),
        }
        .into());
    }

    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    set_cloexec(&pidfd).map_err(|error| anyhow::anyhow!(error))?;
    Ok(pidfd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{fork, getpid, ForkResult};
    use std::time::Duration;

    #[test]
    fn opens_and_verifies_current_process_identity() {
        let pid = getpid().as_raw();
        let starttime = crate::state::process_starttime(pid).expect("starttime should exist");
        let identity = ProcessIdentity::open(pid, Some(starttime)).expect("pidfd should open");
        identity.verify().expect("identity should remain valid");
        assert_eq!(identity.pid(), pid);
    }

    #[test]
    fn pidfd_signal_does_not_target_a_reused_pid() {
        match unsafe { fork() }.expect("fork should work") {
            ForkResult::Child => {
                std::thread::sleep(Duration::from_secs(2));
                std::process::exit(0);
            }
            ForkResult::Parent { child } => {
                let starttime = crate::state::process_starttime(child.as_raw())
                    .expect("child starttime should exist");
                let identity = ProcessIdentity::open(child.as_raw(), Some(starttime))
                    .expect("pidfd should open");
                identity
                    .send_signal(libc::SIGTERM)
                    .expect("pidfd signal should reach child");
                nix::sys::wait::waitpid(child, None).expect("child should be reaped");
            }
        }
    }
}
