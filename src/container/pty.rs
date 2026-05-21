use crate::fd::set_cloexec;
use libc;
use nix::pty::{openpty, OpenptyResult};
use nix::sys::termios::{tcgetattr, tcsetattr, SetArg, Termios};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

pub struct PtyManager {
    pub master: OwnedFd,
    slave: Option<OwnedFd>,
}

impl PtyManager {
    pub fn new() -> io::Result<Self> {
        let OpenptyResult { master, slave } = openpty(None, None).map_err(io::Error::other)?;
        set_cloexec(&master).map_err(io::Error::other)?;
        set_cloexec(&slave).map_err(io::Error::other)?;
        Ok(Self {
            master,
            slave: Some(slave),
        })
    }

    pub fn slave_fd(&self) -> io::Result<RawFd> {
        self.slave
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "pty slave is closed"))
    }

    pub fn slave_ref(&self) -> Option<&OwnedFd> {
        self.slave.as_ref()
    }

    pub fn close_slave(&mut self) {
        self.slave.take();
    }
}

pub struct RawTerminalGuard {
    original_termios: Termios,
}

impl RawTerminalGuard {
    pub fn new() -> io::Result<Self> {
        let stdin = io::stdin();
        let original_termios = tcgetattr(&stdin).map_err(io::Error::other)?;

        let mut raw_termios = original_termios.clone();
        nix::sys::termios::cfmakeraw(&mut raw_termios);

        tcsetattr(&stdin, SetArg::TCSANOW, &raw_termios).map_err(io::Error::other)?;

        Ok(Self { original_termios })
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        let stdin = io::stdin();
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &self.original_termios);
    }
}

static MASTER_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    let fd = MASTER_FD.load(Ordering::Relaxed);
    if fd != -1 {
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe {
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
                libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
            }
        }
    }
}

pub fn register_sigwinch(master_fd: std::os::fd::RawFd) {
    MASTER_FD.store(master_fd, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGWINCH, sigwinch_handler as *const () as usize);
    }
    sigwinch_handler(libc::SIGWINCH);
}

pub fn unregister_sigwinch() {
    MASTER_FD.store(-1, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGWINCH, libc::SIG_DFL);
    }
}

pub struct PtyProxy {
    pid: nix::unistd::Pid,
}

impl PtyProxy {
    pub fn join(self) {
        let _ = nix::sys::wait::waitpid(self.pid, None);
    }
}

pub fn proxy_pty(master: OwnedFd, inherited_control_fds: &[&OwnedFd]) -> io::Result<PtyProxy> {
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork() }.map_err(io::Error::other)? {
        ForkResult::Child => {
            for fd in inherited_control_fds {
                unsafe {
                    libc::close(fd.as_raw_fd());
                }
            }

            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let mut stdin = io::stdin();
                    let mut master_file = File::from(master);
                    let mut buf = [0u8; 1024];
                    loop {
                        match stdin.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if master_file.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    std::process::exit(0);
                }
                Ok(ForkResult::Parent { child }) => {
                    let mut stdout = io::stdout();
                    let mut master_file = File::from(master);
                    let mut buf = [0u8; 1024];
                    loop {
                        match master_file.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if stdout.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                                let _ = stdout.flush();
                            }
                            Err(e) => {
                                if e.kind() != io::ErrorKind::Interrupted {
                                    break;
                                }
                            }
                        }
                    }
                    unsafe {
                        libc::kill(child.as_raw(), libc::SIGTERM);
                    }
                    let _ = nix::sys::wait::waitpid(child, None);
                    std::process::exit(0);
                }
                Err(_) => {
                    std::process::exit(1);
                }
            }
        }
        ForkResult::Parent { child } => Ok(PtyProxy { pid: child }),
    }
}
