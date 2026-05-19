use nix::pty::{openpty, OpenptyResult};
use nix::sys::termios::{tcgetattr, tcsetattr, SetArg, Termios};
use std::fs::File;
use std::io::{self, Read, Write};
use libc;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;

pub struct PtyManager {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

impl PtyManager {
    pub fn new() -> io::Result<Self> {
        let OpenptyResult { master, slave } = openpty(None, None)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Self { master, slave })
    }
}

pub struct RawTerminalGuard {
    original_termios: Termios,
}

impl RawTerminalGuard {
    pub fn new() -> io::Result<Self> {
        let stdin = io::stdin();
        let original_termios = tcgetattr(&stdin)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut raw_termios = original_termios.clone();
        nix::sys::termios::cfmakeraw(&mut raw_termios);

        tcsetattr(&stdin, SetArg::TCSANOW, &raw_termios)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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
    // Đồng bộ kích thước ban đầu
    sigwinch_handler(libc::SIGWINCH);
}

pub fn unregister_sigwinch() {
    MASTER_FD.store(-1, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGWINCH, libc::SIG_DFL);
    }
}

pub fn proxy_pty(master: OwnedFd) -> (thread::JoinHandle<()>, thread::JoinHandle<()>) {
    let master_write = master.try_clone().expect("failed to clone master fd");

    let t_in = thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut master_file = File::from(master_write);
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if master_file.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let t_out = thread::spawn(move || {
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
    });

    (t_in, t_out)
}
