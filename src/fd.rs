use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use std::os::fd::AsFd;

pub(crate) fn set_cloexec(fd: &impl AsFd) -> nix::Result<()> {
    let current = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD)?);
    fcntl(fd, FcntlArg::F_SETFD(current | FdFlag::FD_CLOEXEC))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::pipe;

    #[test]
    fn marks_fd_close_on_exec() {
        let (read_fd, _write_fd) = pipe().expect("pipe should be created");

        set_cloexec(&read_fd).expect("fd should be marked close-on-exec");

        let flags =
            FdFlag::from_bits_truncate(fcntl(&read_fd, FcntlArg::F_GETFD).expect("get fd flags"));
        assert!(flags.contains(FdFlag::FD_CLOEXEC));
    }
}
