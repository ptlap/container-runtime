use anyhow::{Context, Result};
use nix::libc;

/// Replaces the whole process environment with the container configuration.
///
/// The runtime inherits the environment of whoever invoked `minicrun`, including
/// `SUDO_*` and the caller's `PATH`, and `execvp` would hand all of it to the
/// container. Clearing first makes the container environment a function of the
/// bundle alone, which is what the OCI spec describes and what keeps syscall
/// traces reproducible across machines.
///
/// `execvpe` is deliberately not used instead: glibc resolves the `PATH` lookup
/// from the caller's `environ` rather than from the `envp` argument, so the
/// leak would survive in the lookup path.
///
/// When the bundle declares no `PATH`, `execvp` falls back to the confstr
/// default (`/bin:/usr/bin`), which is deterministic.
pub fn replace_environment(env: &[String]) -> Result<()> {
    crate::spec::config::validate_environment(env)?;

    if unsafe { libc::clearenv() } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to clear the inherited environment");
    }

    for item in env {
        let (key, value) = item
            .split_once('=')
            .expect("environment was validated before installation");
        std::env::set_var(key, value);
    }

    Ok(())
}
