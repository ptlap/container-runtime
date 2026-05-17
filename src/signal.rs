use anyhow::{bail, Result};
use nix::errno::Errno;
use nix::libc;

pub const DEFAULT_SIGNAL: &str = "SIGTERM";

pub fn parse_signal(value: &str) -> Result<i32> {
    let normalized = value.trim().to_ascii_uppercase();
    let name = normalized.strip_prefix("SIG").unwrap_or(&normalized);

    if let Ok(signal) = name.parse::<i32>() {
        if signal > 0 {
            return Ok(signal);
        }
        bail!("signal number must be positive: {value}");
    }

    match name {
        "HUP" => Ok(libc::SIGHUP),
        "INT" => Ok(libc::SIGINT),
        "QUIT" => Ok(libc::SIGQUIT),
        "KILL" => Ok(libc::SIGKILL),
        "TERM" => Ok(libc::SIGTERM),
        "USR1" => Ok(libc::SIGUSR1),
        "USR2" => Ok(libc::SIGUSR2),
        "STOP" => Ok(libc::SIGSTOP),
        "CONT" => Ok(libc::SIGCONT),
        _ => bail!("unsupported signal: {value}"),
    }
}

pub fn send_signal(pid: i32, signal: i32) -> Result<()> {
    let result = unsafe { libc::kill(pid, signal) };
    Errno::result(result).map(drop)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_signals() {
        assert_eq!(parse_signal("SIGTERM").expect("term"), libc::SIGTERM);
        assert_eq!(
            parse_signal("term").expect("term without prefix"),
            libc::SIGTERM
        );
        assert_eq!(parse_signal("KILL").expect("kill"), libc::SIGKILL);
    }

    #[test]
    fn parses_numeric_signals() {
        assert_eq!(parse_signal("15").expect("number"), 15);
        assert!(parse_signal("0").is_err());
    }
}
