use crate::modes::LogMode;

pub fn process_exit_status(code: Option<i32>, signal: Option<&str>) -> i32 {
    match (code, signal) {
        (Some(code), _) if (0..=255).contains(&code) => code,
        (Some(code), _) if code < 0 => 1,
        (Some(_), _) => 255,
        (None, Some(_)) => 128,
        (None, None) => 1,
    }
}

pub fn should_capture_logs(log_mode: LogMode, stdin_is_terminal: bool) -> bool {
    match log_mode {
        LogMode::Auto => !stdin_is_terminal,
        LogMode::On => true,
        LogMode::Off => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_process_exit_code_to_cli_status() {
        assert_eq!(process_exit_status(Some(0), None), 0);
        assert_eq!(process_exit_status(Some(42), None), 42);
    }

    #[test]
    fn clamps_process_exit_code_to_shell_range() {
        assert_eq!(process_exit_status(Some(300), None), 255);
        assert_eq!(process_exit_status(Some(-1), None), 1);
    }

    #[test]
    fn maps_signal_and_missing_status_to_nonzero_cli_status() {
        assert_eq!(process_exit_status(None, Some("SIGKILL")), 128);
        assert_eq!(process_exit_status(None, None), 1);
    }

    #[test]
    fn decides_log_capture_from_mode_and_terminal_state() {
        assert!(!should_capture_logs(LogMode::Auto, true));
        assert!(should_capture_logs(LogMode::Auto, false));
        assert!(should_capture_logs(LogMode::On, true));
        assert!(should_capture_logs(LogMode::On, false));
        assert!(!should_capture_logs(LogMode::Off, true));
        assert!(!should_capture_logs(LogMode::Off, false));
    }
}
