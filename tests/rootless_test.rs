use std::process::Command;

#[test]
fn test_cli_help() {
    let mut cmd = Command::new("target/debug/crun");
    cmd.arg("--help");
    let output = cmd.output().expect("failed to run crun");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("crun"));
}

#[test]
fn test_cli_invalid_command() {
    let mut cmd = Command::new("target/debug/crun");
    cmd.arg("invalid-command-xyz");
    let output = cmd.output().expect("failed to run crun");
    assert!(!output.status.success());
}

#[test]
fn test_cli_log_args() {
    let mut cmd = Command::new("target/debug/crun");
    cmd.arg("--log-level")
        .arg("debug")
        .arg("--log-format")
        .arg("json")
        .arg("state")
        .arg("non-existent-container");
    let output = cmd.output().expect("failed to run crun");
    assert!(!output.status.success());
}
