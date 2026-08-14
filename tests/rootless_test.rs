use std::process::Command;

#[test]
fn test_cli_help() {
    let mut cmd = Command::new("target/debug/minicrun");
    cmd.arg("--help");
    let output = cmd.output().expect("failed to run minicrun");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("minicrun"));
}

#[test]
fn test_cli_invalid_command() {
    let mut cmd = Command::new("target/debug/minicrun");
    cmd.arg("invalid-command-xyz");
    let output = cmd.output().expect("failed to run minicrun");
    assert!(!output.status.success());
}

#[test]
fn test_cli_log_args() {
    let mut cmd = Command::new("target/debug/minicrun");
    cmd.arg("--log-level")
        .arg("debug")
        .arg("--log-format")
        .arg("json")
        .arg("state")
        .arg("non-existent-container");
    let output = cmd.output().expect("failed to run minicrun");
    assert!(!output.status.success());
}

/// The seccomp analysis commands are pure file processing, so they give real
/// coverage of the compiler and the comparison maths without needing root.
mod seccomp_cli {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    fn minicrun() -> PathBuf {
        std::env::var_os("CARGO_BIN_EXE_minicrun")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/minicrun"))
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("crun-cli-{}-{name}", std::process::id()))
    }

    fn run(args: &[&str]) -> Output {
        Command::new(minicrun())
            .args(args)
            .output()
            .expect("failed to execute minicrun")
    }

    fn write_capture(path: &Path) {
        let audit_arch = if cfg!(target_arch = "x86_64") {
            0xc000_003eu32
        } else {
            0xc000_00b7u32
        };
        std::fs::write(
            path,
            format!(
                r#"{{
  "schemaVersion": 1,
  "id": "cli-test",
  "command": ["/bin/sh"],
  "arch": "test",
  "auditArch": {audit_arch},
  "runtimeVersion": "0.1.0",
  "startedAtUnix": 1700000000,
  "durationMs": 10,
  "totalEvents": 6,
  "processesSeen": 1,
  "syscalls": {{ "read": 3, "write": 2, "execve": 1 }},
  "firstSeenMs": {{ "read": 1, "write": 2, "execve": 0 }}
}}"#
            ),
        )
        .expect("capture should write");
    }

    #[test]
    fn generates_inspects_and_compares_a_profile() {
        let capture = temp_path("capture.json");
        let profile = temp_path("profile.json");
        write_capture(&capture);

        let generated = run(&[
            "seccomp",
            "generate",
            "--capture",
            capture.to_str().expect("path is utf8"),
            "-o",
            profile.to_str().expect("path is utf8"),
            "--name",
            "cli-test",
            "--json",
        ]);
        assert!(
            generated.status.success(),
            "generate failed: {}",
            String::from_utf8_lossy(&generated.stderr)
        );

        let inspected = run(&[
            "seccomp",
            "inspect",
            profile.to_str().expect("path is utf8"),
            "--json",
        ]);
        assert!(inspected.status.success());
        let report: serde_json::Value =
            serde_json::from_slice(&inspected.stdout).expect("inspect should emit json");
        assert_eq!(report["workload"], "cli-test");
        assert!(report["allowed"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "read")));

        let baseline = repo_root().join("third_party/moby-profiles/seccomp/default.json");
        if baseline.exists() {
            let compared = run(&[
                "seccomp",
                "compare",
                profile.to_str().expect("path is utf8"),
                "--baseline",
                baseline.to_str().expect("path is utf8"),
                "--json",
            ]);
            assert!(compared.status.success());
            let report: serde_json::Value =
                serde_json::from_slice(&compared.stdout).expect("compare should emit json");
            let reduction = report["reduction_vs_baseline"]
                .as_f64()
                .expect("a baseline comparison reports a reduction");
            assert!(
                reduction > 0.5,
                "a three syscall profile should be far smaller than the Docker baseline"
            );
            assert_eq!(
                report["over_allowed"].as_array().map(Vec::len),
                Some(0),
                "the learned syscalls are all in the Docker baseline"
            );
        }

        let _ = std::fs::remove_file(&capture);
        let _ = std::fs::remove_file(&profile);
    }

    #[test]
    fn rejects_enforce_without_a_profile() {
        let output = run(&["run", "--seccomp", "enforce", "demo", "/tmp"]);

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--seccomp-profile"));
    }

    #[test]
    fn rejects_a_capture_path_outside_learn_mode() {
        let output = run(&["run", "--seccomp-out", "/tmp/out.json", "demo", "/tmp"]);

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--seccomp-out"));
    }
}
