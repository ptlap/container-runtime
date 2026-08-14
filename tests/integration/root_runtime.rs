use serde_json::Value;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static ROOT_RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());

fn crun() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_crun")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/crun"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn require_root() -> bool {
    if is_root() {
        true
    } else {
        eprintln!("skipping root runtime test: requires root");
        false
    }
}

fn root_runtime_test_lock() -> MutexGuard<'static, ()> {
    ROOT_RUNTIME_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn has_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn unique_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn run_crun(args: &[&str]) -> Output {
    Command::new(crun())
        .args(args)
        .output()
        .expect("failed to execute crun")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "failed to parse stdout as json: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

struct TestBundle {
    path: PathBuf,
}

impl TestBundle {
    fn new(name: &str, process_args: &[&str], extra_json: &str) -> io::Result<Self> {
        let path = std::env::temp_dir().join(unique_name(name));
        fs::create_dir_all(&path)?;
        symlink(
            repo_root().join("examples/bundle/rootfs"),
            path.join("rootfs"),
        )?;
        fs::write(
            path.join("config.json"),
            bundle_config(process_args, extra_json),
        )?;
        Ok(Self { path })
    }
}

impl Drop for TestBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn bundle_config(process_args: &[&str], extra_json: &str) -> String {
    let args = process_args
        .iter()
        .map(|arg| serde_json::to_string(arg).expect("arg should serialize"))
        .collect::<Vec<_>>()
        .join(", ");
    let extra = if extra_json.trim().is_empty() {
        String::new()
    } else {
        format!(",\n{extra_json}")
    };

    format!(
        r#"{{
  "ociVersion": "1.0.2",
  "process": {{
    "args": [{args}],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/"
  }},
  "root": {{ "path": "rootfs", "readonly": false }},
  "linux": {{
    "namespaces": [
      {{ "type": "pid" }},
      {{ "type": "mount" }},
      {{ "type": "uts" }},
      {{ "type": "ipc" }},
      {{ "type": "network" }}
    ],
    "resources": {{
      "memory": {{ "limit": 268435456 }},
      "pids": {{ "limit": 64 }}
    }}
  }}{extra}
}}
"#
    )
}

struct RunningContainer {
    id: String,
    child: Child,
}

impl RunningContainer {
    fn start(id: String, bundle: &Path) -> Self {
        Self::start_with_security(id, bundle, "unconfined")
    }

    fn start_with_security(id: String, bundle: &Path, security: &str) -> Self {
        let child = Command::new(crun())
            .args([
                "run",
                "--net",
                "none",
                "--security",
                security,
                "--log",
                "on",
                id.as_str(),
            ])
            .arg(bundle)
            .spawn()
            .expect("failed to start crun run");

        wait_until_running(&id);
        Self { id, child }
    }
}

impl Drop for RunningContainer {
    fn drop(&mut self) {
        let _ = run_crun(&["stop", &self.id, "--timeout", "1"]);
        let _ = self.child.wait();
        let _ = run_crun(&["delete", &self.id]);
    }
}

fn wait_until_running(id: &str) {
    for _ in 0..50 {
        let output = run_crun(&["state", id, "--json"]);
        if output.status.success() {
            let state = json_stdout(&output);
            if state["status"] == "running" {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("container {id} did not become running");
}

/// Removes a temporary file when the test ends, however it ends.
struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(name: &str) -> Self {
        Self {
            path: std::env::temp_dir().join(unique_name(name)),
        }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn learn_capture(id: &str, bundle: &Path, capture: &Path, args_note: &str) -> Output {
    let output = Command::new(crun())
        .args([
            "run",
            "--net",
            "none",
            "--security",
            "unconfined",
            "--log",
            "on",
            "--seccomp",
            "learn",
            "--seccomp-out",
        ])
        .arg(capture)
        .arg(id)
        .arg(bundle)
        .output()
        .unwrap_or_else(|error| panic!("failed to run crun for {args_note}: {error}"));
    assert_success(&output);
    output
}

#[test]
#[ignore = "requires root"]
fn learn_mode_captures_the_syscalls_a_container_makes() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-learn");
    let bundle = TestBundle::new("bundle-learn", &["/bin/sh", "-c", "echo learning"], "")
        .expect("bundle should be created");
    let capture = TempFile::new("capture.json");

    learn_capture(&id, &bundle.path, &capture.path, "learn mode");
    assert_success(&run_crun(&["delete", &id]));

    let content = fs::read_to_string(&capture.path).expect("capture should be written");
    let capture: Value = serde_json::from_str(&content).expect("capture should be json");

    assert!(capture["totalEvents"].as_u64().unwrap_or(0) > 0);
    assert!(
        capture["syscalls"]["execve"].as_u64().unwrap_or(0) >= 1,
        "the exec of the container process must be observed: {capture}"
    );
    assert!(
        capture["syscalls"]
            .as_object()
            .is_some_and(|map| map.len() > 5),
        "a shell should use more than a handful of syscalls: {capture}"
    );
}

#[test]
#[ignore = "requires root"]
fn learn_mode_follows_child_processes() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-learn-fork");
    let bundle = TestBundle::new(
        "bundle-learn-fork",
        &["/bin/sh", "-c", "(/bin/true) & wait"],
        "",
    )
    .expect("bundle should be created");
    let capture = TempFile::new("capture-fork.json");

    learn_capture(&id, &bundle.path, &capture.path, "forking workload");
    assert_success(&run_crun(&["delete", &id]));

    let content = fs::read_to_string(&capture.path).expect("capture should be written");
    let capture: Value = serde_json::from_str(&content).expect("capture should be json");

    assert!(
        capture["processesSeen"].as_u64().unwrap_or(0) >= 2,
        "the forked child must be traced too: {capture}"
    );
}

#[test]
#[ignore = "requires root"]
fn learn_mode_still_captures_container_logs() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    // Regression test for the tracer owning waitpid(-1): it reaps the log
    // helper too, and the exit status has to be handed back rather than lost.
    let id = unique_name("root-learn-log");
    let bundle = TestBundle::new(
        "bundle-learn-log",
        &["/bin/sh", "-c", "echo log-through-learn"],
        "",
    )
    .expect("bundle should be created");
    let capture = TempFile::new("capture-log.json");

    learn_capture(&id, &bundle.path, &capture.path, "log capture");

    let logs = run_crun(&["logs", &id]);
    assert_success(&logs);
    assert!(
        String::from_utf8_lossy(&logs.stdout).contains("log-through-learn"),
        "container output must survive learn mode"
    );
    assert_success(&run_crun(&["delete", &id]));
}

#[test]
#[ignore = "requires root"]
fn a_generated_profile_runs_the_workload_it_was_learned_from() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let learn_id = unique_name("root-gen-learn");
    let bundle = TestBundle::new("bundle-gen", &["/bin/sh", "-c", "echo generated"], "")
        .expect("bundle should be created");
    let capture = TempFile::new("capture-gen.json");
    let profile = TempFile::new("profile-gen.json");

    learn_capture(&learn_id, &bundle.path, &capture.path, "profile generation");
    assert_success(&run_crun(&["delete", &learn_id]));

    let generate = Command::new(crun())
        .arg("seccomp")
        .arg("generate")
        .arg("--capture")
        .arg(&capture.path)
        .arg("-o")
        .arg(&profile.path)
        .arg("--name")
        .arg("shell")
        .output()
        .expect("failed to run crun seccomp generate");
    assert_success(&generate);

    let content = fs::read_to_string(&profile.path).expect("profile should be written");
    let parsed: Value = serde_json::from_str(&content).expect("profile should be json");
    assert_eq!(parsed["defaultAction"], "SCMP_ACT_ERRNO");
    assert!(parsed["syscalls"][0]["names"]
        .as_array()
        .is_some_and(|names| !names.is_empty()));

    let enforce_id = unique_name("root-gen-enforce");
    let enforced = Command::new(crun())
        .args([
            "run",
            "--net",
            "none",
            "--security",
            "unconfined",
            "--log",
            "on",
            "--seccomp",
            "enforce",
            "--seccomp-profile",
        ])
        .arg(&profile.path)
        .arg(&enforce_id)
        .arg(&bundle.path)
        .output()
        .expect("failed to run the enforced container");
    assert_success(&enforced);

    let logs = run_crun(&["logs", &enforce_id]);
    assert_success(&logs);
    assert!(
        String::from_utf8_lossy(&logs.stdout).contains("generated"),
        "the workload must still run under its own profile"
    );
    assert_success(&run_crun(&["delete", &enforce_id]));
}

#[test]
#[ignore = "requires root"]
fn an_enforced_profile_denies_a_syscall_it_never_learned() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    // Learned from a trivial command, then used to run one that needs chmod.
    let learn_id = unique_name("root-deny-learn");
    let learn_bundle =
        TestBundle::new("bundle-deny-learn", &["/bin/true"], "").expect("bundle should be created");
    let capture = TempFile::new("capture-deny.json");
    let profile = TempFile::new("profile-deny.json");

    learn_capture(&learn_id, &learn_bundle.path, &capture.path, "denial");
    assert_success(&run_crun(&["delete", &learn_id]));

    let generate = Command::new(crun())
        .arg("seccomp")
        .arg("generate")
        .arg("--capture")
        .arg(&capture.path)
        .arg("-o")
        .arg(&profile.path)
        .output()
        .expect("failed to run crun seccomp generate");
    assert_success(&generate);

    let deny_id = unique_name("root-deny-run");
    let deny_bundle = TestBundle::new(
        "bundle-deny-run",
        &["/bin/sh", "-c", "chmod 0777 /tmp || echo denied"],
        "",
    )
    .expect("bundle should be created");

    let output = Command::new(crun())
        .args([
            "run",
            "--net",
            "none",
            "--security",
            "unconfined",
            "--log",
            "on",
            "--seccomp",
            "enforce",
            "--seccomp-profile",
        ])
        .arg(&profile.path)
        .arg(&deny_id)
        .arg(&deny_bundle.path)
        .output()
        .expect("failed to run the enforced container");

    let logs = run_crun(&["logs", &deny_id]);
    let logs = String::from_utf8_lossy(&logs.stdout).to_string();
    let _ = run_crun(&["delete", &deny_id]);

    assert!(
        logs.contains("denied") || !output.status.success(),
        "a syscall outside the profile must be refused; logs: {logs}"
    );
}

#[test]
#[ignore = "requires root"]
fn container_env_is_not_inherited_from_host() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-env");
    let bundle = TestBundle::new("bundle-env", &["/bin/sh", "-c", "env"], "")
        .expect("bundle should be created");

    let output = Command::new(crun())
        .args([
            "run",
            "--net",
            "none",
            "--security",
            "unconfined",
            "--log",
            "on",
            id.as_str(),
        ])
        .arg(&bundle.path)
        .env("CRUN_TEST_LEAK", "leaked-from-host")
        .output()
        .expect("failed to run crun");
    assert_success(&output);

    let logs = run_crun(&["logs", &id]);
    assert_success(&logs);
    let logs = String::from_utf8_lossy(&logs.stdout);

    assert!(
        !logs.contains("CRUN_TEST_LEAK"),
        "host environment leaked into the container: {logs}"
    );
    assert!(
        logs.contains("PATH=/usr/local/sbin"),
        "container is missing the bundle environment: {logs}"
    );

    assert_success(&run_crun(&["delete", &id]));
}

#[test]
#[ignore = "requires root"]
fn private_userns_accepts_explicit_root_credentials() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-private-userns");
    let bundle = TestBundle::new("bundle-private-userns", &["/bin/sh", "-c", "id -u"], "")
        .expect("bundle should be created");
    let config_path = bundle.path.join("config.json");
    let mut config: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("config should be readable"))
            .expect("config should be JSON");
    config["process"]["user"] = serde_json::json!({
        "uid": 0,
        "gid": 0,
        "additionalGids": []
    });
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&config).expect("config should serialize"),
    )
    .expect("config should be written");

    let output = Command::new(crun())
        .args([
            "run",
            "--net",
            "none",
            "--security",
            "default",
            "--userns",
            "private",
            "--log",
            "off",
            id.as_str(),
        ])
        .arg(&bundle.path)
        .output()
        .expect("failed to run private userns container");
    assert_success(&output);
}

#[test]
#[ignore = "requires root"]
fn denylist_run_applies_base_security_profile() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-denylist-run");
    let bundle = TestBundle::new(
        "bundle-denylist-run",
        &[
            "/bin/sh",
            "-c",
            "grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status && ! mount -t tmpfs tmpfs /tmp",
        ],
        "",
    )
    .expect("bundle should be created");

    let output = run_crun(&[
        "run",
        "--net",
        "none",
        "--security",
        "denylist",
        "--log",
        "on",
        &id,
        bundle.path.to_str().expect("bundle path should be utf8"),
    ]);
    assert_success(&output);
    assert_success(&run_crun(&["delete", &id]));
}

#[test]
#[ignore = "requires root"]
fn exec_preserves_uid_capability_drop_and_default_seccomp() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-exec-security");
    let bundle = TestBundle::new("bundle-exec-security", &["/bin/sh", "-c", "sleep 60"], "")
        .expect("bundle should be created");
    let config_path = bundle.path.join("config.json");
    let mut config: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("config should be readable"))
            .expect("config should be JSON");
    config["process"]["user"] = serde_json::json!({"uid": 1000, "gid": 1000});
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&config).expect("config should serialize"),
    )
    .expect("config should be written");

    let _running = RunningContainer::start_with_security(id.clone(), &bundle.path, "default");
    let exec = run_crun(&[
        "exec",
        &id,
        "/bin/sh",
        "-c",
        "test \"$(id -u)\" = 1000 && grep -Eq '^CapEff:\\s+0+$' /proc/self/status && ! mount -t tmpfs tmpfs /tmp",
    ]);
    assert_success(&exec);
    assert!(
        String::from_utf8_lossy(&exec.stdout).contains("exec process exited with code: 0"),
        "exec should complete successfully: stdout={} stderr={}",
        String::from_utf8_lossy(&exec.stdout),
        String::from_utf8_lossy(&exec.stderr)
    );
}

#[test]
#[ignore = "requires root"]
fn run_state_delete_smoke() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-run");
    let bundle = TestBundle::new("bundle-run", &["/bin/sh", "-c", "exit 0"], "")
        .expect("bundle should be created");

    assert_success(&run_crun(&[
        "run",
        "--net",
        "none",
        "--security",
        "unconfined",
        &id,
        bundle.path.to_str().expect("bundle path should be utf8"),
    ]));

    let state = run_crun(&["state", &id, "--json"]);
    assert_success(&state);
    let state = json_stdout(&state);
    assert_eq!(state["status"], "stopped");
    assert_success(&run_crun(&["delete", &id]));
}

#[test]
#[ignore = "requires root"]
fn healthcheck_keeps_base_denylist_security() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-health-denylist");
    let bundle = TestBundle::new(
        "bundle-health-denylist",
        &["/bin/sh", "-c", "sleep 60"],
        r#""healthcheck": {
    "test": ["CMD", "/bin/sh", "-c", "grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status && ! mount -t tmpfs tmpfs /tmp"],
    "timeout": "2s",
    "retries": 0
  }"#,
    )
    .expect("bundle should be created");
    let _running = RunningContainer::start_with_security(id.clone(), &bundle.path, "denylist");

    let health = run_crun(&["health", &id, "--json"]);
    assert_success(&health);
    let health = json_stdout(&health);
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["attempts"], 1);
}

#[test]
#[ignore = "requires root"]
fn stats_events_health_and_logs_work() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-observe");
    let bundle = TestBundle::new(
        "bundle-observe",
        &["/bin/sh", "-c", "echo log-ok; sleep 60"],
        r#""healthcheck": { "test": ["CMD", "/bin/sh", "-c", "test -f /etc/resolv.conf"], "retries": 1 }"#,
    )
    .expect("bundle should be created");
    let mut running = RunningContainer::start(id.clone(), &bundle.path);

    let stats = run_crun(&["stats", &id, "--json"]);
    assert_success(&stats);
    let stats = json_stdout(&stats);
    assert!(stats["memory"].is_object());
    assert!(stats["cpu"].is_object());
    assert!(stats["pids"].is_object());

    let events = run_crun(&["events", &id, "--snapshot", "--once", "--json"]);
    assert_success(&events);
    let event = json_stdout(&events);
    assert_eq!(event["source"], "cgroup");
    assert_eq!(event["name"], "snapshot");

    let health = run_crun(&["health", &id, "--json"]);
    assert_success(&health);
    let health = json_stdout(&health);
    assert_eq!(health["status"], "healthy");

    assert_success(&run_crun(&["stop", &id, "--timeout", "1"]));
    let _ = running.child.wait();

    let logs = run_crun(&["logs", &id]);
    assert_success(&logs);
    assert!(String::from_utf8_lossy(&logs.stdout).contains("log-ok"));

    assert_success(&run_crun(&["delete", &id]));
    std::mem::forget(running);
}

#[test]
#[ignore = "requires root"]
fn bind_mount_readonly_works() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-mount");
    let shared = std::env::temp_dir().join(unique_name("shared"));
    fs::create_dir_all(&shared).expect("shared dir should be created");
    fs::write(shared.join("message.txt"), "mounted-ok\n").expect("message should be written");
    let extra = format!(
        r#""mounts": [{{
    "destination": "/data",
    "source": {},
    "type": "bind",
    "options": ["rbind", "ro"]
  }}]"#,
        serde_json::to_string(shared.to_str().expect("shared path should be utf8"))
            .expect("source should serialize")
    );
    let bundle = TestBundle::new(
        "bundle-mount",
        &[
            "/bin/sh",
            "-c",
            "cat /data/message.txt && ! sh -c 'echo fail > /data/new.txt'",
        ],
        &extra,
    )
    .expect("bundle should be created");

    let output = run_crun(&[
        "run",
        "--net",
        "none",
        "--security",
        "unconfined",
        &id,
        bundle.path.to_str().expect("bundle path should be utf8"),
    ]);
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("mounted-ok"));
    assert_success(&run_crun(&["delete", &id]));
    let _ = fs::remove_dir_all(shared);
}

#[test]
#[ignore = "requires root"]
fn bind_mount_destination_symlink_cannot_escape_rootfs() {
    if !require_root() {
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-mount-symlink");
    let sentinel = std::env::temp_dir().join(unique_name("mount-sentinel"));
    fs::write(&sentinel, "must-remain-untouched\n").expect("sentinel should be written");
    let source = sentinel.to_str().expect("sentinel path should be utf8");
    let extra = format!(
        r#""mounts": [{{
    "destination": "/etc/escape",
    "source": {},
    "type": "bind",
    "options": ["bind"]
  }}]"#,
        serde_json::to_string(source).expect("sentinel path should serialize")
    );
    let bundle = TestBundle::new("bundle-mount-symlink", &["/bin/true"], &extra)
        .expect("bundle should be created");

    let rootfs = bundle.path.join("rootfs");
    fs::remove_file(&rootfs).expect("test rootfs symlink should be removed");
    fs::create_dir_all(rootfs.join("etc")).expect("test rootfs should be created");
    symlink(&sentinel, rootfs.join("etc/escape")).expect("destination symlink should be created");

    let output = run_crun(&[
        "run",
        "--net",
        "none",
        "--security",
        "unconfined",
        &id,
        bundle.path.to_str().expect("bundle path should be utf8"),
    ]);
    assert!(
        !output.status.success(),
        "a symlinked mount destination must be rejected\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&sentinel).expect("sentinel should remain readable"),
        "must-remain-untouched\n"
    );

    let _ = run_crun(&["delete", &id]);
    let _ = fs::remove_file(sentinel);
}

#[test]
#[ignore = "requires root and an interactive tty"]
fn tty_run_works_when_terminal_is_available() {
    if !require_root() {
        return;
    }
    if !has_tty() || !has_command("script") {
        eprintln!("skipping tty test: requires an interactive tty and script(1)");
        return;
    }
    let _guard = root_runtime_test_lock();

    let id = unique_name("root-tty");
    let bundle = TestBundle::new("bundle-tty", &["/bin/sh", "-c", "echo tty-ok"], "")
        .expect("bundle should be created");
    let output_path = std::env::temp_dir().join(unique_name("crun-tty"));
    let command = format!(
        "{} run -t --net none --security unconfined {} {}",
        crun().display(),
        id,
        bundle.path.display()
    );
    let output = Command::new("script")
        .args([
            "-qfec",
            &command,
            output_path.to_str().expect("output path should be utf8"),
        ])
        .output()
        .expect("failed to execute script");
    assert_success(&output);
    let tty_output = fs::read_to_string(&output_path).expect("tty output should be readable");
    assert!(tty_output.contains("tty-ok"));
    assert_success(&run_crun(&["delete", &id]));
    let _ = fs::remove_file(output_path);
}
