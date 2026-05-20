use serde_json::Value;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn has_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
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
        let child = Command::new(crun())
            .args([
                "run",
                "--net",
                "none",
                "--security",
                "unconfined",
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

#[test]
#[ignore = "requires root"]
fn run_state_delete_smoke() {
    if !require_root() {
        return;
    }

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
fn stats_events_health_and_logs_work() {
    if !require_root() {
        return;
    }

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
#[ignore = "requires root and an interactive tty"]
fn tty_run_works_when_terminal_is_available() {
    if !require_root() {
        return;
    }
    if !has_tty() {
        eprintln!("skipping tty test: stdin/stdout are not a tty");
        return;
    }

    let id = unique_name("root-tty");
    let bundle = TestBundle::new("bundle-tty", &["/bin/sh", "-c", "echo tty-ok"], "")
        .expect("bundle should be created");
    let output = run_crun(&[
        "run",
        "-t",
        "--net",
        "none",
        "--security",
        "unconfined",
        &id,
        bundle.path.to_str().expect("bundle path should be utf8"),
    ]);
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("tty-ok"));
    assert_success(&run_crun(&["delete", &id]));
}
