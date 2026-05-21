use crate::error::CheckpointError;
use crate::spec::config::load_config;
use crate::state::{self, ContainerStatus, DEFAULT_STATE_ROOT};
use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const EXPERIMENTAL_NOTE: &str =
    "experimental CRIU research mode; restored processes are not reattached to runtime state";

#[derive(Debug, Clone)]
pub struct CheckpointOptions {
    pub images_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RestoreOptions {
    pub images_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CriuStatus {
    pub available: bool,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CheckpointReport {
    pub id: String,
    pub pid: i32,
    pub images_dir: String,
    pub criu: CriuStatus,
    pub experimental: String,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RestoreReport {
    pub id: String,
    pub images_dir: String,
    pub criu: CriuStatus,
    pub experimental: String,
    pub command: Vec<String>,
}

pub fn checkpoint(id: &str, options: CheckpointOptions) -> Result<CheckpointReport> {
    let container_state = state::load_current(id)?;
    if container_state.status != ContainerStatus::Running {
        return Err(CheckpointError::ContainerNotRunning { id: id.to_string() }.into());
    }
    let pid = container_state
        .pid
        .ok_or(CheckpointError::ContainerHasNoPid)?;
    let criu = detect_criu();
    ensure_criu_available(&criu)?;

    let images_dir = options
        .images_dir
        .unwrap_or_else(|| default_checkpoint_dir(id));
    if images_dir.exists() {
        return Err(CheckpointError::ImageDirectoryAlreadyExists {
            path: images_dir.display().to_string(),
        }
        .into());
    }
    fs::create_dir_all(&images_dir).with_context(|| {
        format!(
            "failed to create checkpoint image directory: {}",
            images_dir.display()
        )
    })?;

    let command = checkpoint_command(pid, &images_dir);
    if let Err(error) =
        run_criu(&command).with_context(|| format!("failed to checkpoint container {id}"))
    {
        let _ = fs::remove_dir_all(&images_dir);
        return Err(error);
    }

    Ok(CheckpointReport {
        id: id.to_string(),
        pid,
        images_dir: images_dir.display().to_string(),
        criu,
        experimental: EXPERIMENTAL_NOTE.to_string(),
        command,
    })
}

pub fn restore(id: &str, options: RestoreOptions) -> Result<RestoreReport> {
    validate_checkpoint_id(id)?;
    let container_state = state::load_current(id).ok();
    let criu = detect_criu();
    ensure_criu_available(&criu)?;

    let images_dir = options
        .images_dir
        .unwrap_or_else(|| default_checkpoint_dir(id));
    if !images_dir.is_dir() {
        return Err(CheckpointError::ImageDirectoryDoesNotExist {
            path: images_dir.display().to_string(),
        }
        .into());
    }

    let rootfs = container_state
        .as_ref()
        .and_then(|state| restore_rootfs(state).ok());
    let command = restore_command(&images_dir, rootfs.as_deref());
    run_criu(&command).with_context(|| format!("failed to restore checkpoint for {id}"))?;

    Ok(RestoreReport {
        id: id.to_string(),
        images_dir: images_dir.display().to_string(),
        criu,
        experimental: EXPERIMENTAL_NOTE.to_string(),
        command,
    })
}

pub fn detect_criu() -> CriuStatus {
    match Command::new("criu")
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            CriuStatus {
                available: true,
                version: (!version.is_empty()).then_some(version),
                error: None,
            }
        }
        Ok(output) => {
            let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
            CriuStatus {
                available: false,
                version: None,
                error: Some(if error.is_empty() {
                    format!("criu --version exited with {}", output.status)
                } else {
                    error
                }),
            }
        }
        Err(error) => CriuStatus {
            available: false,
            version: None,
            error: Some(error.to_string()),
        },
    }
}

fn ensure_criu_available(status: &CriuStatus) -> std::result::Result<(), CheckpointError> {
    if status.available {
        return Ok(());
    }

    Err(CheckpointError::CriuNotAvailable {
        reason: status
            .error
            .as_deref()
            .unwrap_or("unknown error")
            .to_string(),
    })
}

fn run_criu(command: &[String]) -> Result<()> {
    let Some((program, args)) = command.split_first() else {
        return Err(CheckpointError::EmptyCriuCommand.into());
    };
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to execute {}", command.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CheckpointError::CriuCommandFailed {
            command: command.join(" "),
            stderr: stderr.trim().to_string(),
        }
        .into());
    }

    Ok(())
}

fn checkpoint_command(pid: i32, images_dir: &Path) -> Vec<String> {
    vec![
        "criu".to_string(),
        "dump".to_string(),
        "-t".to_string(),
        pid.to_string(),
        "-D".to_string(),
        images_dir.display().to_string(),
        "--shell-job".to_string(),
        "--tcp-established".to_string(),
        "--file-locks".to_string(),
        "--manage-cgroups=ignore".to_string(),
        "--skip-mnt".to_string(),
        "/sys".to_string(),
        "--skip-mnt".to_string(),
        "./sys".to_string(),
        "--leave-running".to_string(),
    ]
}

fn restore_command(images_dir: &Path, rootfs: Option<&Path>) -> Vec<String> {
    let mut command = vec![
        "criu".to_string(),
        "restore".to_string(),
        "-D".to_string(),
        images_dir.display().to_string(),
        "--shell-job".to_string(),
        "--tcp-established".to_string(),
        "--file-locks".to_string(),
        "--manage-cgroups=ignore".to_string(),
        "--mntns-compat-mode".to_string(),
        "--skip-mnt".to_string(),
        "/sys".to_string(),
        "--skip-mnt".to_string(),
        "./sys".to_string(),
        "-d".to_string(),
    ];

    if let Some(rootfs) = rootfs {
        command.push("--root".to_string());
        command.push(rootfs.display().to_string());
    }

    command
}

fn restore_rootfs(state: &state::ContainerState) -> Result<PathBuf> {
    let bundle = PathBuf::from(&state.bundle);
    let config = load_config(bundle.join("config.json"))?;
    let root_path = Path::new(&config.root.path);
    if root_path.is_absolute() {
        Ok(root_path.to_path_buf())
    } else {
        Ok(bundle.join(root_path))
    }
}

fn default_checkpoint_dir(id: &str) -> PathBuf {
    Path::new(DEFAULT_STATE_ROOT).join(id).join("checkpoint")
}

fn validate_checkpoint_id(id: &str) -> Result<()> {
    state::validate_id(id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StateError;

    #[test]
    fn builds_checkpoint_command_with_leave_running() {
        let command = checkpoint_command(42, Path::new("/run/crun-rs/demo/checkpoint"));

        assert_eq!(command[0], "criu");
        assert!(command.contains(&"dump".to_string()));
        assert!(command.contains(&"42".to_string()));
        assert!(command.contains(&"--manage-cgroups=ignore".to_string()));
        assert!(command.contains(&"/sys".to_string()));
        assert!(command.contains(&"./sys".to_string()));
        assert!(command.contains(&"--leave-running".to_string()));
    }

    #[test]
    fn builds_restore_command_detached() {
        let command = restore_command(
            Path::new("/run/crun-rs/demo/checkpoint"),
            Some(Path::new("/tmp/rootfs")),
        );

        assert_eq!(command[0], "criu");
        assert!(command.contains(&"restore".to_string()));
        assert!(command.contains(&"--mntns-compat-mode".to_string()));
        assert!(command.contains(&"--manage-cgroups=ignore".to_string()));
        assert!(command.contains(&"/sys".to_string()));
        assert!(command.contains(&"./sys".to_string()));
        assert!(command.contains(&"--root".to_string()));
        assert!(command.contains(&"/tmp/rootfs".to_string()));
        assert!(command.contains(&"-d".to_string()));
    }

    #[test]
    fn rejects_invalid_checkpoint_ids() {
        let empty = validate_checkpoint_id("").expect_err("empty id should be rejected");
        assert!(matches!(
            empty.downcast_ref::<StateError>(),
            Some(StateError::EmptyContainerId)
        ));

        let traversal =
            validate_checkpoint_id("../demo").expect_err("traversal id should be rejected");
        assert!(matches!(
            traversal.downcast_ref::<StateError>(),
            Some(StateError::InvalidContainerId)
        ));

        let slash = validate_checkpoint_id("demo/one").expect_err("slash id should be rejected");
        assert!(matches!(
            slash.downcast_ref::<StateError>(),
            Some(StateError::InvalidContainerId)
        ));

        assert!(validate_checkpoint_id("demo_01.2-3").is_ok());
    }

    #[test]
    fn ensure_criu_available_returns_err_when_unavailable() {
        let status = CriuStatus {
            available: false,
            version: None,
            error: Some("not found".to_string()),
        };
        let err = ensure_criu_available(&status).unwrap_err();
        assert_eq!(
            err,
            CheckpointError::CriuNotAvailable {
                reason: "not found".to_string()
            }
        );
    }
}
