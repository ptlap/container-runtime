use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContainerError {
    #[error("process args is empty")]
    EmptyProcessArgs,

    #[error("exec args is empty")]
    EmptyExecArgs,

    #[error("missing required process config field: {field}")]
    MissingProcessConfigField { field: &'static str },

    #[error("pty slave is closed")]
    PtySlaveClosed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OciConfigError {
    #[error("process.args must not be empty")]
    EmptyProcessArgs,

    #[error("root.path must not be empty")]
    EmptyRootPath,

    #[error("mount.destination must not be empty")]
    EmptyMountDestination,

    #[error("unsupported mount type: {mount_type}")]
    UnsupportedMountType { mount_type: String },

    #[error("bind mount source must not be empty")]
    EmptyBindMountSource,

    #[error("healthcheck.test must not be empty")]
    EmptyHealthcheckTest,

    #[error("process.rlimits {rlimit_type} soft limit must not exceed hard limit")]
    RlimitSoftExceedsHard { rlimit_type: String },

    #[error("unsupported process.rlimits type: {rlimit_type}")]
    UnsupportedRlimit { rlimit_type: String },

    #[error("crun.overlay.{field} must not be empty")]
    EmptyOverlayPath { field: &'static str },

    #[error("unsupported crun.profile: {profile}")]
    UnsupportedCrunProfile { profile: String },

    #[error("linux masked/readonly path must be absolute: {path}")]
    LinuxPathNotAbsolute { path: String },

    #[error("linux masked/readonly path must not escape root: {path}")]
    LinuxPathEscapesRoot { path: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CgroupError {
    #[error("memory_limit must be greater than zero, got {value}")]
    InvalidMemoryLimit { value: i64 },

    #[error("pids_limit must be greater than zero, got {value}")]
    InvalidPidsLimit { value: i64 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HealthcheckError {
    #[error("healthcheck.test must not be empty")]
    EmptyTest,

    #[error("healthcheck is disabled")]
    Disabled,

    #[error("healthcheck {kind} must include a command")]
    MissingCommand { kind: &'static str },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    #[error("container id must not be empty")]
    EmptyContainerId,

    #[error("container id may only contain ASCII letters, numbers, '.', '_' and '-'")]
    InvalidContainerId,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkError {
    #[error("no bridge subnets available in 10.88.{start}.0/24..10.88.{end}.0/24")]
    NoBridgeSubnetsAvailable { start: u8, end: u8 },

    #[error("{program} command failed: {args}")]
    CommandFailed { program: &'static str, args: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModeError {
    #[error("invalid network mode in state: {value}")]
    InvalidNetworkMode { value: String },

    #[error("invalid security profile in state: {value}")]
    InvalidSecurityProfile { value: String },

    #[error("invalid log mode in state: {value}")]
    InvalidLogMode { value: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("unsupported crun.profile: {value}")]
    UnsupportedProfile { value: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FilesystemError {
    #[error("mount destination must be absolute: {path}")]
    MountDestinationNotAbsolute { path: String },

    #[error("mount destination must not escape rootfs: {path}")]
    MountDestinationEscapesRootfs { path: String },

    #[error("mount destination contains unsupported prefix: {path}")]
    MountDestinationUnsupportedPrefix { path: String },

    #[error("mount destination must not be container root")]
    MountDestinationIsContainerRoot,

    #[error("bind mount source is required")]
    MissingBindMountSource,

    #[error("bind mount destination exists but is not a directory: {path}")]
    BindDestinationNotDirectory { path: String },

    #[error("bind mount destination exists but is a directory: {path}")]
    BindDestinationIsDirectory { path: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignalError {
    #[error("signal number must be positive: {value}")]
    NonPositiveSignal { value: String },

    #[error("unsupported signal: {value}")]
    UnsupportedSignal { value: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImageError {
    #[error("image name must not be empty")]
    EmptyImageName,

    #[error("image name may only contain ASCII letters, numbers, '.', '_' and '-'")]
    InvalidImageName,

    #[error("image not found: {name}")]
    ImageNotFound { name: String },

    #[error("image rootfs not found: {path}")]
    ImageRootfsNotFound { path: String },

    #[error("rootfs tar does not exist: {path}")]
    RootfsTarDoesNotExist { path: String },

    #[error("image already exists: {name}")]
    ImageAlreadyExists { name: String },

    #[error("tar extraction failed: {stderr}")]
    TarExtractionFailed { stderr: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointError {
    #[error("container {id} is not running")]
    ContainerNotRunning { id: String },

    #[error("running container state has no pid")]
    ContainerHasNoPid,

    #[error("criu is not available: {reason}")]
    CriuNotAvailable { reason: String },

    #[error("checkpoint image directory already exists: {path}")]
    ImageDirectoryAlreadyExists { path: String },

    #[error("checkpoint image directory does not exist: {path}")]
    ImageDirectoryDoesNotExist { path: String },

    #[error("empty CRIU command")]
    EmptyCriuCommand,

    #[error("CRIU command {command} failed: {stderr}")]
    CriuCommandFailed { command: String, stderr: String },
}
