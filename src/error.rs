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

    #[error("execve returned unexpectedly")]
    ExecveReturned,

    #[error("log helper exited with code: {code}")]
    LogHelperExited { code: i32 },

    #[error("log helper killed by signal: {signal}")]
    LogHelperKilled { signal: String },

    #[error("log helper ended with status: {status}")]
    LogHelperStatus { status: String },

    #[error("failed to write fd: wrote zero bytes")]
    WriteZeroBytes,

    #[error("child exited before user namespace was ready")]
    ChildExitedBeforeUsernsReady,

    #[error("parent exited before user namespace was mapped")]
    ParentExitedBeforeUsernsMapped,

    #[error("failed to set controlling terminal")]
    FailedToSetControllingTerminal,

    #[error("failed to dup slave to stdin")]
    FailedToDupSlaveToStdin,

    #[error("failed to dup slave to stdout")]
    FailedToDupSlaveToStdout,

    #[error("failed to dup slave to stderr")]
    FailedToDupSlaveToStderr,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProcessIdentityError {
    #[error("process {pid} identity token is missing")]
    MissingToken { pid: i32 },

    #[error("process {pid} identity no longer matches the recorded process")]
    Reused { pid: i32 },

    #[error("failed to open pidfd for process {pid}: {errno}")]
    PidfdOpen { pid: i32, errno: String },

    #[error("failed to signal process {pid} through pidfd: {errno}")]
    PidfdSignal { pid: i32, errno: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("container id already exists: {id}")]
    ContainerAlreadyExists { id: String },

    #[error("container {id} is not created")]
    ContainerNotCreated { id: String },

    #[error("container child failed: {error}")]
    ChildFailed { error: String },

    #[error("container {id} is not running")]
    ContainerNotRunning { id: String },

    #[error("container {id} has no pid")]
    ContainerHasNoPid { id: String },

    #[error("container {id} has no process identity token")]
    ContainerHasNoProcessIdentity { id: String },

    #[error("container {id} did not stop after SIGKILL")]
    StopDidNotComplete { id: String },
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

    #[error("unsupported Linux namespace type: {namespace_type}")]
    UnsupportedNamespace { namespace_type: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CgroupError {
    #[error("memory_limit must be greater than zero, got {value}")]
    InvalidMemoryLimit { value: i64 },

    #[error("pids_limit must be greater than zero, got {value}")]
    InvalidPidsLimit { value: i64 },

    #[error("cpu_quota must be greater than zero, got {value}")]
    InvalidCpuQuota { value: i64 },

    #[error("cpu_period must be greater than zero, got {value}")]
    InvalidCpuPeriod { value: u64 },

    #[error("container {id} is not running")]
    ContainerNotRunning { id: String },

    #[error("container {id} has no cgroup path")]
    ContainerHasNoPath { id: String },

    #[error("cgroup path does not exist: {path}")]
    PathDoesNotExist { path: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HealthcheckError {
    #[error("healthcheck.test must not be empty")]
    EmptyTest,

    #[error("healthcheck is disabled")]
    Disabled,

    #[error("healthcheck {kind} must include a command")]
    MissingCommand { kind: &'static str },

    #[error("healthcheck timeout is invalid: {value}")]
    InvalidTimeout { value: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HealthRunError {
    #[error("health interval must be greater than zero")]
    InvalidInterval,

    #[error("container {id} is not running")]
    ContainerNotRunning { id: String },

    #[error("container {id} has no pid")]
    ContainerHasNoPid { id: String },

    #[error("container has no healthcheck configured")]
    NoHealthcheckConfigured,

    #[error("healthcheck did not run")]
    HealthcheckDidNotRun,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EventError {
    #[error("events interval must be greater than zero")]
    InvalidInterval,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    #[error("container id must not be empty")]
    EmptyContainerId,

    #[error("container id may only contain ASCII letters, numbers, '.', '_' and '-'")]
    InvalidContainerId,

    #[error("container {id} is running; stop it before delete")]
    ContainerIsRunning { id: String },

    #[error("failed to lock state for container {id}: {errno}")]
    LockFailed { id: String, errno: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkError {
    #[error("no bridge subnets available in 10.88.{start}.0/24..10.88.{end}.0/24")]
    NoBridgeSubnetsAvailable { start: u8, end: u8 },

    #[error("{program} command failed: {args}")]
    CommandFailed { program: &'static str, args: String },

    #[error("timed out waiting for network allocation lock")]
    LockTimeout,
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

    #[error("overlay lowerdir does not exist: {path}")]
    OverlayLowerdirDoesNotExist { path: String },

    #[error("overlay upperdir does not exist: {path}")]
    OverlayUpperdirDoesNotExist { path: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SeccompError {
    #[error("seccomp filter must not be empty")]
    EmptyProgram,

    #[error("seccomp filter has {length} instructions, limit is {limit}")]
    ProgramTooLong { length: usize, limit: usize },

    #[error("seccomp filter must end in a return instruction")]
    ProgramDoesNotEndInReturn,

    #[error("seccomp filter jump at {index} targets {target}, past the end of the program")]
    JumpOutOfRange { index: usize, target: usize },

    #[error("seccomp is not supported on this architecture")]
    UnsupportedArchitecture,

    #[error("syscall number does not fit a seccomp comparison: {number}")]
    InvalidSyscallNumber { number: i64 },

    #[error("no syscall captures to merge")]
    NoCaptures,

    #[error("cannot merge captures from different architectures: {expected:#x} and {found:#x}")]
    ArchMismatch { expected: u32, found: u32 },

    #[error("--seccomp enforce requires --seccomp-profile")]
    MissingProfilePath,

    #[error("--seccomp-profile only applies to --seccomp enforce")]
    ProfileWithoutEnforce,

    #[error("--seccomp-out only applies to --seccomp learn")]
    CaptureWithoutLearn,

    #[error("invalid seccomp mode: {value}")]
    InvalidMode { value: String },

    #[error("invalid seccomp action: {value}")]
    InvalidAction { value: String },

    #[error("invalid syscall order: {value}")]
    InvalidOrder { value: String },

    #[error("unsupported conditional seccomp rule for syscall(s): {syscalls}")]
    UnsupportedConditionalRule { syscalls: String },
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecurityError {
    #[error("seccomp is not supported on this host CPU architecture")]
    UnsupportedArchitecture,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InspectSecurityError {
    #[error("container {id} is not running")]
    ContainerNotRunning { id: String },

    #[error("container {id} has no pid")]
    ContainerHasNoPid { id: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TraceError {
    #[error("container {id} is not running")]
    ContainerNotRunning { id: String },

    #[error("running container state has no pid")]
    ContainerHasNoPid,
}
