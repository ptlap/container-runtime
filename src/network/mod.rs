use crate::command::{self, CommandError, EXTERNAL_COMMAND_TIMEOUT};
use crate::error::NetworkError;
use anyhow::{Context, Result};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;

const CONTAINER_IFACE: &str = "eth0";
const DEFAULT_NETWORK_STATE_ROOT: &str = "/run/crun-rs/network";
const BRIDGE_OCTET_START: u8 = 20;
const BRIDGE_OCTET_END: u8 = 219;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const STALE_LOCK_AFTER_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Host,
    None,
    Bridge,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::None => "none",
            Self::Bridge => "bridge",
        }
    }

    pub fn to_effective(self) -> Self {
        let is_root = nix::unistd::getuid().is_root();
        if !is_root && self == Self::Bridge {
            Self::None
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VethPair {
    pub host_name: String,
    pub peer_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeNetwork {
    pub veth: VethPair,
    pub subnet: String,
    pub host_cidr: String,
    pub container_cidr: String,
    pub gateway: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatLease {
    pub subnet: String,
    pub postrouting_owned: bool,
    pub forward_source_owned: bool,
    pub forward_destination_owned: bool,
    pub previous_ip_forward: Option<String>,
}

impl BridgeNetwork {
    pub fn for_pid(pid: i32) -> Self {
        let octet = bridge_octet(pid);
        Self::for_octet(VethPair::for_pid(pid), octet)
    }

    fn for_container_id(container_id: &str, octet: u8) -> Self {
        Self::for_octet(VethPair::for_container_id(container_id), octet)
    }

    fn for_octet(veth: VethPair, octet: u8) -> Self {
        Self {
            veth,
            subnet: format!("10.88.{octet}.0/24"),
            host_cidr: format!("10.88.{octet}.1/24"),
            container_cidr: format!("10.88.{octet}.2/24"),
            gateway: format!("10.88.{octet}.1"),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BridgeAllocations {
    containers: BTreeMap<String, u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AllocationLockOwner {
    owner_pid: u32,
    #[serde(default)]
    owner_starttime: Option<u64>,
    created_at_unix: u64,
}

struct AllocationLock {
    path: PathBuf,
}

impl Drop for AllocationLock {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            warn!(
                "failed to release network allocation lock {}: {error}",
                self.path.display()
            );
        }
    }
}

impl VethPair {
    pub fn for_pid(pid: i32) -> Self {
        Self {
            host_name: format!("vethh{pid}"),
            peer_name: format!("vethp{pid}"),
        }
    }

    pub fn for_container_id(container_id: &str) -> Self {
        let token = stable_veth_token(container_id);
        Self {
            host_name: format!("vethh{token}"),
            peer_name: format!("vethp{token}"),
        }
    }
}

fn stable_veth_token(container_id: &str) -> String {
    let mut hash = 2_166_136_261u32;
    for byte in container_id.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    format!("{hash:08x}")
}

fn bridge_octet(pid: i32) -> u8 {
    ((pid.unsigned_abs() % 200) + 20) as u8
}

pub fn allocate_bridge_network(container_id: &str, pid: i32) -> Result<BridgeNetwork> {
    allocate_bridge_network_from(Path::new(DEFAULT_NETWORK_STATE_ROOT), container_id, pid)
}

pub fn release_bridge_network(container_id: &str) -> Result<()> {
    release_bridge_network_from(Path::new(DEFAULT_NETWORK_STATE_ROOT), container_id)
}

fn allocate_bridge_network_from(
    root: &Path,
    container_id: &str,
    _pid: i32,
) -> Result<BridgeNetwork> {
    let _lock = acquire_allocation_lock(root)?;
    let mut allocations = read_allocations(root)?;

    if let Some(octet) = allocations.containers.get(container_id).copied() {
        return Ok(BridgeNetwork::for_container_id(container_id, octet));
    }

    let octet = next_free_bridge_octet(&allocations)?;
    allocations
        .containers
        .insert(container_id.to_string(), octet);
    save_allocations(root, &allocations)?;

    Ok(BridgeNetwork::for_container_id(container_id, octet))
}

fn release_bridge_network_from(root: &Path, container_id: &str) -> Result<()> {
    let _lock = acquire_allocation_lock(root)?;
    let mut allocations = read_allocations(root)?;
    allocations.containers.remove(container_id);
    save_allocations(root, &allocations)
}

fn next_free_bridge_octet(allocations: &BridgeAllocations) -> Result<u8> {
    for octet in BRIDGE_OCTET_START..=BRIDGE_OCTET_END {
        if !allocations.containers.values().any(|value| *value == octet) {
            return Ok(octet);
        }
    }

    Err(NetworkError::NoBridgeSubnetsAvailable {
        start: BRIDGE_OCTET_START,
        end: BRIDGE_OCTET_END,
    }
    .into())
}

fn read_allocations(root: &Path) -> Result<BridgeAllocations> {
    let path = allocations_file(root);
    match fs::read_to_string(&path) {
        Ok(content) => {
            serde_json::from_str(&content).context("failed to parse network allocations")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(BridgeAllocations::default())
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to read network allocations: {}", path.display())),
    }
}

fn save_allocations(root: &Path, allocations: &BridgeAllocations) -> Result<()> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create network state root: {}", root.display()))?;
    let content = serde_json::to_string_pretty(allocations)
        .context("failed to serialize network allocations")?;
    fs::write(allocations_file(root), format!("{content}\n"))
        .context("failed to write network allocations")
}

fn acquire_allocation_lock(root: &Path) -> Result<AllocationLock> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create network state root: {}", root.display()))?;

    let path = root.join("allocations.lock");
    let deadline = Instant::now() + LOCK_TIMEOUT;

    loop {
        match fs::create_dir(&path) {
            Ok(()) => {
                write_lock_owner(&path)?;
                return Ok(AllocationLock { path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                remove_stale_allocation_lock(&path)?;
                if Instant::now() >= deadline {
                    return Err(NetworkError::LockTimeout.into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to acquire network allocation lock: {}",
                        path.display()
                    )
                });
            }
        }
    }
}

fn write_lock_owner(path: &Path) -> Result<()> {
    let owner_pid = std::process::id();
    let owner = AllocationLockOwner {
        owner_pid,
        owner_starttime: crate::state::process_starttime(
            i32::try_from(owner_pid).unwrap_or(i32::MAX),
        )
        .ok(),
        created_at_unix: unix_timestamp()?,
    };
    let content = serde_json::to_string_pretty(&owner).context("failed to serialize lock owner")?;
    fs::write(lock_owner_file(path), format!("{content}\n")).with_context(|| {
        format!(
            "failed to write network allocation lock owner: {}",
            path.display()
        )
    })
}

fn remove_stale_allocation_lock(path: &Path) -> Result<()> {
    if !allocation_lock_is_stale(path)? {
        return Ok(());
    }

    fs::remove_dir_all(path).with_context(|| {
        format!(
            "failed to remove stale network allocation lock: {}",
            path.display()
        )
    })
}

fn allocation_lock_is_stale(path: &Path) -> Result<bool> {
    let owner = read_lock_owner(path)?;
    if owner.owner_pid == 0 {
        return Ok(true);
    }

    let current_starttime =
        crate::state::process_starttime(i32::try_from(owner.owner_pid).unwrap_or(i32::MAX)).ok();
    if let Some(expected) = owner.owner_starttime {
        return Ok(current_starttime != Some(expected));
    }
    if current_starttime.is_none() {
        return Ok(true);
    }

    let now = unix_timestamp()?;
    Ok(now.saturating_sub(owner.created_at_unix) > STALE_LOCK_AFTER_SECS)
}

fn read_lock_owner(path: &Path) -> Result<AllocationLockOwner> {
    let owner_path = lock_owner_file(path);
    match fs::read_to_string(&owner_path) {
        Ok(content) => {
            serde_json::from_str(&content).context("failed to parse network allocation lock owner")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AllocationLockOwner {
            owner_pid: 0,
            owner_starttime: None,
            created_at_unix: 0,
        }),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to read network allocation lock owner: {}",
                owner_path.display()
            )
        }),
    }
}

fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs())
}

fn allocations_file(root: &Path) -> PathBuf {
    root.join("allocations.json")
}

fn lock_owner_file(lock_path: &Path) -> PathBuf {
    lock_path.join("owner.json")
}

pub fn setup_loopback() -> Result<()> {
    run_ip(&["link", "set", "lo", "up"])
}

pub fn setup_veth_parent(child_pid: Pid, network: &BridgeNetwork) -> Result<()> {
    run_ip(&[
        "link",
        "add",
        &network.veth.host_name,
        "type",
        "veth",
        "peer",
        "name",
        &network.veth.peer_name,
    ])?;

    run_ip(&[
        "link",
        "set",
        &network.veth.peer_name,
        "netns",
        &child_pid.as_raw().to_string(),
    ])?;

    run_ip(&[
        "addr",
        "add",
        &network.host_cidr,
        "dev",
        &network.veth.host_name,
    ])?;
    run_ip(&["link", "set", &network.veth.host_name, "up"])?;

    Ok(())
}

pub fn setup_veth_child(network: &BridgeNetwork) -> Result<()> {
    run_ip(&[
        "link",
        "set",
        &network.veth.peer_name,
        "name",
        CONTAINER_IFACE,
    ])?;
    run_ip(&[
        "addr",
        "add",
        &network.container_cidr,
        "dev",
        CONTAINER_IFACE,
    ])?;
    run_ip(&["link", "set", CONTAINER_IFACE, "up"])?;
    run_ip(&["route", "add", "default", "via", &network.gateway])?;

    Ok(())
}

pub fn cleanup_veth_host(host_name: &str) -> Result<()> {
    if !link_exists(host_name)? {
        return Ok(());
    }

    run_ip_quiet(&["link", "delete", host_name])
}

fn link_exists(name: &str) -> Result<bool> {
    let mut command = Command::new("ip");
    command.args(["-o", "link", "show", name]);
    let description = format!("ip -o link show {name}");
    let output = command::output(command, description, EXTERNAL_COMMAND_TIMEOUT).map_err(
        |error| match error {
            CommandError::TimedOut { timeout_ms, .. } => {
                anyhow::Error::new(NetworkError::CommandTimedOut {
                    program: "ip",
                    args: format!("-o link show {name}"),
                    timeout_ms,
                })
            }
            error => anyhow::Error::new(error),
        },
    )?;
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    Err(NetworkError::CommandFailed {
        program: "ip",
        args: format!("-o link show {name}"),
    }
    .into())
}

fn run_ip(args: &[&str]) -> Result<()> {
    run_network_command("ip", args)
}

fn run_ip_quiet(args: &[&str]) -> Result<()> {
    run_network_command("ip", args)
}

pub fn setup_nat(subnet: &str) -> Result<NatLease> {
    let previous_ip_forward = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .ok()
        .map(|value| value.trim().to_string());
    if previous_ip_forward.as_deref() != Some("1") {
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .context("failed to enable ipv4 forwarding")?;
    }

    let mut lease = NatLease {
        subnet: subnet.to_string(),
        postrouting_owned: false,
        forward_source_owned: false,
        forward_destination_owned: false,
        previous_ip_forward,
    };

    let setup = (|| {
        lease.postrouting_owned = ensure_iptables_rule(&[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            subnet,
            "-j",
            "MASQUERADE",
        ])?;
        lease.forward_source_owned =
            ensure_iptables_rule(&["-A", "FORWARD", "-s", subnet, "-j", "ACCEPT"])?;
        lease.forward_destination_owned =
            ensure_iptables_rule(&["-A", "FORWARD", "-d", subnet, "-j", "ACCEPT"])?;
        Ok::<(), anyhow::Error>(())
    })();

    if let Err(error) = setup {
        cleanup_nat_lease(&lease).ok();
        return Err(error);
    }

    Ok(lease)
}

fn ensure_iptables_rule(add_args: &[&str]) -> Result<bool> {
    let mut check_args = add_args.to_vec();
    let action_index = check_args
        .iter()
        .position(|arg| *arg == "-A")
        .context("iptables rule is missing append action")?;
    check_args[action_index] = "-C";

    if run_iptables_quiet(&check_args).is_ok() {
        return Ok(false);
    }

    run_iptables(add_args)?;
    Ok(true)
}

fn run_iptables(args: &[&str]) -> Result<()> {
    run_network_command("iptables", args)
}

fn run_iptables_quiet(args: &[&str]) -> Result<()> {
    run_network_command("iptables", args)
}

fn run_network_command(program: &'static str, args: &[&str]) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args);
    let description = format!("{program} {}", args.join(" "));
    let status = command::status(command, description, EXTERNAL_COMMAND_TIMEOUT).map_err(
        |error| match error {
            CommandError::TimedOut { timeout_ms, .. } => {
                anyhow::Error::new(NetworkError::CommandTimedOut {
                    program,
                    args: args.join(" "),
                    timeout_ms,
                })
            }
            error => anyhow::Error::new(error),
        },
    )?;

    if !status.success() {
        return Err(NetworkError::CommandFailed {
            program,
            args: args.join(" "),
        }
        .into());
    }

    Ok(())
}

pub fn cleanup_nat_lease(lease: &NatLease) -> Result<()> {
    let mut errors = Vec::new();
    if lease.postrouting_owned {
        if let Err(error) = run_iptables_quiet(&[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            &lease.subnet,
            "-j",
            "MASQUERADE",
        ]) {
            errors.push(format!("POSTROUTING cleanup failed: {error}"));
        }
    }
    if lease.forward_source_owned {
        if let Err(error) =
            run_iptables_quiet(&["-D", "FORWARD", "-s", &lease.subnet, "-j", "ACCEPT"])
        {
            errors.push(format!("FORWARD source cleanup failed: {error}"));
        }
    }
    if lease.forward_destination_owned {
        if let Err(error) =
            run_iptables_quiet(&["-D", "FORWARD", "-d", &lease.subnet, "-j", "ACCEPT"])
        {
            errors.push(format!("FORWARD destination cleanup failed: {error}"));
        }
    }
    if let Some(previous) = lease.previous_ip_forward.as_deref() {
        if previous != "1" {
            if let Err(error) = fs::write("/proc/sys/net/ipv4/ip_forward", previous)
                .context("failed to restore ipv4 forwarding")
            {
                errors.push(error.to_string());
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(errors.join("; ")))
    }
}

/// Legacy cleanup for callers without an ownership token. New lifecycle code
/// must use `cleanup_nat_lease` so pre-existing administrator rules are preserved.
pub fn cleanup_nat(subnet: &str) -> Result<()> {
    cleanup_nat_lease(&NatLease {
        subnet: subnet.to_string(),
        postrouting_owned: true,
        forward_source_owned: true,
        forward_destination_owned: true,
        previous_ip_forward: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_short_veth_names_from_pid() {
        let veth = VethPair::for_pid(12345);

        assert_eq!(veth.host_name, "vethh12345");
        assert_eq!(veth.peer_name, "vethp12345");
        assert!(veth.host_name.len() <= 15);
        assert!(veth.peer_name.len() <= 15);
    }

    #[test]
    fn generates_bridge_network_from_pid() {
        let network = BridgeNetwork::for_pid(12345);

        assert_eq!(network.veth.host_name, "vethh12345");
        assert_eq!(network.veth.peer_name, "vethp12345");
        assert_eq!(network.subnet, "10.88.165.0/24");
        assert_eq!(network.host_cidr, "10.88.165.1/24");
        assert_eq!(network.container_cidr, "10.88.165.2/24");
        assert_eq!(network.gateway, "10.88.165.1");
    }

    #[test]
    fn stable_veth_names_do_not_depend_on_pid() {
        let first = VethPair::for_container_id("container-alpha");
        let same = VethPair::for_container_id("container-alpha");
        let other = VethPair::for_container_id("container-beta");

        assert_eq!(first, same);
        assert_ne!(first, other);
        assert!(first.host_name.len() <= 15);
        assert!(first.peer_name.len() <= 15);
    }

    #[test]
    fn allocation_lock_starttime_detects_pid_reuse() {
        let root =
            std::env::temp_dir().join(format!("crun-rs-lock-identity-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let lock = root.join("allocations.lock");
        fs::create_dir_all(&lock).expect("create lock directory");
        let pid = std::process::id();
        let starttime = crate::state::process_starttime(i32::try_from(pid).expect("pid fits"))
            .expect("current process starttime should exist");
        let owner = AllocationLockOwner {
            owner_pid: pid,
            owner_starttime: Some(starttime + 1),
            created_at_unix: unix_timestamp().expect("clock should be available"),
        };
        let content = serde_json::to_string_pretty(&owner).expect("serialize lock owner");
        fs::write(lock_owner_file(&lock), format!("{content}\n")).expect("write lock owner");

        assert!(allocation_lock_is_stale(&lock).expect("lock state should read"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn allocates_bridge_subnets_without_reuse_until_release() {
        let root = std::env::temp_dir().join(format!("crun-rs-net-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let first = allocate_bridge_network_from(&root, "first", 1001).expect("first allocation");
        let second =
            allocate_bridge_network_from(&root, "second", 1002).expect("second allocation");

        assert_eq!(first.subnet, "10.88.20.0/24");
        assert_eq!(second.subnet, "10.88.21.0/24");

        release_bridge_network_from(&root, "first").expect("release first allocation");
        let third = allocate_bridge_network_from(&root, "third", 1003).expect("third allocation");

        assert_eq!(third.subnet, "10.88.20.0/24");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_bridge_allocation_when_subnet_pool_is_exhausted() {
        let allocations = BridgeAllocations {
            containers: (BRIDGE_OCTET_START..=BRIDGE_OCTET_END)
                .map(|octet| (format!("container-{octet}"), octet))
                .collect(),
        };

        let error = next_free_bridge_octet(&allocations).expect_err("pool should be exhausted");
        let network_error = error
            .downcast_ref::<NetworkError>()
            .expect("error should be typed");

        assert!(matches!(
            network_error,
            NetworkError::NoBridgeSubnetsAvailable {
                start: BRIDGE_OCTET_START,
                end: BRIDGE_OCTET_END
            }
        ));
    }

    #[test]
    fn removes_stale_allocation_lock_before_allocating() {
        let root = std::env::temp_dir().join(format!(
            "crun-rs-stale-net-lock-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let lock = root.join("allocations.lock");
        fs::create_dir_all(&lock).expect("create stale lock");
        let owner = AllocationLockOwner {
            owner_pid: 0,
            owner_starttime: None,
            created_at_unix: 1,
        };
        let content = serde_json::to_string_pretty(&owner).expect("serialize owner");
        fs::write(lock_owner_file(&lock), format!("{content}\n")).expect("write stale owner");

        let network = allocate_bridge_network_from(&root, "after-stale", 1001).expect("allocation");

        assert_eq!(network.subnet, "10.88.20.0/24");
        assert!(!lock.exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn formats_network_modes_for_state() {
        assert_eq!(NetworkMode::Host.as_str(), "host");
        assert_eq!(NetworkMode::None.as_str(), "none");
        assert_eq!(NetworkMode::Bridge.as_str(), "bridge");
    }
}
