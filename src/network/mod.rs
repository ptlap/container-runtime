use anyhow::{Context, Result};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::{Command, Stdio};

const CONTAINER_IFACE: &str = "eth0";

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethPair {
    pub host_name: String,
    pub peer_name: String,
}

impl VethPair {
    pub fn for_pid(pid: i32) -> Self {
        Self {
            host_name: format!("vethh{pid}"),
            peer_name: format!("vethp{pid}"),
        }
    }
}

pub fn setup_loopback() -> Result<()> {
    run_ip(&["link", "set", "lo", "up"])
}

pub fn setup_veth_parent(child_pid: Pid, veth: &VethPair) -> Result<()> {
    run_ip_quiet(&["link", "delete", &veth.host_name]).ok();

    run_ip(&[
        "link",
        "add",
        &veth.host_name,
        "type",
        "veth",
        "peer",
        "name",
        &veth.peer_name,
    ])?;

    run_ip(&[
        "link",
        "set",
        &veth.peer_name,
        "netns",
        &child_pid.as_raw().to_string(),
    ])?;

    run_ip(&["addr", "add", "10.0.0.1/24", "dev", &veth.host_name])?;
    run_ip(&["link", "set", &veth.host_name, "up"])?;

    Ok(())
}

pub fn setup_veth_child(peer_name: &str) -> Result<()> {
    run_ip(&["link", "set", peer_name, "name", CONTAINER_IFACE])?;
    run_ip(&["addr", "add", "10.0.0.2/24", "dev", CONTAINER_IFACE])?;
    run_ip(&["link", "set", CONTAINER_IFACE, "up"])?;
    run_ip(&["route", "add", "default", "via", "10.0.0.1"])?;

    Ok(())
}

pub fn cleanup_veth_host(host_name: &str) -> Result<()> {
    run_ip_quiet(&["link", "delete", host_name])
}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .with_context(|| format!("failed to execute ip {}", args.join(" ")))?;

    if !status.success() {
        anyhow::bail!("ip command failed: {}", args.join(" "));
    }

    Ok(())
}

fn run_ip_quiet(args: &[&str]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to execute ip {}", args.join(" ")))?;

    if !status.success() {
        anyhow::bail!("ip command failed: {}", args.join(" "));
    }

    Ok(())
}

pub fn setup_nat() -> Result<()> {
    fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("failed to enable ipv4 forwarding")?;

    run_iptables_quiet(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        "10.0.0.0/24",
        "-j",
        "MASQUERADE",
    ])
    .ok();

    run_iptables(&[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        "10.0.0.0/24",
        "-j",
        "MASQUERADE",
    ])?;

    run_iptables(&["-P", "FORWARD", "ACCEPT"])?;

    Ok(())
}

fn run_iptables(args: &[&str]) -> Result<()> {
    let status = Command::new("iptables")
        .args(args)
        .status()
        .with_context(|| format!("failed to execute iptables {}", args.join(" ")))?;

    if !status.success() {
        anyhow::bail!("iptables command failed: {}", args.join(" "));
    }

    Ok(())
}

fn run_iptables_quiet(args: &[&str]) -> Result<()> {
    let status = Command::new("iptables")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to execute iptables {}", args.join(" ")))?;

    if !status.success() {
        anyhow::bail!("iptables command failed: {}", args.join(" "));
    }

    Ok(())
}

pub fn cleanup_nat() -> Result<()> {
    while run_iptables_quiet(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        "10.0.0.0/24",
        "-j",
        "MASQUERADE",
    ])
    .is_ok()
    {}

    Ok(())
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
    fn formats_network_modes_for_state() {
        assert_eq!(NetworkMode::Host.as_str(), "host");
        assert_eq!(NetworkMode::None.as_str(), "none");
        assert_eq!(NetworkMode::Bridge.as_str(), "bridge");
    }
}
