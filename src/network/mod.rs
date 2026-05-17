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

impl BridgeNetwork {
    pub fn for_pid(pid: i32) -> Self {
        let octet = bridge_octet(pid);

        Self {
            veth: VethPair::for_pid(pid),
            subnet: format!("10.88.{octet}.0/24"),
            host_cidr: format!("10.88.{octet}.1/24"),
            container_cidr: format!("10.88.{octet}.2/24"),
            gateway: format!("10.88.{octet}.1"),
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
}

fn bridge_octet(pid: i32) -> u8 {
    ((pid.unsigned_abs() % 200) + 20) as u8
}

pub fn setup_loopback() -> Result<()> {
    run_ip(&["link", "set", "lo", "up"])
}

pub fn setup_veth_parent(child_pid: Pid, network: &BridgeNetwork) -> Result<()> {
    run_ip_quiet(&["link", "delete", &network.veth.host_name]).ok();

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
    if run_ip_quiet(&["link", "show", host_name]).is_err() {
        return Ok(());
    }

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

pub fn setup_nat(subnet: &str) -> Result<()> {
    fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("failed to enable ipv4 forwarding")?;

    run_iptables_quiet(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        subnet,
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
        subnet,
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

pub fn cleanup_nat(subnet: &str) -> Result<()> {
    while run_iptables_quiet(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        subnet,
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
    fn formats_network_modes_for_state() {
        assert_eq!(NetworkMode::Host.as_str(), "host");
        assert_eq!(NetworkMode::None.as_str(), "none");
        assert_eq!(NetworkMode::Bridge.as_str(), "bridge");
    }
}
