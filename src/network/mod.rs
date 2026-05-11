use anyhow::{Context, Result};
use nix::unistd::Pid;
use std::fs;
use std::process::Command;

pub fn setup_loopback() -> Result<()> {
    run_ip(&["link", "set", "lo", "up"])
}

pub fn setup_veth_parent(child_pid: Pid) -> Result<()> {
    Command::new("ip")
        .args(["link", "delete", "veth-host"])
        .status()
        .ok();

    run_ip(&[
        "link",
        "add",
        "veth-host",
        "type",
        "veth",
        "peer",
        "name",
        "veth-cont",
    ])?;

    run_ip(&[
        "link",
        "set",
        "veth-cont",
        "netns",
        &child_pid.as_raw().to_string(),
    ])?;

    run_ip(&["addr", "add", "10.0.0.1/24", "dev", "veth-host"])?;
    run_ip(&["link", "set", "veth-host", "up"])?;

    Ok(())
}

pub fn setup_veth_child() -> Result<()> {
    run_ip(&["addr", "add", "10.0.0.2/24", "dev", "veth-cont"])?;
    run_ip(&["link", "set", "veth-cont", "up"])?;
    run_ip(&["route", "add", "default", "via", "10.0.0.1"])?;

    Ok(())
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

pub fn setup_nat() -> Result<()> {
    fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("failed to enable ipv4 forwarding")?;

    run_iptables(&[
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

pub fn cleanup_nat() -> Result<()> {
    while run_iptables(&[
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
