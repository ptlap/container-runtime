use anyhow::{Context, Result};
use nix::unistd::Pid;
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
