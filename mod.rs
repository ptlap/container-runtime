use anyhow::{Context, Result};
use std::process::Command;

pub fn setup_loopback() -> Result<()> {
    let status = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .context("failed to execute ip link set lo up")?;

    if !status.success() {
        anyhow::bail!("failed to bring loopback up");
    }

    Ok(())
}
