use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::path::Path;

pub fn setup_rootfs(rootfs: &Path) -> Result<()> {
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("failed to bind mount rootfs")?;

    let old_root = rootfs.join(".old_root");

    fs::create_dir_all(&old_root).context("failed to create .old_root")?;

    pivot_root(rootfs, &old_root).context("failed to pivot_root")?;

    chdir("/").context("failed to chdir to new root")?;

    umount2("/.old_root", MntFlags::MNT_DETACH).context("failed to unmount old root")?;

    if let Err(error) = fs::remove_dir("/.old_root") {
        eprintln!("warn: could not remove .old_root: {error}");
    }

    let proc_dir = Path::new("/proc");

    if !proc_dir.exists() {
        fs::create_dir_all(proc_dir).context("failed to create /proc")?;
    }

    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("failed to mount proc")?;

    Ok(())
}
