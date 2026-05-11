use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
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

    setup_dns()?;
    setup_dev()?;

    Ok(())
}

fn setup_dev() -> Result<()> {
    fs::create_dir_all("/dev").context("failed to create /dev")?;

    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755"),
    )
    .context("failed to mount tmpfs on /dev")?;

    create_char_device("/dev/null", 1, 3, 0o666)?;
    create_char_device("/dev/zero", 1, 5, 0o666)?;
    create_char_device("/dev/random", 1, 8, 0o666)?;
    create_char_device("/dev/urandom", 1, 9, 0o666)?;

    Ok(())
}

fn create_char_device(path: &str, major: u64, minor: u64, mode: u32) -> Result<()> {
    if Path::new(path).exists() {
        return Ok(());
    }

    mknod(
        Path::new(path),
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(mode),
        makedev(major, minor),
    )
    .with_context(|| format!("failed to create device node: {path}"))?;

    Ok(())
}

fn setup_dns() -> Result<()> {
    fs::create_dir_all("/etc").context("failed to create /etc")?;

    fs::write(
        "/etc/resolv.conf",
        "nameserver 1.1.1.1\nameserver
         8.8.8.8\n",
    )
    .context("failed to write /etc/resolv.conf")?;

    Ok(())
}
