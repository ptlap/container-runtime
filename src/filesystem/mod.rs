use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::path::{Path, PathBuf};

use crate::spec::config::Mount;

#[derive(Debug, Clone)]
pub struct OverlayConfig {
    pub lowerdir: PathBuf,
    pub upperdir: PathBuf,
    pub workdir: PathBuf,
    pub mergeddir: PathBuf,
}

pub fn setup_overlay_rootfs(config: &OverlayConfig) -> Result<PathBuf> {
    if !config.lowerdir.exists() {
        anyhow::bail!(
            "overlay lowerdir does not exist: {}",
            config.lowerdir.display()
        );
    }

    fs::create_dir_all(&config.upperdir).with_context(|| {
        format!(
            "failed to create overlay upperdir: {}",
            config.upperdir.display()
        )
    })?;
    fs::create_dir_all(&config.workdir).with_context(|| {
        format!(
            "failed to create overlay workdir: {}",
            config.workdir.display()
        )
    })?;
    fs::create_dir_all(&config.mergeddir).with_context(|| {
        format!(
            "failed to create overlay mergeddir: {}",
            config.mergeddir.display()
        )
    })?;

    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        config.lowerdir.display(),
        config.upperdir.display(),
        config.workdir.display()
    );

    mount(
        Some("overlay"),
        config.mergeddir.as_path(),
        Some("overlay"),
        MsFlags::empty(),
        Some(data.as_str()),
    )
    .with_context(|| {
        format!(
            "failed to mount overlay rootfs at {}",
            config.mergeddir.display()
        )
    })?;

    Ok(config.mergeddir.clone())
}

pub fn setup_rootfs(rootfs: &Path, readonly: bool, mounts: &[Mount]) -> Result<()> {
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("failed to bind mount rootfs")?;

    setup_mounts(rootfs, mounts)?;

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

    if readonly {
        remount_root_readonly()?;
    }

    Ok(())
}

fn setup_mounts(rootfs: &Path, mounts: &[Mount]) -> Result<()> {
    for mount_config in mounts {
        setup_bind_mount(rootfs, mount_config)?;
    }

    Ok(())
}

fn setup_bind_mount(rootfs: &Path, mount_config: &Mount) -> Result<()> {
    let source = mount_config
        .source
        .as_deref()
        .context("bind mount source is required")?;
    let destination = container_mount_destination(rootfs, &mount_config.destination)?;

    fs::create_dir_all(&destination).with_context(|| {
        format!(
            "failed to create mount destination: {}",
            destination.display()
        )
    })?;

    let recursive = mount_config
        .options
        .iter()
        .any(|option| option == "rbind" || option == "rshared");
    let readonly = mount_config.options.iter().any(|option| option == "ro");

    let mut flags = MsFlags::MS_BIND;
    if recursive {
        flags |= MsFlags::MS_REC;
    }

    mount(
        Some(Path::new(source)),
        destination.as_path(),
        None::<&str>,
        flags,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "failed to bind mount {} to {}",
            source,
            destination.display()
        )
    })?;

    if readonly {
        mount::<Path, Path, str, str>(
            None,
            destination.as_path(),
            None,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None,
        )
        .with_context(|| {
            format!(
                "failed to remount bind mount readonly: {}",
                destination.display()
            )
        })?;
    }

    Ok(())
}

fn container_mount_destination(rootfs: &Path, destination: &str) -> Result<PathBuf> {
    let destination = Path::new(destination);
    if !destination.is_absolute() {
        anyhow::bail!(
            "mount destination must be absolute: {}",
            destination.display()
        );
    }

    let relative = destination
        .strip_prefix("/")
        .context("failed to normalize mount destination")?;

    Ok(rootfs.join(relative))
}

fn remount_root_readonly() -> Result<()> {
    mount::<str, str, str, str>(
        None,
        "/",
        None,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None,
    )
    .context("failed to remount rootfs readonly")?;

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

    let dev_path = Path::new(path);
    if mknod(
        dev_path,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(mode),
        makedev(major, minor),
    )
    .is_err()
    {
        let filename = dev_path
            .file_name()
            .and_then(|n| n.to_str())
            .context("invalid device name")?;
        let host_path = format!("/dev/{filename}");
        fs::write(dev_path, "").context("failed to write dummy device file")?;
        mount::<str, Path, str, str>(Some(&host_path), dev_path, None, MsFlags::MS_BIND, None)
            .with_context(|| format!("failed to bind mount host device {host_path} to {path}"))?;
    }

    Ok(())
}

fn setup_dns() -> Result<()> {
    fs::create_dir_all("/etc").context("failed to create /etc")?;

    fs::write(
        "/etc/resolv.conf",
        "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
    )
    .context("failed to write /etc/resolv.conf")?;

    Ok(())
}
