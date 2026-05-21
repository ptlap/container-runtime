use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
use nix::unistd::{chdir, pivot_root};
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

use crate::error::FilesystemError;
use crate::spec::config::{CrunConfig, Mount};

#[derive(Debug, Clone)]
pub struct OverlayConfig {
    pub lowerdir: PathBuf,
    pub upperdir: PathBuf,
    pub workdir: PathBuf,
    pub mergeddir: PathBuf,
}

pub fn resolve_overlay_config(
    bundle: &Path,
    root_path: &str,
    crun: Option<&CrunConfig>,
) -> Option<OverlayConfig> {
    let overlay = crun.and_then(|config| config.overlay.as_ref())?;
    if !overlay.enabled {
        return None;
    }

    let lowerdir = overlay
        .lowerdir
        .as_deref()
        .map(|path| resolve_bundle_path(bundle, path))
        .unwrap_or_else(|| resolve_bundle_path(bundle, root_path));

    Some(OverlayConfig {
        lowerdir,
        upperdir: resolve_bundle_path(bundle, &overlay.upperdir),
        workdir: resolve_bundle_path(bundle, &overlay.workdir),
        mergeddir: resolve_bundle_path(bundle, &overlay.mergeddir),
    })
}

pub fn resolve_bundle_path(bundle: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        bundle.join(path)
    }
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

pub fn apply_oci_linux_paths(masked_paths: &[String], readonly_paths: &[String]) -> Result<()> {
    for path in masked_paths {
        mask_container_path(Path::new(path))?;
    }
    for path in readonly_paths {
        make_container_path_readonly(Path::new(path))?;
    }

    Ok(())
}

fn mask_container_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if path.is_dir() {
        mount(
            Some("tmpfs"),
            path,
            Some("tmpfs"),
            MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some("size=0k"),
        )
        .with_context(|| format!("failed to mask directory path: {}", path.display()))?;
    } else {
        mount(
            Some("/dev/null"),
            path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| format!("failed to mask file path: {}", path.display()))?;
    }

    Ok(())
}

fn make_container_path_readonly(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    mount(
        Some(path),
        path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("failed to bind readonly path: {}", path.display()))?;

    mount(
        Some(path),
        path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .with_context(|| format!("failed to remount readonly path: {}", path.display()))?;

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
        .ok_or(FilesystemError::MissingBindMountSource)?;
    let source_path = Path::new(source);
    let source_metadata = fs::metadata(source_path)
        .with_context(|| format!("failed to stat bind mount source: {source}"))?;
    let destination = container_mount_destination(rootfs, &mount_config.destination)?;

    prepare_bind_mount_destination(&destination, source_metadata.is_dir())?;

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
        Some(source_path),
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
        let mut remount_flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
        if recursive {
            remount_flags |= MsFlags::MS_REC;
        }
        mount::<Path, Path, str, str>(None, destination.as_path(), None, remount_flags, None)
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
        return Err(FilesystemError::MountDestinationNotAbsolute {
            path: destination.display().to_string(),
        }
        .into());
    }

    let mut relative = PathBuf::new();
    for component in destination.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::ParentDir => {
                return Err(FilesystemError::MountDestinationEscapesRootfs {
                    path: destination.display().to_string(),
                }
                .into());
            }
            Component::Prefix(_) => {
                return Err(FilesystemError::MountDestinationUnsupportedPrefix {
                    path: destination.display().to_string(),
                }
                .into());
            }
        }
    }

    if relative.as_os_str().is_empty() {
        return Err(FilesystemError::MountDestinationIsContainerRoot.into());
    }

    Ok(rootfs.join(relative))
}

fn prepare_bind_mount_destination(destination: &Path, source_is_dir: bool) -> Result<()> {
    if source_is_dir {
        if destination.exists() && !destination.is_dir() {
            return Err(FilesystemError::BindDestinationNotDirectory {
                path: destination.display().to_string(),
            }
            .into());
        }

        fs::create_dir_all(destination).with_context(|| {
            format!(
                "failed to create mount destination directory: {}",
                destination.display()
            )
        })?;
        return Ok(());
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create mount destination parent: {}",
                parent.display()
            )
        })?;
    }

    if destination.exists() && destination.is_dir() {
        return Err(FilesystemError::BindDestinationIsDirectory {
            path: destination.display().to_string(),
        }
        .into());
    }

    File::create(destination).with_context(|| {
        format!(
            "failed to create mount destination file: {}",
            destination.display()
        )
    })?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("crun-fs-test-{name}-{nanos}"))
    }

    #[test]
    fn resolves_absolute_mount_destination_inside_rootfs() {
        let rootfs = Path::new("/tmp/rootfs");
        let destination = container_mount_destination(rootfs, "/var/lib/data")
            .expect("destination should resolve");

        assert_eq!(destination, PathBuf::from("/tmp/rootfs/var/lib/data"));
    }

    #[test]
    fn rejects_mount_destination_that_escapes_rootfs() {
        let error = container_mount_destination(Path::new("/tmp/rootfs"), "/../../host")
            .expect_err("escaping destination should be rejected");

        assert!(matches!(
            error.downcast_ref::<FilesystemError>(),
            Some(FilesystemError::MountDestinationEscapesRootfs { .. })
        ));
    }

    #[test]
    fn rejects_container_root_mount_destination() {
        let error = container_mount_destination(Path::new("/tmp/rootfs"), "/")
            .expect_err("root destination should be rejected");

        assert!(matches!(
            error.downcast_ref::<FilesystemError>(),
            Some(FilesystemError::MountDestinationIsContainerRoot)
        ));
    }

    #[test]
    fn prepares_directory_bind_mount_destination() {
        let destination = unique_temp_path("dir").join("data");

        prepare_bind_mount_destination(&destination, true)
            .expect("directory destination should be created");

        assert!(destination.is_dir());
        let _ = fs::remove_dir_all(destination.parent().expect("destination has parent"));
    }

    #[test]
    fn prepares_file_bind_mount_destination() {
        let destination = unique_temp_path("file").join("etc").join("config.txt");

        prepare_bind_mount_destination(&destination, false)
            .expect("file destination should be created");

        assert!(destination.is_file());
        let _ = fs::remove_dir_all(
            destination
                .parent()
                .and_then(Path::parent)
                .expect("destination has test root"),
        );
    }
}
