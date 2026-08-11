use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::fcntl::{open, openat2, OFlag, OpenHow, ResolveFlag};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::stat::{fstat, makedev, mkdirat, mknod, Mode, SFlag};
use nix::unistd::{chdir, pivot_root};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use tracing::warn;

use crate::error::{FilesystemError, OciConfigError};
use crate::spec::config::{CrunConfig, Mount};

#[derive(Debug, Clone)]
pub struct OverlayConfig {
    pub lowerdir: PathBuf,
    pub upperdir: PathBuf,
    pub workdir: PathBuf,
    pub mergeddir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootfsMode {
    Direct,
    Overlay,
}

impl RootfsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Overlay => "overlay",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedRootfs {
    pub path: PathBuf,
    pub overlay_config: Option<OverlayConfig>,
    pub mode: RootfsMode,
}

pub fn resolve_rootfs(bundle: &Path, root_path: &str, crun: Option<&CrunConfig>) -> ResolvedRootfs {
    let overlay_config = resolve_overlay_config(bundle, root_path, crun);
    let mode = if overlay_config.is_some() {
        RootfsMode::Overlay
    } else {
        RootfsMode::Direct
    };

    ResolvedRootfs {
        path: resolve_bundle_path(bundle, root_path),
        overlay_config,
        mode,
    }
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
        return Err(FilesystemError::OverlayLowerdirDoesNotExist {
            path: config.lowerdir.display().to_string(),
        }
        .into());
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
        warn!("could not remove .old_root: {error}");
    }

    // The bundle owns any destination it declares; the built-in defaults below
    // only fill in what it left out, so a minimal bundle still gets a usable
    // /proc and /dev.
    let declared = declared_destinations(mounts);

    if !declared.contains("/proc") {
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
    }

    setup_dns(&declared)?;
    setup_dev(&declared)?;

    if readonly {
        remount_root_readonly()?;
    }

    Ok(())
}

/// Normalized set of mount destinations declared by the bundle.
fn declared_destinations(mounts: &[Mount]) -> BTreeSet<String> {
    mounts
        .iter()
        .map(|mount| normalize_destination(&mount.destination))
        .collect()
}

fn normalize_destination(destination: &str) -> String {
    let trimmed = destination.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
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
        setup_mount(rootfs, mount_config)?;
    }

    Ok(())
}

/// Dispatches an OCI `mounts[]` entry by its filesystem type.
///
/// Bundles produced by standard tooling (umoci, runc) declare `proc`, `sysfs`,
/// `tmpfs`, `devpts` and `mqueue` entries whose `source` is a filesystem name
/// rather than a host path, so treating every entry as a bind mount fails on
/// them.
fn setup_mount(rootfs: &Path, mount_config: &Mount) -> Result<()> {
    if mount_config.is_bind() {
        return setup_bind_mount(rootfs, mount_config);
    }

    match mount_config.mount_type.as_str() {
        "proc" | "sysfs" | "tmpfs" | "devpts" | "mqueue" | "cgroup" | "cgroup2" | "ramfs" => {
            setup_filesystem_mount(rootfs, mount_config)
        }
        value => Err(OciConfigError::UnsupportedMountType {
            mount_type: value.to_string(),
        }
        .into()),
    }
}

fn setup_filesystem_mount(rootfs: &Path, mount_config: &Mount) -> Result<()> {
    let destination = prepare_mount_destination(rootfs, &mount_config.destination, true)?;
    let mount_path = destination.mount_path();

    let options = MountOptions::parse(&mount_config.options);
    let filesystem = filesystem_type(&mount_config.mount_type);
    let source = mount_config.source.as_deref().unwrap_or(filesystem);

    mount(
        Some(source),
        mount_path.as_path(),
        Some(filesystem),
        options.flags,
        options.data.as_deref(),
    )
    .with_context(|| {
        format!(
            "failed to mount {filesystem} at {}",
            destination.path.display()
        )
    })?;

    if let Some(propagation) = options.propagation {
        mount::<str, Path, str, str>(None, destination.path.as_path(), None, propagation, None)
            .with_context(|| {
                format!(
                    "failed to set mount propagation for {}",
                    destination.path.display()
                )
            })?;
    }

    Ok(())
}

/// Maps an OCI filesystem type onto what this runtime can actually mount.
///
/// The runtime targets cgroup v2 only, and a `cgroup` mount fails on a unified
/// hierarchy, so bundles asking for the v1 type get `cgroup2`.
fn filesystem_type(mount_type: &str) -> &str {
    match mount_type {
        "cgroup" => "cgroup2",
        other => other,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct MountOptions {
    flags: MsFlags,
    /// Propagation is applied by a second `mount` call because the kernel
    /// rejects it being combined with any other flag.
    propagation: Option<MsFlags>,
    data: Option<String>,
}

impl MountOptions {
    fn parse(options: &[String]) -> Self {
        let mut flags = MsFlags::empty();
        let mut propagation = None;
        let mut data = Vec::new();

        for option in options {
            match option.as_str() {
                "defaults" | "bind" | "rbind" => {}
                "ro" => flags |= MsFlags::MS_RDONLY,
                "rw" => flags.remove(MsFlags::MS_RDONLY),
                "nosuid" => flags |= MsFlags::MS_NOSUID,
                "suid" => flags.remove(MsFlags::MS_NOSUID),
                "nodev" => flags |= MsFlags::MS_NODEV,
                "dev" => flags.remove(MsFlags::MS_NODEV),
                "noexec" => flags |= MsFlags::MS_NOEXEC,
                "exec" => flags.remove(MsFlags::MS_NOEXEC),
                "sync" => flags |= MsFlags::MS_SYNCHRONOUS,
                "dirsync" => flags |= MsFlags::MS_DIRSYNC,
                "remount" => flags |= MsFlags::MS_REMOUNT,
                "noatime" => flags |= MsFlags::MS_NOATIME,
                "atime" => flags.remove(MsFlags::MS_NOATIME),
                "nodiratime" => flags |= MsFlags::MS_NODIRATIME,
                "relatime" => flags |= MsFlags::MS_RELATIME,
                "norelatime" => flags.remove(MsFlags::MS_RELATIME),
                "strictatime" => flags |= MsFlags::MS_STRICTATIME,
                "nostrictatime" => flags.remove(MsFlags::MS_STRICTATIME),
                "private" => propagation = Some(MsFlags::MS_PRIVATE),
                "rprivate" => propagation = Some(MsFlags::MS_PRIVATE | MsFlags::MS_REC),
                "slave" => propagation = Some(MsFlags::MS_SLAVE),
                "rslave" => propagation = Some(MsFlags::MS_SLAVE | MsFlags::MS_REC),
                "shared" => propagation = Some(MsFlags::MS_SHARED),
                "rshared" => propagation = Some(MsFlags::MS_SHARED | MsFlags::MS_REC),
                "unbindable" => propagation = Some(MsFlags::MS_UNBINDABLE),
                "runbindable" => propagation = Some(MsFlags::MS_UNBINDABLE | MsFlags::MS_REC),
                value => data.push(value),
            }
        }

        Self {
            flags,
            propagation,
            data: (!data.is_empty()).then(|| data.join(",")),
        }
    }
}

fn setup_bind_mount(rootfs: &Path, mount_config: &Mount) -> Result<()> {
    let source = mount_config
        .source
        .as_deref()
        .ok_or(FilesystemError::MissingBindMountSource)?;
    let source_path = Path::new(source);
    let source_metadata = fs::metadata(source_path)
        .with_context(|| format!("failed to stat bind mount source: {source}"))?;
    let destination =
        prepare_mount_destination(rootfs, &mount_config.destination, source_metadata.is_dir())?;
    let mount_path = destination.mount_path();

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
        mount_path.as_path(),
        None::<&str>,
        flags,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "failed to bind mount {} to {}",
            source,
            destination.path.display()
        )
    })?;

    if readonly {
        let mut remount_flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
        if recursive {
            remount_flags |= MsFlags::MS_REC;
        }
        mount::<Path, Path, str, str>(None, destination.path.as_path(), None, remount_flags, None)
            .with_context(|| {
                format!(
                    "failed to remount bind mount readonly: {}",
                    destination.path.display()
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

struct PreparedMountDestination {
    path: PathBuf,
    fd: OwnedFd,
}

impl PreparedMountDestination {
    fn mount_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }
}

fn prepare_mount_destination(
    rootfs: &Path,
    destination: &str,
    source_is_dir: bool,
) -> Result<PreparedMountDestination> {
    let path = container_mount_destination(rootfs, destination)?;
    let relative = path
        .strip_prefix(rootfs)
        .context("mount destination was not beneath rootfs")?;
    let components = relative_components(relative)?;
    let root_fd = open(
        rootfs,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("failed to open rootfs directory: {}", rootfs.display()))?;

    let fd = if source_is_dir {
        open_or_create_directory_tree(&root_fd, &components).with_context(|| {
            format!(
                "failed to resolve directory mount destination without symlinks: {}",
                path.display()
            )
        })?
    } else {
        open_or_create_file_destination(&root_fd, &components).with_context(|| {
            format!(
                "failed to resolve file mount destination without symlinks: {}",
                path.display()
            )
        })?
    };

    Ok(PreparedMountDestination { path, fd })
}

fn relative_components(path: &Path) -> Result<Vec<OsString>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => components.push(part.to_os_string()),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(FilesystemError::MountDestinationEscapesRootfs {
                    path: path.display().to_string(),
                }
                .into());
            }
        }
    }

    if components.is_empty() {
        return Err(FilesystemError::MountDestinationIsContainerRoot.into());
    }

    Ok(components)
}

fn safe_open_how(flags: OFlag) -> OpenHow {
    OpenHow::new().flags(flags).resolve(
        ResolveFlag::RESOLVE_BENEATH
            | ResolveFlag::RESOLVE_NO_MAGICLINKS
            | ResolveFlag::RESOLVE_NO_SYMLINKS,
    )
}

fn open_directory_at(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd> {
    openat2(
        parent,
        name,
        safe_open_how(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC),
    )
    .with_context(|| {
        format!(
            "failed to open mount destination component {}",
            name.to_string_lossy()
        )
    })
}

fn open_or_create_directory_at(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd> {
    match open_directory_at(parent, name) {
        Ok(fd) => Ok(fd),
        Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {
            mkdirat(parent, name, Mode::from_bits_truncate(0o755)).with_context(|| {
                format!(
                    "failed to create mount destination directory {}",
                    name.to_string_lossy()
                )
            })?;
            open_directory_at(parent, name)
        }
        Err(error) => Err(error),
    }
}

fn open_or_create_directory_tree(root_fd: &OwnedFd, components: &[OsString]) -> Result<OwnedFd> {
    let mut current = open_directory_at(root_fd, OsStr::new("."))?;
    for component in components {
        current = open_or_create_directory_at(&current, component)?;
    }
    Ok(current)
}

fn open_or_create_file_destination(root_fd: &OwnedFd, components: &[OsString]) -> Result<OwnedFd> {
    let (name, parents) = components
        .split_last()
        .context("file mount destination has no final component")?;
    let parent = open_or_create_directory_tree(root_fd, parents)?;

    match openat2(
        &parent,
        name.as_os_str(),
        safe_open_how(OFlag::O_PATH | OFlag::O_CLOEXEC),
    ) {
        Ok(fd) => {
            if SFlag::from_bits_truncate(fstat(&fd)?.st_mode).contains(SFlag::S_IFDIR) {
                return Err(FilesystemError::BindDestinationIsDirectory {
                    path: name.to_string_lossy().into_owned(),
                }
                .into());
            }
            Ok(fd)
        }
        Err(Errno::ENOENT) => openat2(
            &parent,
            name.as_os_str(),
            safe_open_how(OFlag::O_CREAT | OFlag::O_RDWR | OFlag::O_CLOEXEC)
                .mode(Mode::from_bits_truncate(0o666)),
        )
        .with_context(|| {
            format!(
                "failed to create mount destination file {}",
                name.to_string_lossy()
            )
        }),
        Err(error) => Err(error.into()),
    }
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

fn setup_dev(declared: &BTreeSet<String>) -> Result<()> {
    if !declared.contains("/dev") {
        fs::create_dir_all("/dev").context("failed to create /dev")?;

        mount(
            Some("tmpfs"),
            "/dev",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
            Some("mode=755"),
        )
        .context("failed to mount tmpfs on /dev")?;
    }

    create_char_device("/dev/null", 1, 3, 0o666)?;
    create_char_device("/dev/zero", 1, 5, 0o666)?;
    create_char_device("/dev/random", 1, 8, 0o666)?;
    create_char_device("/dev/urandom", 1, 9, 0o666)?;

    if !declared.contains("/dev/shm") {
        setup_dev_shm()?;
    }

    setup_dev_fd_links()?;

    Ok(())
}

/// POSIX shared memory. Workloads such as PostgreSQL fail to start without it.
fn setup_dev_shm() -> Result<()> {
    let path = Path::new("/dev/shm");
    fs::create_dir_all(path).context("failed to create /dev/shm")?;

    mount(
        Some("shm"),
        path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=1777,size=65536k"),
    )
    .context("failed to mount tmpfs on /dev/shm")
}

/// Standard descriptor symlinks. Container images commonly redirect their logs
/// to /dev/stdout, and the process aborts at startup when it cannot open it.
fn setup_dev_fd_links() -> Result<()> {
    let links = [
        ("/proc/self/fd", "/dev/fd"),
        ("/proc/self/fd/0", "/dev/stdin"),
        ("/proc/self/fd/1", "/dev/stdout"),
        ("/proc/self/fd/2", "/dev/stderr"),
    ];

    for (target, link) in links {
        let link_path = Path::new(link);
        if link_path.exists() || link_path.is_symlink() {
            continue;
        }
        std::os::unix::fs::symlink(target, link_path)
            .with_context(|| format!("failed to link {link} to {target}"))?;
    }

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

fn setup_dns(declared: &BTreeSet<String>) -> Result<()> {
    if declared.contains("/etc/resolv.conf") {
        return Ok(());
    }

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
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn mount_entry(destination: &str, mount_type: &str, options: &[&str]) -> Mount {
        serde_json::from_value(serde_json::json!({
            "destination": destination,
            "type": mount_type,
            "options": options,
        }))
        .expect("mount should deserialize")
    }

    #[test]
    fn parses_mount_flags_options_and_data_separately() {
        let options = MountOptions::parse(&[
            "nosuid".to_string(),
            "noexec".to_string(),
            "nodev".to_string(),
            "mode=1777".to_string(),
            "size=65536k".to_string(),
        ]);

        assert!(options.flags.contains(MsFlags::MS_NOSUID));
        assert!(options.flags.contains(MsFlags::MS_NOEXEC));
        assert!(options.flags.contains(MsFlags::MS_NODEV));
        assert_eq!(options.data.as_deref(), Some("mode=1777,size=65536k"));
        assert_eq!(options.propagation, None);
    }

    #[test]
    fn keeps_propagation_out_of_the_main_mount_flags() {
        let options = MountOptions::parse(&["ro".to_string(), "rslave".to_string()]);

        assert!(options.flags.contains(MsFlags::MS_RDONLY));
        assert!(!options.flags.contains(MsFlags::MS_SLAVE));
        assert_eq!(
            options.propagation,
            Some(MsFlags::MS_SLAVE | MsFlags::MS_REC)
        );
    }

    #[test]
    fn later_mount_options_override_earlier_ones() {
        let options = MountOptions::parse(&["ro".to_string(), "rw".to_string()]);

        assert!(!options.flags.contains(MsFlags::MS_RDONLY));
    }

    #[test]
    fn maps_cgroup_mounts_to_the_unified_hierarchy() {
        assert_eq!(filesystem_type("cgroup"), "cgroup2");
        assert_eq!(filesystem_type("proc"), "proc");
        assert_eq!(filesystem_type("tmpfs"), "tmpfs");
    }

    #[test]
    fn detects_bind_mounts_by_type_or_option() {
        assert!(mount_entry("/data", "bind", &[]).is_bind());
        assert!(mount_entry("/data", "none", &["rbind"]).is_bind());
        assert!(!mount_entry("/proc", "proc", &[]).is_bind());
        assert!(!mount_entry("/dev/shm", "tmpfs", &["nosuid"]).is_bind());
    }

    #[test]
    fn collects_declared_destinations_without_trailing_slashes() {
        let mounts = vec![
            mount_entry("/proc", "proc", &[]),
            mount_entry("/dev/shm/", "tmpfs", &[]),
        ];
        let declared = declared_destinations(&mounts);

        assert!(declared.contains("/proc"));
        assert!(declared.contains("/dev/shm"));
        assert!(!declared.contains("/dev"));
    }

    #[test]
    fn rejects_unsupported_mount_types() {
        let rootfs = unique_temp_path("unsupported-type");
        let error = setup_mount(&rootfs, &mount_entry("/data", "nfs", &[]))
            .expect_err("unsupported type should be rejected");

        assert!(error.to_string().contains("nfs"));
    }

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
        let rootfs = unique_temp_path("dir");
        fs::create_dir_all(&rootfs).expect("rootfs should be created");

        let destination = prepare_mount_destination(&rootfs, "/data", true)
            .expect("directory destination should be created");

        assert!(destination.path.is_dir());
        let _ = fs::remove_dir_all(rootfs);
    }

    #[test]
    fn prepares_file_bind_mount_destination() {
        let rootfs = unique_temp_path("file");
        fs::create_dir_all(&rootfs).expect("rootfs should be created");

        let destination = prepare_mount_destination(&rootfs, "/etc/config.txt", false)
            .expect("file destination should be created");

        assert!(destination.path.is_file());
        let _ = fs::remove_dir_all(rootfs);
    }

    #[test]
    fn rejects_symlinked_directory_destination_without_touching_target() {
        let rootfs = unique_temp_path("symlink-dir");
        let outside = unique_temp_path("outside-dir");
        fs::create_dir_all(rootfs.join("etc")).expect("rootfs directories should be created");
        fs::create_dir_all(&outside).expect("outside directory should be created");
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, "untouched").expect("sentinel should be written");
        symlink(&outside, rootfs.join("etc").join("link")).expect("symlink should be created");

        assert!(prepare_mount_destination(&rootfs, "/etc/link/new-dir", true).is_err());
        assert_eq!(
            fs::read_to_string(&sentinel).expect("sentinel should remain"),
            "untouched"
        );
        assert!(!outside.join("new-dir").exists());

        let _ = fs::remove_dir_all(rootfs);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn rejects_symlinked_file_destination_without_truncating_target() {
        let rootfs = unique_temp_path("symlink-file");
        let outside = unique_temp_path("outside-file");
        fs::create_dir_all(rootfs.join("etc")).expect("rootfs directories should be created");
        fs::create_dir_all(&outside).expect("outside directory should be created");
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, "untouched").expect("sentinel should be written");
        symlink(&sentinel, rootfs.join("etc").join("config")).expect("symlink should be created");

        assert!(prepare_mount_destination(&rootfs, "/etc/config", false).is_err());
        assert_eq!(
            fs::read_to_string(&sentinel).expect("sentinel should remain"),
            "untouched"
        );

        let _ = fs::remove_dir_all(rootfs);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn resolves_direct_rootfs_mode_without_overlay() {
        let rootfs = resolve_rootfs(Path::new("/bundle"), "rootfs", None);

        assert_eq!(rootfs.path, PathBuf::from("/bundle/rootfs"));
        assert_eq!(rootfs.mode, RootfsMode::Direct);
        assert!(rootfs.overlay_config.is_none());
    }
}
