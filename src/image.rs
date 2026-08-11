use crate::error::ImageError;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use tar::{Archive, EntryType};

pub const DEFAULT_IMAGE_ROOT: &str = "/var/lib/crun-rs/images";

const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: u64 = 100_000;
const MAX_ARCHIVE_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_UNPACKED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImageInfo {
    pub name: String,
    pub path: String,
    pub rootfs: String,
}

pub fn import(rootfs_tar: &Path, name: &str) -> Result<ImageInfo> {
    import_into(Path::new(DEFAULT_IMAGE_ROOT), rootfs_tar, name)
}

pub fn list() -> Result<Vec<ImageInfo>> {
    list_from(Path::new(DEFAULT_IMAGE_ROOT))
}

pub fn bundle_path(name: &str) -> Result<PathBuf> {
    validate_image_name(name)?;
    let dir = image_dir(Path::new(DEFAULT_IMAGE_ROOT), name);
    if !dir.join("config.json").is_file() {
        return Err(ImageError::ImageNotFound {
            name: name.to_string(),
        }
        .into());
    }
    if !dir.join("rootfs").is_dir() {
        return Err(ImageError::ImageRootfsNotFound {
            path: dir.join("rootfs").display().to_string(),
        }
        .into());
    }
    Ok(dir)
}

fn import_into(root: &Path, rootfs_tar: &Path, name: &str) -> Result<ImageInfo> {
    validate_image_name(name)?;
    if !rootfs_tar.is_file() {
        return Err(ImageError::RootfsTarDoesNotExist {
            path: rootfs_tar.display().to_string(),
        }
        .into());
    }

    fs::create_dir_all(root)
        .with_context(|| format!("failed to create image root: {}", root.display()))?;

    let dir = image_dir(root, name);
    if dir.exists() {
        return Err(ImageError::ImageAlreadyExists {
            name: name.to_string(),
        }
        .into());
    }

    let rootfs = dir.join("rootfs");
    fs::create_dir_all(&rootfs)
        .with_context(|| format!("failed to create image rootfs: {}", rootfs.display()))?;

    if let Err(error) = extract_rootfs(rootfs_tar, &rootfs)
        .and_then(|()| write_minimal_config(&dir))
        .with_context(|| format!("failed to import image: {name}"))
    {
        let _ = fs::remove_dir_all(&dir);
        return Err(error);
    }

    image_info(root, name)
}

fn list_from(root: &Path) -> Result<Vec<ImageInfo>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut images = Vec::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("failed to read image root: {}", root.display()))?
    {
        let entry = entry.context("failed to read image directory entry")?;
        if !entry
            .file_type()
            .context("failed to read image directory entry type")?
            .is_dir()
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !entry.path().join("rootfs").is_dir() || !entry.path().join("config.json").is_file() {
            continue;
        }
        images.push(image_info(root, &name)?);
    }

    images.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(images)
}

fn extract_rootfs(rootfs_tar: &Path, rootfs: &Path) -> Result<()> {
    preflight_archive(rootfs_tar)?;

    let file = File::open(rootfs_tar)
        .with_context(|| format!("failed to open rootfs archive: {}", rootfs_tar.display()))?;
    let mut archive = Archive::new(file);
    archive.set_preserve_ownerships(false);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(false);
    archive
        .unpack(rootfs)
        .with_context(|| format!("failed to extract rootfs archive: {}", rootfs_tar.display()))?;
    Ok(())
}

fn preflight_archive(rootfs_tar: &Path) -> Result<()> {
    let archive_size = fs::metadata(rootfs_tar)
        .with_context(|| format!("failed to stat rootfs archive: {}", rootfs_tar.display()))?
        .len();
    if archive_size > MAX_ARCHIVE_BYTES {
        return Err(ImageError::ArchiveTooLarge {
            limit: MAX_ARCHIVE_BYTES,
        }
        .into());
    }

    let file = File::open(rootfs_tar)
        .with_context(|| format!("failed to open rootfs archive: {}", rootfs_tar.display()))?;
    let mut archive = Archive::new(file);
    let mut entries = 0u64;
    let mut unpacked_bytes = 0u64;

    for entry in archive.entries().context("failed to read rootfs archive")? {
        let entry = entry.context("failed to read rootfs archive entry")?;
        entries = entries.saturating_add(1);
        if entries > MAX_ARCHIVE_ENTRIES {
            return Err(ImageError::ArchiveTooManyEntries {
                limit: MAX_ARCHIVE_ENTRIES,
            }
            .into());
        }

        let path = entry
            .path()
            .context("failed to read rootfs archive path")?
            .into_owned();
        validate_archive_path(&path)?;
        let entry_type = entry.header().entry_type();

        if entry_type.is_file() || entry_type.is_contiguous() {
            let size = entry.size();
            if size > MAX_ARCHIVE_FILE_BYTES {
                return Err(ImageError::ArchiveFileTooLarge {
                    path: path.display().to_string(),
                    size,
                    limit: MAX_ARCHIVE_FILE_BYTES,
                }
                .into());
            }
            unpacked_bytes = unpacked_bytes.saturating_add(size);
            if unpacked_bytes > MAX_ARCHIVE_UNPACKED_BYTES {
                return Err(ImageError::ArchiveTooLarge {
                    limit: MAX_ARCHIVE_UNPACKED_BYTES,
                }
                .into());
            }
        } else if entry_type.is_symlink() {
            let target = entry
                .link_name()
                .context("failed to read rootfs symlink target")?
                .ok_or_else(|| ImageError::ArchiveLinkTargetMissing {
                    path: path.display().to_string(),
                })?;
            validate_link_target(&path, &target, true)?;
        } else if entry_type.is_hard_link() {
            let target = entry
                .link_name()
                .context("failed to read rootfs hardlink target")?
                .ok_or_else(|| ImageError::ArchiveLinkTargetMissing {
                    path: path.display().to_string(),
                })?;
            validate_link_target(&path, &target, false)?;
        } else if entry_type.is_dir() {
            // Directories carry no data and are safe after path validation.
        } else {
            return Err(ImageError::UnsupportedArchiveEntry {
                path: path.display().to_string(),
                kind: archive_entry_kind(entry_type),
            }
            .into());
        }
    }

    Ok(())
}

fn validate_archive_path(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(ImageError::ArchivePathEscapesRootfs {
            path: path.display().to_string(),
        }
        .into());
    }
    Ok(())
}

fn validate_link_target(path: &Path, target: &Path, allow_absolute: bool) -> Result<()> {
    if (!allow_absolute && target.is_absolute())
        || target
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(ImageError::ArchivePathEscapesRootfs {
            path: format!("{} -> {}", path.display(), target.display()),
        }
        .into());
    }
    Ok(())
}

fn archive_entry_kind(entry_type: EntryType) -> &'static str {
    if entry_type.is_character_special() {
        "character device"
    } else if entry_type.is_block_special() {
        "block device"
    } else if entry_type.is_fifo() {
        "fifo"
    } else {
        "unsupported"
    }
}

fn write_minimal_config(image_dir: &Path) -> Result<()> {
    let config = minimal_config();
    let content =
        serde_json::to_string_pretty(&config).context("failed to serialize image config")?;
    let path = image_dir.join("config.json");
    fs::write(&path, content)
        .with_context(|| format!("failed to write image config: {}", path.display()))
}

fn minimal_config() -> serde_json::Value {
    json!({
        "ociVersion": "1.0.2",
        "process": {
            "args": ["/bin/sh"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/"
        },
        "root": {
            "path": "rootfs",
            "readonly": false
        },
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "mount" },
                { "type": "uts" },
                { "type": "ipc" },
                { "type": "network" }
            ]
        }
    })
}

fn image_info(root: &Path, name: &str) -> Result<ImageInfo> {
    validate_image_name(name)?;
    let dir = image_dir(root, name);
    Ok(ImageInfo {
        name: name.to_string(),
        path: dir.display().to_string(),
        rootfs: dir.join("rootfs").display().to_string(),
    })
}

fn image_dir(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

fn validate_image_name(name: &str) -> std::result::Result<(), ImageError> {
    if name.is_empty() {
        return Err(ImageError::EmptyImageName);
    }

    if matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ImageError::InvalidImageName);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn rejects_invalid_image_names() {
        assert_eq!(
            validate_image_name("").unwrap_err(),
            ImageError::EmptyImageName
        );
        assert_eq!(
            validate_image_name("../alpine").unwrap_err(),
            ImageError::InvalidImageName
        );
        assert_eq!(
            validate_image_name("alpine/latest").unwrap_err(),
            ImageError::InvalidImageName
        );
        assert_eq!(
            validate_image_name("alpine latest").unwrap_err(),
            ImageError::InvalidImageName
        );
        assert_eq!(
            validate_image_name(".").unwrap_err(),
            ImageError::InvalidImageName
        );
        assert_eq!(
            validate_image_name("..").unwrap_err(),
            ImageError::InvalidImageName
        );
        assert!(validate_image_name("alpine_3.19-1").is_ok());
    }

    #[test]
    fn lists_imported_images_sorted() {
        let root = std::env::temp_dir().join(format!("crun-rs-images-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        for name in ["zeta", "alpha"] {
            let dir = image_dir(&root, name);
            fs::create_dir_all(dir.join("rootfs")).expect("image rootfs should be created");
            write_minimal_config(&dir).expect("image config should be written");
        }

        let images = list_from(&root).expect("images should list");
        let names = images
            .iter()
            .map(|image| image.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["alpha", "zeta"]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_archive_path_traversal() {
        let archive_path = std::env::temp_dir().join(format!(
            "crun-rs-malicious-archive-{}.tar",
            std::process::id()
        ));
        let file = File::create(&archive_path).expect("archive should be created");
        let mut builder = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header
            .set_path_absolute("/escape")
            .expect("absolute path should fit tar header");
        header.set_size(1);
        header.set_cksum();
        builder
            .append(&header, &b"x"[..])
            .expect("malicious archive should be constructible");
        builder.finish().expect("archive should finish");

        let error = preflight_archive(&archive_path).expect_err("traversal should be rejected");
        assert!(matches!(
            error.downcast_ref::<ImageError>(),
            Some(ImageError::ArchivePathEscapesRootfs { .. })
        ));
        let _ = fs::remove_file(archive_path);
    }

    #[test]
    fn rejects_archive_symlink_target_escape() {
        let archive_path =
            std::env::temp_dir().join(format!("crun-rs-malicious-link-{}.tar", std::process::id()));
        let file = File::create(&archive_path).expect("archive should be created");
        let mut builder = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::symlink());
        header.set_size(0);
        header.set_cksum();
        builder
            .append_link(&mut header, "usr/bin/escape", "../../host")
            .expect("malicious link archive should be constructible");
        builder.finish().expect("archive should finish");

        let error = preflight_archive(&archive_path).expect_err("link escape should be rejected");
        assert!(matches!(
            error.downcast_ref::<ImageError>(),
            Some(ImageError::ArchivePathEscapesRootfs { .. })
        ));
        let _ = fs::remove_file(archive_path);
    }

    #[test]
    fn accepts_and_extracts_a_normal_archive_without_host_metadata() {
        let archive_path =
            std::env::temp_dir().join(format!("crun-rs-normal-archive-{}.tar", std::process::id()));
        let rootfs =
            std::env::temp_dir().join(format!("crun-rs-normal-rootfs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&rootfs);
        fs::create_dir_all(&rootfs).expect("rootfs should be created");
        let file = File::create(&archive_path).expect("archive should be created");
        let mut builder = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_cksum();
        builder
            .append_data(&mut header, "bin/hello", &b"hello"[..])
            .expect("normal archive should be constructible");
        builder.finish().expect("archive should finish");

        extract_rootfs(&archive_path, &rootfs).expect("normal archive should extract");
        assert_eq!(
            fs::read(rootfs.join("bin/hello")).expect("file should exist"),
            b"hello"
        );
        let _ = fs::remove_file(archive_path);
        let _ = fs::remove_dir_all(rootfs);
    }

    #[test]
    fn minimal_config_uses_imported_rootfs() {
        let config = minimal_config();

        assert_eq!(config["process"]["args"][0], "/bin/sh");
        assert_eq!(config["root"]["path"], "rootfs");
        assert_eq!(config["root"]["readonly"], false);
    }
}
