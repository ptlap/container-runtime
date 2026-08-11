use crate::error::ImageError;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_IMAGE_ROOT: &str = "/var/lib/crun-rs/images";

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
    let output = Command::new("tar")
        .arg("-xf")
        .arg(rootfs_tar)
        .arg("-C")
        .arg(rootfs)
        .arg("--no-same-owner")
        .output()
        .context("failed to execute tar")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ImageError::TarExtractionFailed {
            stderr: stderr.trim().to_string(),
        }
        .into());
    }

    Ok(())
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
    fn minimal_config_uses_imported_rootfs() {
        let config = minimal_config();

        assert_eq!(config["process"]["args"][0], "/bin/sh");
        assert_eq!(config["root"]["path"], "rootfs");
        assert_eq!(config["root"]["readonly"], false);
    }
}
