use crate::error::FilesystemError;
use crate::filesystem::resolve_bundle_path;
use crate::spec::config::load_config;
use crate::state;
use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RootfsDiffReport {
    pub id: String,
    pub lowerdir: String,
    pub upperdir: String,
    pub entries: Vec<RootfsDiffEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RootfsDiffEntry {
    pub path: String,
    pub kind: RootfsDiffKind,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RootfsDiffKind {
    Created,
    Modified,
    Deleted,
}

impl RootfsDiffKind {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
        }
    }
}

pub fn diff_container(id: &str) -> Result<RootfsDiffReport> {
    let container_state = state::load(id)?;
    let bundle = PathBuf::from(&container_state.bundle);
    let config = load_config(bundle.join("config.json"))?;
    let overlay = config
        .crun
        .as_ref()
        .and_then(|crun| crun.overlay.as_ref())
        .filter(|overlay| overlay.enabled)
        .context("container bundle does not enable overlay rootfs")?;

    let lowerdir = overlay
        .lowerdir
        .as_deref()
        .map(|path| resolve_bundle_path(&bundle, path))
        .unwrap_or_else(|| resolve_bundle_path(&bundle, &config.root.path));
    let upperdir = resolve_bundle_path(&bundle, &overlay.upperdir);

    if !lowerdir.exists() {
        return Err(FilesystemError::OverlayLowerdirDoesNotExist {
            path: lowerdir.display().to_string(),
        }
        .into());
    }
    if !upperdir.exists() {
        return Err(FilesystemError::OverlayUpperdirDoesNotExist {
            path: upperdir.display().to_string(),
        }
        .into());
    }

    let entries = diff_overlay_dirs(&lowerdir, &upperdir)?;

    Ok(RootfsDiffReport {
        id: id.to_string(),
        lowerdir: lowerdir.display().to_string(),
        upperdir: upperdir.display().to_string(),
        entries,
    })
}

fn diff_overlay_dirs(lowerdir: &Path, upperdir: &Path) -> Result<Vec<RootfsDiffEntry>> {
    let mut entries = Vec::new();
    collect_diff_entries(lowerdir, upperdir, upperdir, &mut entries)?;
    sort_entries(&mut entries);
    Ok(entries)
}

fn sort_entries(entries: &mut Vec<RootfsDiffEntry>) {
    entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| diff_kind_rank(&left.kind).cmp(&diff_kind_rank(&right.kind)))
    });
    entries.dedup();
}

fn collect_diff_entries(
    lowerdir: &Path,
    upperdir: &Path,
    current: &Path,
    entries: &mut Vec<RootfsDiffEntry>,
) -> Result<()> {
    for entry in fs::read_dir(current)
        .with_context(|| format!("failed to read overlay upperdir: {}", current.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to read overlay upperdir entry under {}",
                current.display()
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat overlay upper entry: {}", path.display()))?;

        if is_opaque_marker(&path) {
            if let Some(parent) = path.parent() {
                entries.push(RootfsDiffEntry {
                    path: container_path(upperdir, parent)?,
                    kind: RootfsDiffKind::Modified,
                });
            }
            continue;
        }

        if let Some(deleted_path) = whiteout_deleted_path(upperdir, &path, &metadata)? {
            entries.push(RootfsDiffEntry {
                path: deleted_path,
                kind: RootfsDiffKind::Deleted,
            });
            continue;
        }

        let rel_path = path
            .strip_prefix(upperdir)
            .with_context(|| format!("failed to strip upperdir prefix: {}", path.display()))?;
        let lower_path = lowerdir.join(rel_path);

        if metadata.is_dir() {
            if !lower_path.exists() {
                entries.push(RootfsDiffEntry {
                    path: container_path(upperdir, &path)?,
                    kind: RootfsDiffKind::Created,
                });
            }
            collect_diff_entries(lowerdir, upperdir, &path, entries)?;
        } else {
            entries.push(RootfsDiffEntry {
                path: container_path(upperdir, &path)?,
                kind: if lower_path.exists() {
                    RootfsDiffKind::Modified
                } else {
                    RootfsDiffKind::Created
                },
            });
        }
    }

    Ok(())
}

fn whiteout_deleted_path(
    upperdir: &Path,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<Option<String>> {
    if is_char_whiteout(metadata) {
        return Ok(Some(container_path(upperdir, path)?));
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    let Some(deleted_name) = name.strip_prefix(".wh.") else {
        return Ok(None);
    };
    if deleted_name.is_empty() || deleted_name == ".wh..opq" {
        return Ok(None);
    }

    let deleted_path = path.parent().unwrap_or(upperdir).join(deleted_name);
    Ok(Some(container_path(upperdir, &deleted_path)?))
}

fn is_char_whiteout(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_char_device() && metadata.rdev() == 0
}

fn is_opaque_marker(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == ".wh..wh..opq")
}

fn container_path(base: &Path, path: &Path) -> Result<String> {
    let rel_path = path
        .strip_prefix(base)
        .with_context(|| format!("failed to strip path prefix: {}", path.display()))?;
    if rel_path.as_os_str().is_empty() {
        return Ok("/".to_string());
    }

    Ok(format!("/{}", rel_path.to_string_lossy()))
}

fn diff_kind_rank(kind: &RootfsDiffKind) -> u8 {
    match kind {
        RootfsDiffKind::Created => 0,
        RootfsDiffKind::Modified => 1,
        RootfsDiffKind::Deleted => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn classifies_overlay_changes() {
        let root = test_dir("classifies_overlay_changes");
        let lower = root.join("lower");
        let upper = root.join("upper");
        fs::create_dir_all(lower.join("etc")).expect("create lower etc");
        fs::create_dir_all(upper.join("etc")).expect("create upper etc");
        write_file(&lower.join("etc/config"), "old");
        write_file(&upper.join("etc/config"), "new");
        write_file(&upper.join("new-file"), "new");
        write_file(&upper.join("etc/.wh.removed"), "");

        let entries = diff_overlay_dirs(&lower, &upper).expect("diff overlay dirs");

        assert_eq!(
            entries,
            vec![
                RootfsDiffEntry {
                    path: "/etc/config".to_string(),
                    kind: RootfsDiffKind::Modified,
                },
                RootfsDiffEntry {
                    path: "/etc/removed".to_string(),
                    kind: RootfsDiffKind::Deleted,
                },
                RootfsDiffEntry {
                    path: "/new-file".to_string(),
                    kind: RootfsDiffKind::Created,
                },
            ]
        );

        fs::remove_dir_all(root).expect("cleanup test dir");
    }

    #[test]
    fn marks_new_directories_and_opaque_directories() {
        let root = test_dir("marks_new_directories_and_opaque_directories");
        let lower = root.join("lower");
        let upper = root.join("upper");
        fs::create_dir_all(lower.join("var/cache")).expect("create lower cache");
        fs::create_dir_all(upper.join("var/cache")).expect("create upper cache");
        fs::create_dir_all(upper.join("opt/new-dir")).expect("create upper new dir");
        write_file(&upper.join("var/cache/.wh..wh..opq"), "");

        let entries = diff_overlay_dirs(&lower, &upper).expect("diff overlay dirs");

        assert_eq!(
            entries,
            vec![
                RootfsDiffEntry {
                    path: "/opt".to_string(),
                    kind: RootfsDiffKind::Created,
                },
                RootfsDiffEntry {
                    path: "/opt/new-dir".to_string(),
                    kind: RootfsDiffKind::Created,
                },
                RootfsDiffEntry {
                    path: "/var/cache".to_string(),
                    kind: RootfsDiffKind::Modified,
                },
            ]
        );

        fs::remove_dir_all(root).expect("cleanup test dir");
    }

    #[test]
    fn formats_diff_kind_labels() {
        assert_eq!(RootfsDiffKind::Created.as_label(), "created");
        assert_eq!(RootfsDiffKind::Modified.as_label(), "modified");
        assert_eq!(RootfsDiffKind::Deleted.as_label(), "deleted");
    }

    fn test_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("crun-rootfs-diff-{name}-{stamp}"))
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        let mut file = fs::File::create(path).expect("create test file");
        file.write_all(content.as_bytes()).expect("write test file");
    }
}
