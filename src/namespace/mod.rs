use crate::network::NetworkMode;
use crate::userns::UserNamespaceMode;
use anyhow::{bail, Result};
use nix::sched::CloneFlags;

pub fn namespace_flags<S: AsRef<str>>(namespaces: &[S]) -> Result<CloneFlags> {
    let mut flags = CloneFlags::empty();

    for namespace in namespaces {
        match namespace.as_ref() {
            "pid" => flags |= CloneFlags::CLONE_NEWPID,
            "mount" => flags |= CloneFlags::CLONE_NEWNS,
            "uts" => flags |= CloneFlags::CLONE_NEWUTS,
            "ipc" => flags |= CloneFlags::CLONE_NEWIPC,
            "network" => flags |= CloneFlags::CLONE_NEWNET,
            "user" => flags |= CloneFlags::CLONE_NEWUSER,
            unsupported => bail!("unsupported OCI Linux namespace type: {unsupported}"),
        }
    }

    Ok(flags)
}

pub fn effective_namespace_flags<S: AsRef<str>>(
    namespaces: &[S],
    network_mode: NetworkMode,
    userns_mode: UserNamespaceMode,
) -> Result<CloneFlags> {
    let flags = namespace_flags(namespaces)?;
    let flags = apply_network_mode(flags, network_mode);
    Ok(apply_userns_mode(flags, userns_mode))
}

fn apply_network_mode(mut flags: CloneFlags, network_mode: NetworkMode) -> CloneFlags {
    match network_mode {
        NetworkMode::Host => flags.remove(CloneFlags::CLONE_NEWNET),
        NetworkMode::None | NetworkMode::Bridge => flags.insert(CloneFlags::CLONE_NEWNET),
    }

    flags
}

fn apply_userns_mode(mut flags: CloneFlags, userns_mode: UserNamespaceMode) -> CloneFlags {
    match userns_mode {
        UserNamespaceMode::Host => flags.remove(CloneFlags::CLONE_NEWUSER),
        UserNamespaceMode::Private(_) => flags.insert(CloneFlags::CLONE_NEWUSER),
    }

    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn maps_supported_namespaces_to_clone_flags() {
        let flags = namespace_flags(&names(&["pid", "mount", "uts", "ipc", "network", "user"]))
            .expect("supported namespaces should map");

        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(flags.contains(CloneFlags::CLONE_NEWUTS));
        assert!(flags.contains(CloneFlags::CLONE_NEWIPC));
        assert!(flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }

    #[test]
    fn rejects_unknown_namespaces() {
        assert!(namespace_flags(&names(&["pid", "unsupported"])).is_err());
    }

    #[test]
    fn applies_runtime_network_and_user_namespace_modes() {
        let flags = effective_namespace_flags(
            &names(&["pid", "network", "user"]),
            NetworkMode::Host,
            UserNamespaceMode::Host,
        )
        .expect("supported namespaces should map");

        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(!flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(!flags.contains(CloneFlags::CLONE_NEWUSER));

        let flags = effective_namespace_flags(
            &names(&["pid"]),
            NetworkMode::None,
            UserNamespaceMode::Private(crate::userns::UserNamespaceMap {
                host_uid: 1000,
                host_gid: 1000,
            }),
        )
        .expect("supported namespaces should map");

        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }
}
