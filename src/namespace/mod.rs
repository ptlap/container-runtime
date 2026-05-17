use nix::sched::CloneFlags;

pub fn namespace_flags(namespaces: &[String]) -> CloneFlags {
    let mut flags = CloneFlags::empty();

    for namespace in namespaces {
        match namespace.as_str() {
            "pid" => flags |= CloneFlags::CLONE_NEWPID,
            "mount" => flags |= CloneFlags::CLONE_NEWNS,
            "uts" => flags |= CloneFlags::CLONE_NEWUTS,
            "ipc" => flags |= CloneFlags::CLONE_NEWIPC,
            "network" => flags |= CloneFlags::CLONE_NEWNET,
            "user" => flags |= CloneFlags::CLONE_NEWUSER,
            _ => {}
        }
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
        let flags = namespace_flags(&names(&["pid", "mount", "uts", "ipc", "network", "user"]));

        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(flags.contains(CloneFlags::CLONE_NEWUTS));
        assert!(flags.contains(CloneFlags::CLONE_NEWIPC));
        assert!(flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }

    #[test]
    fn ignores_unknown_namespaces() {
        let flags = namespace_flags(&names(&["pid", "unsupported"]));

        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(!flags.contains(CloneFlags::CLONE_NEWNS));
    }
}
