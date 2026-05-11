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
