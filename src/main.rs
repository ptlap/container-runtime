use container_runtime::spec::config::load_config;

fn main() -> anyhow::Result<()> {
    let config = load_config("examples/bundle/config.json")?;

    println!("args: {:?}", config.process.args);
    println!("env: {:?}", config.process.env);
    println!("rootfs: {}", config.root.path);

    if let Some(linux) = config.linux {
        for ns in linux.namespaces {
            println!("namespace: {}", ns.namespace_type);
        }

        if let Some(resources) = linux.resources {
            if let Some(memory) = resources.memory {
                println!("memory limit: {:?}", memory.limit);
            }

            if let Some(cpu) = resources.cpu {
                println!("cpu quota: {:?}", cpu.quota);
                println!("cpu period: {:?}", cpu.period);
            }
        }
    }

    Ok(())
}
