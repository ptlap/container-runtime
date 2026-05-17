use container_runtime::namespace::namespace_flags;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn namespace_flag_mapping(c: &mut Criterion) {
    let namespaces = vec![
        "pid".to_string(),
        "mount".to_string(),
        "uts".to_string(),
        "ipc".to_string(),
        "network".to_string(),
    ];

    c.bench_function("namespace_flag_mapping", |b| {
        b.iter(|| namespace_flags(black_box(&namespaces)))
    });
}

criterion_group!(benches, namespace_flag_mapping);
criterion_main!(benches);
