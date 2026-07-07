//! Benchmark for replacement store throughput.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use scour_secrets::category::Category;
use scour_secrets::generator::HmacGenerator;
use scour_secrets::store::MappingStore;
use std::sync::Arc;

fn bench_insert_unique(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert_unique");
    for count in [1_000, 10_000, 100_000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                let gen = Arc::new(HmacGenerator::new([42u8; 32]));
                let store = MappingStore::new(gen, None);
                for i in 0..count {
                    store
                        .get_or_insert(&Category::Email, &format!("user{}@test.com", i))
                        .unwrap();
                }
            });
        });
    }
    group.finish();
}

fn bench_insert_duplicate(c: &mut Criterion) {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = MappingStore::new(gen, None);
    // Pre-populate 10k entries.
    for i in 0..10_000 {
        store
            .get_or_insert(&Category::Email, &format!("user{}@test.com", i))
            .unwrap();
    }

    c.bench_function("lookup_existing_10k", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let key = format!("user{}@test.com", idx % 10_000);
            store.get_or_insert(&Category::Email, &key).unwrap();
            idx += 1;
        });
    });
}

fn bench_concurrent_insert(c: &mut Criterion) {
    c.bench_function("concurrent_8threads_10k_each", |b| {
        b.iter(|| {
            let gen = Arc::new(HmacGenerator::new([42u8; 32]));
            let store = Arc::new(MappingStore::new(gen, None));
            let mut handles = vec![];
            for t in 0..8 {
                let store = Arc::clone(&store);
                handles.push(std::thread::spawn(move || {
                    for i in 0..10_000 {
                        store
                            .get_or_insert(&Category::Email, &format!("t{}-u{}@test.com", t, i))
                            .unwrap();
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

criterion_group!(
    benches,
    bench_insert_unique,
    bench_insert_duplicate,
    bench_concurrent_insert,
);
criterion_main!(benches);
