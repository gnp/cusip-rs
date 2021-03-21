use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use cusip::checksum::checksum_simple;
use cusip::checksum::checksum_table;

const PAYLOADS: [&str; 3] = [
    "00000000", // The least taxing input for the functional style because digit expansion is rarely needed
    "03783310", // A typical input (this is the payload for the Apple (AAPL) common stock CUSIP)
    "ZZZZZZZZ", // The most taxing input for the functional style because digit expansion is maximized
];

fn bench_checksums(c: &mut Criterion) {
    println!("bench_checksums module path is: {}", std::module_path!());

    let mut group = c.benchmark_group("Checksum");
    for p in PAYLOADS.iter() {
        group.bench_with_input(BenchmarkId::new("Simple", p), p, |b, p| {
            b.iter(|| checksum_simple(p.as_bytes()))
        });
        group.bench_with_input(BenchmarkId::new("Table", p), p, |b, p| {
            b.iter(|| checksum_table(p.as_bytes()))
        });
    }
}

criterion_group!(benches, bench_checksums);
criterion_main!(benches);
