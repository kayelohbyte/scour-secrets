//! End-to-end benchmark for the streaming scanner and archive processor.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rayon::prelude::*;
use scour_secrets::category::Category;
use scour_secrets::generator::HmacGenerator;
use scour_secrets::processor::archive::ArchiveProcessor;
use scour_secrets::processor::ProcessorRegistry;
use scour_secrets::scanner::{ScanConfig, ScanPattern, StreamScanner};
use scour_secrets::store::MappingStore;
use std::io::Cursor;
use std::sync::Arc;

/// Build a scanner with only literal patterns (exercises the Aho-Corasick path).
fn build_literal_scanner(chunk_size: usize) -> Arc<StreamScanner> {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let patterns = vec![
        ScanPattern::from_literal("SECRET_KEY=", Category::AuthToken, "secret_key").unwrap(),
        ScanPattern::from_literal("password=", Category::AuthToken, "password").unwrap(),
        ScanPattern::from_literal("api_key=", Category::AuthToken, "api_key").unwrap(),
        ScanPattern::from_literal("Bearer ", Category::AuthToken, "bearer").unwrap(),
        ScanPattern::from_literal("Authorization:", Category::AuthToken, "auth_header").unwrap(),
    ];
    let config = ScanConfig::new(chunk_size, 4096);
    Arc::new(StreamScanner::new(patterns, store, config).unwrap())
}

/// Build a scanner with both literal and regex patterns (exercises both paths together).
fn build_mixed_scanner(chunk_size: usize) -> Arc<StreamScanner> {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let patterns = vec![
        ScanPattern::from_literal("SECRET_KEY=", Category::AuthToken, "secret_key").unwrap(),
        ScanPattern::from_literal("password=", Category::AuthToken, "password").unwrap(),
        ScanPattern::from_literal("api_key=", Category::AuthToken, "api_key").unwrap(),
        ScanPattern::from_regex(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Category::Email,
            "email",
        )
        .unwrap(),
        ScanPattern::from_regex(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            Category::IpV4,
            "ipv4",
        )
        .unwrap(),
    ];
    let config = ScanConfig::new(chunk_size, 4096);
    Arc::new(StreamScanner::new(patterns, store, config).unwrap())
}

/// Build a reusable scanner + store for benchmarks.
fn build_scanner(chunk_size: usize) -> Arc<StreamScanner> {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let patterns = vec![
        ScanPattern::from_regex(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Category::Email,
            "email",
        )
        .unwrap(),
        ScanPattern::from_regex(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            Category::IpV4,
            "ipv4",
        )
        .unwrap(),
        ScanPattern::from_regex(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            Category::Uuid,
            "uuid",
        )
        .unwrap(),
    ];
    let config = ScanConfig::new(chunk_size, 4096);
    Arc::new(StreamScanner::new(patterns, store, config).unwrap())
}

/// Generate synthetic input with embedded secrets every ~200 bytes.
fn generate_input(size: usize) -> Vec<u8> {
    let line = "server=192.168.1.42 user=alice@corp.com id=550e8400-e29b-41d4-a716-446655440000 lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor\n";
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let remaining = size - buf.len();
        if remaining >= line.len() {
            buf.extend_from_slice(line.as_bytes());
        } else {
            buf.extend_from_slice(&line.as_bytes()[..remaining]);
        }
    }
    buf.truncate(size);
    buf
}

/// Generate synthetic input with embedded literal secrets every ~200 bytes.
fn generate_literal_input(size: usize) -> Vec<u8> {
    let line = "config: SECRET_KEY=abc123 password=hunter2 api_key=xyzzy Bearer token=foobar Authorization: Basic dXNlcjpwYXNz lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod\n";
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let remaining = size - buf.len();
        if remaining >= line.len() {
            buf.extend_from_slice(line.as_bytes());
        } else {
            buf.extend_from_slice(&line.as_bytes()[..remaining]);
        }
    }
    buf.truncate(size);
    buf
}

/// Generate synthetic input mixing literal and regex secrets.
fn generate_mixed_input(size: usize) -> Vec<u8> {
    let line = "config: SECRET_KEY=abc123 password=hunter2 api_key=xyzzy user=alice@corp.com server=192.168.1.42 lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod\n";
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let remaining = size - buf.len();
        if remaining >= line.len() {
            buf.extend_from_slice(line.as_bytes());
        } else {
            buf.extend_from_slice(&line.as_bytes()[..remaining]);
        }
    }
    buf.truncate(size);
    buf
}

// ---------------------------------------------------------------------------
// Streaming scanner benchmarks
// ---------------------------------------------------------------------------

fn bench_scan_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_throughput");

    for &size_mib in &[1, 16, 64] {
        let size = size_mib * 1024 * 1024;
        let input = generate_input(size);
        let scanner = build_scanner(1024 * 1024);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("default_chunk", format!("{size_mib}MiB")),
            &input,
            |b, input| {
                b.iter(|| {
                    let mut output = Vec::with_capacity(input.len());
                    scanner.scan_reader(input.as_slice(), &mut output).unwrap();
                });
            },
        );
    }
    group.finish();
}

fn bench_chunk_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_size_impact");
    let size = 16 * 1024 * 1024; // 16 MiB
    let input = generate_input(size);

    for &chunk_kib in &[64, 256, 1024, 4096] {
        let chunk_size = chunk_kib * 1024;
        let scanner = build_scanner(chunk_size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("16MiB_input", format!("{chunk_kib}KiB")),
            &input,
            |b, input| {
                b.iter(|| {
                    let mut output = Vec::with_capacity(input.len());
                    scanner.scan_reader(input.as_slice(), &mut output).unwrap();
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Archive processing benchmark
// ---------------------------------------------------------------------------

fn bench_tar_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("tar_processing");

    // Build a tar archive with N files of 64 KiB each.
    for &file_count in &[10, 50] {
        let file_size = 64 * 1024;
        let file_data = generate_input(file_size);

        // Create tar in memory.
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for i in 0..file_count {
                let mut header = tar::Header::new_gnu();
                header.set_size(file_data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("file_{i}.log"), file_data.as_slice())
                    .unwrap();
            }
            builder.finish().unwrap();
        }

        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let scanner = build_scanner(1024 * 1024);
        let registry = Arc::new(ProcessorRegistry::new());
        let archive_proc = ArchiveProcessor::new(registry, scanner, store, vec![]);

        group.throughput(Throughput::Bytes(tar_buf.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("files", file_count),
            &tar_buf,
            |b, tar_buf| {
                b.iter(|| {
                    let reader = Cursor::new(tar_buf);
                    let mut output = Vec::with_capacity(tar_buf.len());
                    archive_proc.process_tar(reader, &mut output).unwrap();
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Literal-only (Aho-Corasick path) benchmark
// ---------------------------------------------------------------------------

fn bench_literal_scan_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("literal_scan_throughput");

    for &size_mib in &[1, 16, 64] {
        let size = size_mib * 1024 * 1024;
        let input = generate_literal_input(size);
        let scanner = build_literal_scanner(1024 * 1024);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("aho_corasick", format!("{size_mib}MiB")),
            &input,
            |b, input| {
                b.iter(|| {
                    let mut output = Vec::with_capacity(input.len());
                    scanner.scan_reader(input.as_slice(), &mut output).unwrap();
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Mixed literal+regex benchmark
// ---------------------------------------------------------------------------

fn bench_mixed_scan_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_scan_throughput");

    for &size_mib in &[1, 16, 64] {
        let size = size_mib * 1024 * 1024;
        let input = generate_mixed_input(size);
        let scanner = build_mixed_scanner(1024 * 1024);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("hybrid_ac_regex", format!("{size_mib}MiB")),
            &input,
            |b, input| {
                b.iter(|| {
                    let mut output = Vec::with_capacity(input.len());
                    scanner.scan_reader(input.as_slice(), &mut output).unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_scan_throughput,
    bench_chunk_sizes,
    bench_literal_scan_throughput,
    bench_mixed_scan_throughput,
    bench_tar_processing,
    bench_parallel_archive_entries,
    bench_parallel_multi_file,
);
criterion_main!(benches);

// ---------------------------------------------------------------------------
// Parallel archive-entry benchmark
//
// Compares serial (threshold = usize::MAX) vs parallel (threshold = 1) entry
// sanitization for a tar with a fixed number of file entries.
// ---------------------------------------------------------------------------

fn bench_parallel_archive_entries(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_archive_entries");

    let file_size = 64 * 1024; // 64 KiB per entry
    let file_data = generate_input(file_size);

    for &file_count in &[8, 20, 50] {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for i in 0..file_count {
                let mut header = tar::Header::new_gnu();
                header.set_size(file_data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("file_{i}.log"), file_data.as_slice())
                    .unwrap();
            }
            builder.finish().unwrap();
        }

        let make_proc = |parallel_threshold: usize| {
            let gen = Arc::new(HmacGenerator::new([42u8; 32]));
            let store = Arc::new(MappingStore::new(gen, None));
            let scanner = build_scanner(1024 * 1024);
            let registry = Arc::new(ProcessorRegistry::new());
            ArchiveProcessor::new(registry, scanner, store, vec![])
                .with_parallel_threshold(parallel_threshold)
        };

        group.throughput(Throughput::Bytes(tar_buf.len() as u64));

        // Serial baseline: parallel_threshold = usize::MAX disables par_iter.
        let serial_proc = make_proc(usize::MAX);
        group.bench_with_input(
            BenchmarkId::new(format!("serial_files{file_count}"), file_count),
            &tar_buf,
            |b, tar_buf| {
                b.iter(|| {
                    let reader = Cursor::new(tar_buf);
                    let mut output = Vec::with_capacity(tar_buf.len());
                    serial_proc.process_tar(reader, &mut output).unwrap();
                });
            },
        );

        // Parallel: parallel_threshold = 1 always uses par_iter.
        let parallel_proc = make_proc(1);
        group.bench_with_input(
            BenchmarkId::new(format!("parallel_files{file_count}"), file_count),
            &tar_buf,
            |b, tar_buf| {
                b.iter(|| {
                    let reader = Cursor::new(tar_buf);
                    let mut output = Vec::with_capacity(tar_buf.len());
                    parallel_proc.process_tar(reader, &mut output).unwrap();
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Parallel multi-file benchmark
//
// Compares sequential vs rayon::par_iter for scanning N independent files.
// Exercises the same code path as the parallel top-level file loop added in
// run_sanitize.
// ---------------------------------------------------------------------------

fn bench_parallel_multi_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_multi_file");

    let file_size = 1024 * 1024; // 1 MiB per file
    let scanner = build_mixed_scanner(1024 * 1024);

    for &file_count in &[2, 4, 8] {
        let files: Vec<Vec<u8>> = (0..file_count)
            .map(|_| generate_mixed_input(file_size))
            .collect();

        let total_bytes = (file_size * file_count) as u64;
        group.throughput(Throughput::Bytes(total_bytes));

        // Sequential baseline.
        let scanner_seq = Arc::clone(&scanner);
        group.bench_with_input(
            BenchmarkId::new(format!("sequential_files{file_count}"), file_count),
            &files,
            |b, files| {
                b.iter(|| {
                    for file in files {
                        let mut out = Vec::with_capacity(file.len());
                        scanner_seq.scan_reader(file.as_slice(), &mut out).unwrap();
                    }
                });
            },
        );

        // Parallel via rayon.
        let scanner_par = Arc::clone(&scanner);
        group.bench_with_input(
            BenchmarkId::new(format!("parallel_files{file_count}"), file_count),
            &files,
            |b, files| {
                b.iter(|| {
                    files.par_iter().for_each(|file| {
                        let mut out = Vec::with_capacity(file.len());
                        scanner_par.scan_reader(file.as_slice(), &mut out).unwrap();
                    });
                });
            },
        );
    }

    group.finish();
}
