//! Integration tests for the reporting module.
//!
//! Tests cover:
//! - Report generation from scanner stats
//! - JSON serialization correctness
//! - Thread-safe concurrent recording
//! - No secret values leak into reports
//! - Large-file and multi-file aggregation
//! - Report + scanner end-to-end integration

use scour_secrets::category::Category;
use scour_secrets::generator::HmacGenerator;
use scour_secrets::report::{FileReport, ReportBuilder, ReportMetadata};
use scour_secrets::scanner::{ScanConfig, ScanPattern, StreamScanner};
use scour_secrets::store::MappingStore;
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_metadata() -> ReportMetadata {
    ReportMetadata::new(env!("CARGO_PKG_VERSION"), "2026-03-01T00:00:00Z")
        .with_deterministic(true)
        .with_chunk_size(1_048_576)
        .with_threads(Some(4))
        .with_secrets_file(Some("secrets.enc".into()))
}

fn make_scanner(patterns: Vec<ScanPattern>) -> (Arc<StreamScanner>, Arc<MappingStore>) {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let scanner =
        Arc::new(StreamScanner::new(patterns, Arc::clone(&store), ScanConfig::default()).unwrap());
    (scanner, store)
}

fn email_pattern() -> ScanPattern {
    ScanPattern::from_regex(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        Category::Email,
        "email",
    )
    .unwrap()
}

fn ipv4_pattern() -> ScanPattern {
    ScanPattern::from_regex(
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        Category::IpV4,
        "ipv4",
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// End-to-end: scan + report
// ---------------------------------------------------------------------------

#[test]
fn scan_and_report_integration() {
    let (scanner, _store) = make_scanner(vec![email_pattern(), ipv4_pattern()]);
    let input = b"Contact alice@corp.com at 10.0.0.1 or bob@corp.com at 192.168.1.1";

    let (_output, stats) = scanner.scan_bytes(input).unwrap();

    let builder = ReportBuilder::new(test_metadata());
    builder.record_file(FileReport::from_scan_stats("test.log", &stats, "scanner"));
    let report = builder.finish();

    assert_eq!(report.summary.total_files, 1);
    assert_eq!(report.summary.total_matches, 4);
    assert_eq!(*report.summary.pattern_counts.get("email").unwrap(), 2);
    assert_eq!(*report.summary.pattern_counts.get("ipv4").unwrap(), 2);

    // Serialize and verify JSON structure.
    let json = report.to_json_pretty().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["summary"]["total_matches"], 4);
    assert_eq!(parsed["files"][0]["path"], "test.log");
    assert_eq!(parsed["files"][0]["method"], "scanner");
    assert_eq!(parsed["metadata"]["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn report_never_contains_secrets() {
    let secret = "super-secret-api-key-12345";
    let pat = ScanPattern::from_literal(secret, Category::Custom("api_key".into()), "openai_key")
        .unwrap();

    let (scanner, _store) = make_scanner(vec![pat]);
    let input = format!("token={secret}&other=value");
    let (_output, stats) = scanner.scan_bytes(input.as_bytes()).unwrap();

    let builder = ReportBuilder::new(test_metadata());
    builder.record_file(FileReport::from_scan_stats("config.env", &stats, "scanner"));
    let report = builder.finish();
    let json = report.to_json_pretty().unwrap();

    // The original secret must never appear in the report.
    assert!(!json.contains(secret));
    // The pattern label is fine — it's user-defined metadata, not the secret.
    assert!(json.contains("openai_key"));
    // Verify match was counted.
    assert_eq!(report.summary.total_matches, 1);
}

#[test]
fn report_multiple_files_aggregation() {
    let (scanner, _store) = make_scanner(vec![email_pattern()]);
    let builder = ReportBuilder::new(test_metadata());

    let files = vec![
        ("a.log", b"alice@corp.com and bob@corp.com" as &[u8]),
        ("b.log", b"charlie@corp.com"),
        ("c.log", b"no emails here"),
    ];

    for (name, content) in &files {
        let (_out, stats) = scanner.scan_bytes(content).unwrap();
        builder.record_file(FileReport::from_scan_stats(*name, &stats, "scanner"));
    }

    let report = builder.finish();
    assert_eq!(report.summary.total_files, 3);
    assert_eq!(report.summary.total_matches, 3); // 2 + 1 + 0
    assert_eq!(report.files.len(), 3);

    // Per-file correctness.
    assert_eq!(
        report
            .files
            .iter()
            .find(|f| f.path == "a.log")
            .unwrap()
            .matches,
        2
    );
    assert_eq!(
        report
            .files
            .iter()
            .find(|f| f.path == "b.log")
            .unwrap()
            .matches,
        1
    );
    assert_eq!(
        report
            .files
            .iter()
            .find(|f| f.path == "c.log")
            .unwrap()
            .matches,
        0
    );
}

#[test]
fn concurrent_scan_and_report() {
    use std::thread;

    let (scanner, _store) = make_scanner(vec![email_pattern()]);
    let builder = Arc::new(ReportBuilder::new(test_metadata()));

    let mut handles = Vec::new();
    for i in 0..8 {
        let sc = Arc::clone(&scanner);
        let rb = Arc::clone(&builder);
        handles.push(thread::spawn(move || {
            let input = format!("thread_{i}@example.com and more_{i}@test.org");
            let (_out, stats) = sc.scan_bytes(input.as_bytes()).unwrap();
            rb.record_file(FileReport::from_scan_stats(
                format!("thread_{i}.log"),
                &stats,
                "scanner",
            ));
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let builder = Arc::try_unwrap(builder).unwrap();
    let report = builder.finish();

    assert_eq!(report.summary.total_files, 8);
    // Each thread has 2 email matches.
    assert_eq!(report.summary.total_matches, 16);
    assert_eq!(*report.summary.pattern_counts.get("email").unwrap(), 16);

    // All file entries are present (order may vary due to concurrency).
    let mut paths: Vec<String> = report.files.iter().map(|f| f.path.clone()).collect();
    paths.sort();
    for i in 0..8 {
        assert!(paths.contains(&format!("thread_{i}.log")));
    }
}

#[test]
fn report_large_file_streaming() {
    // Simulate a large file scanned in streaming mode.
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let scanner = StreamScanner::new(
        vec![email_pattern()],
        Arc::clone(&store),
        ScanConfig::new(256, 64), // small chunks to exercise streaming
    )
    .unwrap();

    // Build ~64 KiB input with emails every ~200 bytes.
    let mut input = Vec::new();
    let filler = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    let email_count = 300;
    for i in 0..email_count {
        input.extend_from_slice(filler);
        input.extend_from_slice(format!("user{}@bigcorp.example.com ", i).as_bytes());
    }

    let (_output, stats) = scanner.scan_bytes(&input).unwrap();

    let builder = ReportBuilder::new(test_metadata());
    builder.record_file(FileReport::from_scan_stats("large.log", &stats, "scanner"));
    let report = builder.finish();

    assert_eq!(report.summary.total_matches, email_count);
    assert_eq!(report.files[0].matches, email_count);
    assert!(report.summary.total_bytes_processed > 0);
    assert!(report.summary.total_bytes_output > 0);

    // JSON serialization works fine for large data.
    let json = report.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["summary"]["total_matches"], email_count);
}

#[test]
fn report_json_structure_complete() {
    let builder = ReportBuilder::new(test_metadata());
    let mut fr = FileReport::new("app.yaml", "structured:yaml");
    fr.matches = 5;
    fr.replacements = 5;
    fr.bytes_processed = 2048;
    fr.bytes_output = 2200;
    fr.pattern_counts = HashMap::from([("email".into(), 3u64), ("hostname".into(), 2)]);
    builder.record_file(fr);
    let report = builder.finish();
    let json = report.to_json_pretty().unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Top-level keys.
    assert!(v.get("metadata").is_some());
    assert!(v.get("summary").is_some());
    assert!(v.get("files").is_some());

    // Metadata.
    assert_eq!(v["metadata"]["deterministic"], true);
    assert_eq!(v["metadata"]["chunk_size"], 1_048_576);
    assert_eq!(v["metadata"]["threads"], 4);
    assert_eq!(v["metadata"]["secrets_file"], "secrets.enc");

    // Summary.
    assert_eq!(v["summary"]["total_files"], 1);
    assert_eq!(v["summary"]["total_matches"], 5);
    assert_eq!(v["summary"]["total_replacements"], 5);
    assert!(v["summary"]["duration_ms"].is_number());
    assert_eq!(v["summary"]["pattern_counts"]["email"], 3);
    assert_eq!(v["summary"]["pattern_counts"]["hostname"], 2);

    // Files array.
    let f = &v["files"][0];
    assert_eq!(f["path"], "app.yaml");
    assert_eq!(f["matches"], 5);
    assert_eq!(f["method"], "structured:yaml");
    assert_eq!(f["bytes_processed"], 2048);
}

#[test]
fn report_dry_run_metadata() {
    let mut meta = test_metadata();
    meta.dry_run = true;
    let builder = ReportBuilder::new(meta);
    let report = builder.finish();
    assert!(report.metadata.dry_run);
    let json = report.to_json().unwrap();
    assert!(json.contains("\"dry_run\":true"));
}

#[test]
fn empty_scan_produces_valid_report() {
    let (scanner, _store) = make_scanner(vec![email_pattern()]);
    let (_output, stats) = scanner.scan_bytes(b"no secrets here").unwrap();

    let builder = ReportBuilder::new(test_metadata());
    builder.record_file(FileReport::from_scan_stats("clean.txt", &stats, "scanner"));
    let report = builder.finish();

    assert_eq!(report.summary.total_matches, 0);
    assert_eq!(report.summary.total_replacements, 0);
    assert_eq!(report.files[0].matches, 0);
    assert!(report.files[0].pattern_counts.is_empty());

    // Still produces valid JSON.
    let json = report.to_json().unwrap();
    let _: serde_json::Value = serde_json::from_str(&json).unwrap();
}
