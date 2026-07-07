//! Canary regression tests: a known sentinel value planted in a fixture must
//! never appear in any scan/sanitize output.
//!
//! The sanitizer's whole job is to keep secret *values* out of the artifacts it
//! produces. These tests guard against regressions where a finding record, a
//! match location, an error message, a serialized report (JSON / SARIF / HTML),
//! or an `--extract-context` snippet might echo the raw value it is meant to
//! redact. We plant a unique `CANARY` token and assert it is absent from every
//! output stream and file the tool writes.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

/// Sentinel value that must never leak into any output stream or artifact.
/// Deliberately distinctive so a substring match is unambiguous.
const CANARY: &str = "CANARY_8f3a9b2c_DO_NOT_LEAK_4e1d";

/// Fixture with the canary planted on INFO, WARN, and ERROR lines, so that
/// `--extract-context` (keyed on error/warn) is *forced* to capture lines that
/// originally held the secret — making the redaction assertion non-vacuous.
fn fixture() -> String {
    format!(
        "2026-06-16 INFO  service booting normally\n\
         2026-06-16 INFO  auth token={CANARY} loaded\n\
         2026-06-16 ERROR connection refused to upstream\n\
         2026-06-16 WARN  retry with credential {CANARY}\n\
         2026-06-16 ERROR failed: secret was {CANARY} during crash\n\
         2026-06-16 INFO  shutdown clean\n"
    )
}

/// Secrets file matching the canary as an exact literal.
fn canary_secrets(dir: &Path) -> PathBuf {
    let p = dir.join("secrets.json");
    fs::write(
        &p,
        format!(
            r#"[{{"pattern":"{CANARY}","kind":"literal","category":"custom:canary","label":"canary_token"}}]"#
        ),
    )
    .unwrap();
    p
}

fn write_fixture(dir: &Path) -> PathBuf {
    let p = dir.join("app.log");
    fs::write(&p, fixture()).unwrap();
    p
}

/// Read a file with retry on transient permission errors.
///
/// On Windows CI, real-time AV (Defender) can briefly hold a lock on a file
/// right after `AtomicFileWriter::finish` renames it into place. Mirrors the
/// helper in `extract_context_tests.rs`.
fn read_to_string_retry(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match fs::read_to_string(path) {
            Ok(s) => return s,
            Err(e)
                if (e.kind() == ErrorKind::PermissionDenied || e.raw_os_error() == Some(5))
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("read {}: {e}", path.display()),
        }
    }
}

#[track_caller]
fn assert_no_canary(label: &str, text: &str) {
    assert!(
        !text.contains(CANARY),
        "canary value leaked in {label}:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// `scour-secrets scan` (dry-run detector) — every output mode
// ---------------------------------------------------------------------------

#[test]
fn scan_human_output_hides_canary() {
    let dir = tempdir().unwrap();
    let s = canary_secrets(dir.path());
    let input = write_fixture(dir.path());

    // No SCOUR_SECRETS_LOG override: exercise the default (chattier) verbosity that
    // prints the "Matched: N canary_token" tally — a stronger leak test.
    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(["scan", input.to_str().unwrap(), "-s", s.to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(2),
        "scan should exit 2 when secrets match"
    );
    assert_no_canary("scan stdout", &String::from_utf8_lossy(&out.stdout));
    assert_no_canary("scan stderr", &String::from_utf8_lossy(&out.stderr));
}

#[test]
fn scan_findings_ndjson_hides_canary() {
    let dir = tempdir().unwrap();
    let s = canary_secrets(dir.path());
    let input = write_fixture(dir.path());

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--findings",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Sanity: findings NDJSON actually ran and reported the matches by label.
    assert!(
        stdout.contains("canary_token") && stdout.contains("\"matches\":3"),
        "expected findings NDJSON with 3 canary_token matches, got: {stdout}"
    );
    assert_no_canary("findings stdout", &stdout);
    assert_no_canary("findings stderr", &String::from_utf8_lossy(&out.stderr));
}

/// Shared body for the JSON / SARIF / HTML report formats.
fn scan_report_format_hides_canary(format: &str, ext: &str) {
    let dir = tempdir().unwrap();
    let s = canary_secrets(dir.path());
    let input = write_fixture(dir.path());
    let report = dir.path().join(format!("report.{ext}"));

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "-r",
            report.to_str().unwrap(),
            "--report-format",
            format,
        ])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(2),
        "{format}: scan should exit 2 on matches"
    );
    assert!(report.exists(), "{format}: report file was not created");

    assert_no_canary(
        &format!("scan {format} stdout"),
        &String::from_utf8_lossy(&out.stdout),
    );
    assert_no_canary(
        &format!("scan {format} stderr"),
        &String::from_utf8_lossy(&out.stderr),
    );
    assert_no_canary(&format!("{format} report"), &read_to_string_retry(&report));
}

#[test]
fn scan_json_report_hides_canary() {
    scan_report_format_hides_canary("json", "json");
}

#[test]
fn scan_sarif_report_hides_canary() {
    scan_report_format_hides_canary("sarif", "sarif");
}

#[test]
fn scan_html_report_hides_canary() {
    scan_report_format_hides_canary("html", "html");
}

// ---------------------------------------------------------------------------
// `--extract-context` (real, mutating run) — the snippet path
// ---------------------------------------------------------------------------

/// A real (non-dry-run) `--extract-context` run captures error/warn lines —
/// which in the fixture originally held the canary — into the report. Because
/// context is extracted from the *already-sanitized* bytes, the snippets must
/// contain the redaction placeholder, never the raw value.
///
/// Input is piped via stdin (output to stdout) to sidestep the Windows
/// file-output AV lock noted in `extract_context_tests.rs`.
#[test]
fn extract_context_snippets_hide_canary() {
    let dir = tempdir().unwrap();
    let s = canary_secrets(dir.path());
    let report = dir.path().join("report.json");

    let mut child = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "-",
            "-s",
            s.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            "--extract-context",
            "--context-lines",
            "1",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("SCOUR_SECRETS_LOG", "error")
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fixture().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Sanitized output is written to stdout: canary replaced by a placeholder.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("__SANITIZED_"),
        "expected canary to be replaced with a placeholder, got: {stdout}"
    );
    assert_no_canary("sanitized stdout", &stdout);

    // Non-vacuous proof: context extraction actually ran and embedded snippets
    // of the error/warn lines, with the canary redacted inside them.
    let report_text = read_to_string_retry(&report);
    assert!(
        report_text.contains("log_context"),
        "report missing log_context block: {report_text}"
    );
    assert!(
        report_text.contains("__SANITIZED_"),
        "context snippet should carry the redaction placeholder: {report_text}"
    );
    assert_no_canary("extract-context report", &report_text);
}
