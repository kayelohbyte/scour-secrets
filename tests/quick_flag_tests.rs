//! Integration tests for the `--quick` flag.
//!
//! Covers:
//! - Literal values are redacted
//! - Multiple comma-separated literals in one flag
//! - Multiple --quick flags accumulate
//! - regex: prefix matches by pattern
//! - Combines correctly with a secrets file (additive, not replacing)
//! - Works with no secrets file (defaults still load)
//! - Empty pattern is rejected at validation time
//! - Non-matching literal passes through unchanged

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

fn run_stdin(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(args)
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn empty_secrets(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(&p, "[]").unwrap();
    p
}

// ---------------------------------------------------------------------------
// Literal matching
// ---------------------------------------------------------------------------

#[test]
fn quick_literal_is_redacted() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());

    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            "supersecret",
        ],
        b"value: supersecret end",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        !s.contains("supersecret"),
        "literal should be redacted; got: {s}"
    );
    assert!(
        s.contains("value:"),
        "surrounding text should survive; got: {s}"
    );
}

#[test]
fn quick_comma_separated_both_redacted() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());

    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            "tok-aaa,tok-bbb",
        ],
        b"first=tok-aaa second=tok-bbb",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        !s.contains("tok-aaa"),
        "first literal should be redacted; got: {s}"
    );
    assert!(
        !s.contains("tok-bbb"),
        "second literal should be redacted; got: {s}"
    );
}

#[test]
fn quick_repeated_flags_accumulate() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());

    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            "alpha-secret",
            "--quick",
            "beta-secret",
        ],
        b"a=alpha-secret b=beta-secret",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        !s.contains("alpha-secret"),
        "first repeated flag value should be redacted; got: {s}"
    );
    assert!(
        !s.contains("beta-secret"),
        "second repeated flag value should be redacted; got: {s}"
    );
}

// ---------------------------------------------------------------------------
// Regex prefix
// ---------------------------------------------------------------------------

#[test]
fn quick_regex_prefix_matches_by_pattern() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());

    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            r"regex:tok-[A-Za-z0-9]{8}",
        ],
        b"token tok-AbCd1234 safe",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        !s.contains("tok-AbCd1234"),
        "regex match should be redacted; got: {s}"
    );
    assert!(
        s.contains("safe"),
        "non-matching text should survive; got: {s}"
    );
}

#[test]
fn quick_regex_does_not_match_different_value() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());

    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            r"regex:tok-[A-Za-z0-9]{8}",
        ],
        b"tok-short",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    // "tok-short" is only 9 chars but regex requires exactly 8 alnum after "tok-"
    // "short" = 5 chars, so it won't match the 8-char pattern
    assert!(
        s.contains("tok-short"),
        "non-matching value should pass through; got: {s}"
    );
}

// ---------------------------------------------------------------------------
// Interaction with secrets file
// ---------------------------------------------------------------------------

#[test]
fn quick_is_additive_with_secrets_file() {
    let dir = tempdir().unwrap();
    // secrets file catches "file-secret"; --quick catches "quick-secret"
    let secrets = dir.path().join("secrets.yaml");
    fs::write(
        &secrets,
        b"- pattern: 'file-secret'\n  kind: literal\n  category: auth_token\n",
    )
    .unwrap();

    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            "quick-secret",
        ],
        b"a=file-secret b=quick-secret",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        !s.contains("file-secret"),
        "secrets-file pattern should still fire; got: {s}"
    );
    assert!(
        !s.contains("quick-secret"),
        "--quick pattern should fire too; got: {s}"
    );
}

// ---------------------------------------------------------------------------
// No secrets file — defaults still load
// ---------------------------------------------------------------------------

#[test]
fn quick_works_without_secrets_file() {
    // --quick with no -s: default balanced patterns load + the quick literal.
    // The Anthropic key format is caught by defaults; the custom literal by --quick.
    let out = run_stdin(
        &["-", "--quick", "my-one-off-value"],
        b"custom my-one-off-value end",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        !s.contains("my-one-off-value"),
        "--quick literal should be redacted without a secrets file; got: {s}"
    );
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

#[test]
fn quick_empty_pattern_is_rejected() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());
    let input = dir.path().join("in.txt");
    fs::write(&input, b"hello").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            "",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .output()
        .unwrap();

    assert!(!out.status.success(), "empty --quick should fail");
    assert!(
        stderr(&out).contains("empty"),
        "error should mention empty; got: {}",
        stderr(&out)
    );
}

#[test]
fn quick_empty_regex_prefix_is_rejected() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());
    let input = dir.path().join("in.txt");
    fs::write(&input, b"hello").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            "regex:",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .output()
        .unwrap();

    assert!(!out.status.success(), "empty regex: pattern should fail");
    assert!(
        stderr(&out).contains("empty"),
        "error should mention empty; got: {}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// Multiple invalid patterns — all reported
// ---------------------------------------------------------------------------

#[test]
fn quick_multiple_invalid_patterns_all_reported() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());
    let input = dir.path().join("in.txt");
    fs::write(&input, b"hello").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            "regex:(unclosed-first",
            "--quick",
            "regex:(unclosed-second",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "multiple invalid patterns should fail"
    );
    let err = stderr(&out);
    assert!(
        err.contains("position 0") && err.contains("position 1"),
        "all errors must be reported; got: {err}",
    );
}

// ---------------------------------------------------------------------------
// Label format preserved in report
// ---------------------------------------------------------------------------

#[test]
fn quick_regex_label_preserved_in_report() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());
    let report_path = dir.path().join("report.json");

    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--dry-run",
            "--quick",
            "regex:SK-[A-Z]{8}",
            "--report",
            report_path.to_str().unwrap(),
        ],
        b"token SK-ABCDEFGH end",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let report = fs::read_to_string(&report_path).unwrap();
    assert!(
        report.contains("quick:regex:SK-[A-Z]{8}"),
        "report must preserve regex: prefix in label; got:\n{report}",
    );
}

// ---------------------------------------------------------------------------
// Deterministic mode
// ---------------------------------------------------------------------------

#[test]
fn quick_deterministic_produces_stable_replacement() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());

    // Run twice with the same seed — the replacement for "mysecret" must be identical.
    let run = |n: u8| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
            .args([
                "-",
                "-s",
                secrets.to_str().unwrap(),
                "--quick",
                "mysecret",
                "--deterministic",
            ])
            .env("SCOUR_SECRETS_LOG", "error")
            .env("SCOUR_SECRETS_NO_SETTINGS", "1")
            .env("SCOUR_SECRETS_PASSWORD", format!("testpass{n}"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"value: mysecret end")
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let out1 = run(0);
    let out2 = run(0);
    assert!(out1.status.success(), "stderr: {}", stderr(&out1));
    assert!(out2.status.success(), "stderr: {}", stderr(&out2));

    let s1 = stdout(&out1);
    let s2 = stdout(&out2);
    assert!(
        !s1.contains("mysecret"),
        "literal should be redacted; got: {s1}"
    );
    assert_eq!(
        s1, s2,
        "same seed must produce identical output on repeated runs"
    );

    // Different seed must produce a different replacement.
    let out3 = run(1);
    assert!(out3.status.success(), "stderr: {}", stderr(&out3));
    let s3 = stdout(&out3);
    assert!(
        !s3.contains("mysecret"),
        "literal should be redacted with different seed; got: {s3}"
    );
    assert_ne!(s1, s3, "different seed must produce different replacement");
}

// ---------------------------------------------------------------------------
// Non-matching literal passes through
// ---------------------------------------------------------------------------

#[test]
fn quick_non_matching_literal_leaves_text_unchanged() {
    let dir = tempdir().unwrap();
    let secrets = empty_secrets(dir.path());

    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--quick",
            "not-in-input",
        ],
        b"hello world",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "hello world");
}
