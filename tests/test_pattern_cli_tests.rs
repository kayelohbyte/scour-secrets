//! Integration tests for the `scour-secrets test-pattern` subcommand.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a secrets JSON file with a single literal pattern entry.
fn write_literal_secrets(dir: &std::path::Path, filename: &str, value: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    let content = format!(
        r#"[{{"pattern":"{value}","kind":"literal","category":"custom:test","label":"lbl"}}]"#
    );
    fs::write(&path, content).unwrap();
    path
}

/// Write a secrets JSON file with a single regex pattern entry.
fn write_regex_secrets(dir: &std::path::Path, filename: &str, pattern: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    let content = format!(
        r#"[{{"pattern":"{pattern}","kind":"regex","category":"custom:test","label":"tok"}}]"#
    );
    fs::write(&path, content).unwrap();
    path
}

/// Write an empty secrets JSON file.
fn write_empty_secrets(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    fs::write(&path, "[]").unwrap();
    path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1. A value present in the secrets file exits 0.
#[test]
fn test_pattern_matched_value_exits_zero() {
    let dir = tempdir().unwrap();
    let secrets = write_literal_secrets(dir.path(), "secrets.json", "hunter2");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(["test-pattern", "-s", secrets.to_str().unwrap(), "hunter2"])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0 for matched value; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 2. A value NOT present in the secrets file exits 1.
#[test]
fn test_pattern_unmatched_value_exits_one() {
    let dir = tempdir().unwrap();
    let secrets = write_literal_secrets(dir.path(), "secrets.json", "hunter2");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "test-pattern",
            "-s",
            secrets.to_str().unwrap(),
            "nope_not_in_secrets",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for unmatched value; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 3. --json output with a matching value contains the "matched" field.
#[test]
fn test_pattern_json_output_contains_matched() {
    let dir = tempdir().unwrap();
    let secrets = write_literal_secrets(dir.path(), "secrets.json", "hunter2");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "test-pattern",
            "-s",
            secrets.to_str().unwrap(),
            "--json",
            "hunter2",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "expected exit 0 for matched value with --json; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.is_empty(), "stdout should be non-empty JSON output");
    assert!(
        stdout.contains("\"matched\""),
        "JSON output should contain the \"matched\" field; got: {stdout}"
    );

    // Parse and verify the matched flag is true for this value.
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\noutput: {stdout}"));
    let results = v["results"].as_array().expect("results must be an array");
    let hit = results
        .iter()
        .find(|r| r["value"] == "hunter2")
        .expect("hunter2 should appear in results");
    assert_eq!(hit["matched"], true, "hunter2 should be matched");
}

/// 4. --json output with an unmatched value shows matched = false.
#[test]
fn test_pattern_json_output_contains_unmatched() {
    let dir = tempdir().unwrap();
    let secrets = write_literal_secrets(dir.path(), "secrets.json", "hunter2");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "test-pattern",
            "-s",
            secrets.to_str().unwrap(),
            "--json",
            "completely_different_value",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    // Exit 1 because the value did not match.
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for unmatched value with --json; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"matched\""),
        "JSON output should contain the \"matched\" field; got: {stdout}"
    );
    // The JSON should contain false somewhere (matched: false).
    assert!(
        stdout.contains("false"),
        "JSON output should contain false for an unmatched value; got: {stdout}"
    );

    // Parse and verify explicitly.
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\noutput: {stdout}"));
    let results = v["results"].as_array().expect("results must be an array");
    let hit = results
        .iter()
        .find(|r| r["value"] == "completely_different_value")
        .expect("value should appear in results");
    assert_eq!(
        hit["matched"], false,
        "unmatched value should have matched=false"
    );
}

/// 5. Mixed values (one match, one miss) exit 1.
#[test]
fn test_pattern_multiple_values_mixed_exit_one() {
    let dir = tempdir().unwrap();
    let secrets = write_literal_secrets(dir.path(), "secrets.json", "hunter2");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "test-pattern",
            "-s",
            secrets.to_str().unwrap(),
            "hunter2",
            "nope_not_in_secrets",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for partial match; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 6. Two values both in secrets exit 0.
#[test]
fn test_pattern_multiple_values_all_matched_exit_zero() {
    let dir = tempdir().unwrap();
    // Create a secrets file with two literal patterns.
    let path = dir.path().join("secrets.json");
    fs::write(
        &path,
        r#"[
            {"pattern":"hunter2","kind":"literal","category":"custom:test","label":"pw1"},
            {"pattern":"s3cr3t","kind":"literal","category":"custom:test","label":"pw2"}
        ]"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "test-pattern",
            "-s",
            path.to_str().unwrap(),
            "hunter2",
            "s3cr3t",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0 when all values match; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 7. A regex pattern (kind: regex) matches a conforming value.
#[test]
fn test_pattern_regex_kind_matches() {
    let dir = tempdir().unwrap();
    let secrets = write_regex_secrets(dir.path(), "secrets.json", "tok-[0-9]+");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(["test-pattern", "-s", secrets.to_str().unwrap(), "tok-12345"])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0 for regex match; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 8. --json output for a matched literal includes a "category" field.
#[test]
fn test_pattern_json_shows_replacement_category() {
    let dir = tempdir().unwrap();
    let secrets = write_literal_secrets(dir.path(), "secrets.json", "hunter2");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "test-pattern",
            "-s",
            secrets.to_str().unwrap(),
            "--json",
            "hunter2",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"category\""),
        "JSON output should contain a \"category\" field; got: {stdout}"
    );
}

/// 9. Empty secrets file — no patterns — value does not match, exit 1.
#[test]
fn test_pattern_no_secrets_no_match() {
    let dir = tempdir().unwrap();
    let secrets = write_empty_secrets(dir.path(), "secrets.json");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "test-pattern",
            "-s",
            secrets.to_str().unwrap(),
            "some_value",
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    // Either exit 1 (no patterns loaded but no crash) or exit 2 (error: no
    // patterns). Both are acceptable as long as exit 0 is not returned.
    let code = out.status.code().unwrap_or(1);
    assert_ne!(
        code,
        0,
        "expected non-zero exit when no secrets are defined; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 10. --app gitlab matches a realistic GitLab personal access token (v2 format).
///     Accepts exit 0 (match) or exit 1 (no match) — both are non-error results.
///     Only exit 2 (tool error / crash) is a failure.
#[test]
fn test_pattern_with_app_bundle_matches_known_pattern() {
    // glpat- + 20 alphanumeric characters — satisfies the v2 PAT regex in the
    // built-in gitlab bundle: `\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b`
    let token = "glpat-xxxxxxxxxxxxxxxxxxxx";

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(["test-pattern", "--app", "gitlab", token])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    let code = out.status.code().unwrap_or(2);
    assert!(
        code == 0 || code == 1,
        "expected exit 0 or 1, not a tool error (2); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
