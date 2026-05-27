//! Integration tests for the field-name signal heuristic.
//!
//! Covers: entropy gate (pass / fail), explicit FieldRule takes precedence,
//! kind:allow suppresses replacement, --no-field-signal disables heuristic,
//! user-defined kind:field-name entries via secrets file.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_file(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

fn write_json_profile(dir: &tempfile::TempDir, filename: &str) -> std::path::PathBuf {
    // Minimal profile: json processor, no explicit FieldRules — field-name
    // signals are the only mechanism that can fire.
    let content = r#"[{"processor":"json","extensions":[".json"],"fields":[]}]"#;
    write_file(dir.path(), filename, content)
}

fn sanitize_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sanitize"));
    cmd.stdin(std::process::Stdio::null());
    cmd
}

// ---------------------------------------------------------------------------
// 1. High-entropy password field is replaced
// ---------------------------------------------------------------------------

#[test]
fn high_entropy_password_field_is_replaced() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    // Value has high entropy (random-looking hex string, ~4.0 bits/char).
    let input = write_file(
        dir.path(),
        "config.json",
        r#"{"password":"a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"}"#,
    );
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        !out.contains("a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"),
        "high-entropy password value should have been replaced; got: {out}"
    );
}

// ---------------------------------------------------------------------------
// 2. Low-entropy value on a password field is NOT replaced
// ---------------------------------------------------------------------------

#[test]
fn low_entropy_password_field_is_not_replaced() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    // "disabled" has entropy ~2.5 bits/char — below both thresholds.
    let input = write_file(dir.path(), "config.json", r#"{"password":"disabled"}"#);
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        out.contains("\"disabled\""),
        "low-entropy value should pass through unchanged; got: {out}"
    );
}

// ---------------------------------------------------------------------------
// 3. enum-like token_type value is NOT replaced
// ---------------------------------------------------------------------------

#[test]
fn enum_token_type_is_not_replaced() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    // "Bearer" entropy ≈ 2.4 — below the medium threshold (3.5).
    let input = write_file(dir.path(), "config.json", r#"{"token_type":"Bearer"}"#);
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        out.contains("\"Bearer\""),
        "low-entropy Bearer token_type should pass through; got: {out}"
    );
}

// ---------------------------------------------------------------------------
// 4. Explicit FieldRule takes precedence over field-name signal
// ---------------------------------------------------------------------------

#[test]
fn explicit_field_rule_takes_precedence() {
    let dir = tempdir().unwrap();

    // Profile with an explicit rule on "password" using a custom category.
    let profile_content = r#"[{
        "processor": "json",
        "extensions": [".json"],
        "fields": [{"pattern": "password", "category": "custom:explicit_rule"}]
    }]"#;
    let profile = write_file(dir.path(), "profile.json", profile_content);

    let input = write_file(
        dir.path(),
        "config.json",
        r#"{"password":"a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"}"#,
    );
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    // Value should be replaced (by the explicit rule, not the signal — same outcome).
    assert!(
        !out.contains("a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"),
        "explicit rule should replace the value; got: {out}"
    );
}

// ---------------------------------------------------------------------------
// 5. --no-field-signal disables the heuristic
// ---------------------------------------------------------------------------

#[test]
fn no_field_signal_disables_heuristic() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    // High-entropy value on a "secret" key — would normally be flagged.
    let input = write_file(
        dir.path(),
        "config.json",
        r#"{"secret":"a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"}"#,
    );
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "--no-field-signal",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        out.contains("a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"),
        "--no-field-signal should leave high-entropy secret value untouched; got: {out}"
    );
}

// ---------------------------------------------------------------------------
// 6. User-defined kind:field-name entry in secrets file
// ---------------------------------------------------------------------------

#[test]
fn user_defined_field_name_signal() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    // Custom signal: flag any field named "db_pass" with threshold 3.0.
    let secrets_content = r#"[{
        "kind": "field-name",
        "pattern": "^db_pass$",
        "category": "custom:credential",
        "label": "db-pass-signal",
        "threshold": 3.0
    }]"#;
    let secrets = write_file(dir.path(), "secrets.json", secrets_content);

    let input = write_file(
        dir.path(),
        "config.json",
        r#"{"db_pass":"a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"}"#,
    );
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--secrets-file",
            secrets.to_str().unwrap(),
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        !out.contains("a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"),
        "user-defined field-name signal should replace db_pass value; got: {out}"
    );
}

// ---------------------------------------------------------------------------
// Compound field-name matching (previously required exact match)
// ---------------------------------------------------------------------------

#[test]
fn compound_field_name_password_hash_is_replaced() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    // "password_hash" contains "password" — should trigger the strong signal
    // now that patterns are unanchored substring matches.
    let input = write_file(
        dir.path(),
        "config.json",
        r#"{"password_hash":"a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"}"#,
    );
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        !out.contains("a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"),
        "compound field 'password_hash' should trigger the strong signal; got: {out}"
    );
}

#[test]
fn compound_field_name_db_password_is_replaced() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    let input = write_file(
        dir.path(),
        "config.json",
        r#"{"db_password":"a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"}"#,
    );
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        !out.contains("a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"),
        "compound field 'db_password' should trigger the strong signal; got: {out}"
    );
}

#[test]
fn compound_field_access_token_is_replaced() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    // "access_token" contains "token" (medium signal, threshold 3.5).
    // The value has entropy well above 3.5.
    let input = write_file(
        dir.path(),
        "config.json",
        r#"{"access_token":"sk-a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1XYZ9"}"#,
    );
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        !out.contains("sk-a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1XYZ9"),
        "compound field 'access_token' should trigger the medium signal; got: {out}"
    );
}

// ---------------------------------------------------------------------------
// KV processor field-name signal support
// ---------------------------------------------------------------------------

fn write_kv_profile(dir: &tempfile::TempDir, filename: &str) -> std::path::PathBuf {
    let content = r#"[{"processor":"key_value","extensions":[".env"],"fields":[]}]"#;
    write_file(dir.path(), filename, content)
}

#[test]
fn kv_field_signal_replaces_high_entropy_env_var() {
    let dir = tempdir().unwrap();
    let profile = write_kv_profile(&dir, "profile.json");

    // DB_PASSWORD contains "password" — strong signal, threshold 3.0.
    let input = write_file(
        dir.path(),
        "config.env",
        "DB_PASSWORD=a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1\n",
    );
    let output = dir.path().join("config-sanitized.env");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        !out.contains("a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1"),
        "KV field 'DB_PASSWORD' should trigger field-name signal; got: {out}"
    );
    assert!(
        out.starts_with("DB_PASSWORD="),
        "key and delimiter should be preserved; got: {out}"
    );
}

#[test]
fn kv_field_signal_low_entropy_not_replaced() {
    let dir = tempdir().unwrap();
    let profile = write_kv_profile(&dir, "profile.json");

    // TOKEN_TYPE contains "token" — medium signal — but "Bearer" has
    // entropy ~1.9, well below the 3.5 threshold.
    let input = write_file(dir.path(), "config.env", "TOKEN_TYPE=Bearer\n");
    let output = dir.path().join("config-sanitized.env");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        out.contains("Bearer"),
        "low-entropy 'Bearer' should pass through unchanged; got: {out}"
    );
}

#[test]
fn kv_api_key_replaced_in_quoted_value() {
    let dir = tempdir().unwrap();
    let profile = write_kv_profile(&dir, "profile.json");

    // API_KEY contains "api_key" (medium signal). Value is high-entropy.
    let input = write_file(
        dir.path(),
        "config.env",
        "API_KEY=\"sk-a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1XYZ9\"\n",
    );
    let output = dir.path().join("config-sanitized.env");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        !out.contains("sk-a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1XYZ9"),
        "KV field 'API_KEY' with quoted value should be replaced; got: {out}"
    );
    assert!(
        out.contains('"'),
        "double-quote style should be preserved; got: {out}"
    );
}

// ---------------------------------------------------------------------------
// 7. api_key with high entropy is replaced (medium-signal group)
// ---------------------------------------------------------------------------

#[test]
fn api_key_high_entropy_is_replaced() {
    let dir = tempdir().unwrap();
    let profile = write_json_profile(&dir, "profile.json");

    // Value has entropy well above 3.5 — should fire the medium-signal group.
    let input = write_file(
        dir.path(),
        "config.json",
        r#"{"api_key":"sk-a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1XYZ9"}"#,
    );
    let output = dir.path().join("config-sanitized.json");

    let status = sanitize_cmd()
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--use-default",
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success(), "expected exit 0");
    let out = fs::read_to_string(&output).unwrap();
    assert!(
        !out.contains("sk-a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1XYZ9"),
        "high-entropy api_key value should be replaced; got: {out}"
    );
}
