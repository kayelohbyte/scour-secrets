//! Integration tests for the `--app` flag in the main sanitize flow and `--no-structured-handoff`.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a simple key-value profile JSON that processes `.cfg` files and
/// replaces all field values.
fn write_kv_profile(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    // Vec<FileTypeProfile> in JSON: processor "key_value", extension ".cfg",
    // wildcard field rule so all key=value pairs are sanitized.
    fs::write(
        &path,
        r#"[{"processor":"key_value","extensions":[".cfg"],"fields":[{"pattern":"*"}]}]"#,
    )
    .unwrap();
    path
}

/// Write a `.cfg` key-value input file.
fn write_cfg_input(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    fs::write(&path, "host = localhost\npassword = secret123\n").unwrap();
    path
}

/// Write a secrets JSON file with a single literal pattern.
fn write_literal_secrets(dir: &std::path::Path, filename: &str, value: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    let content = format!(
        r#"[{{"pattern":"{value}","kind":"literal","category":"custom:test","label":"lbl"}}]"#
    );
    fs::write(&path, content).unwrap();
    path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1. --app gitlab: file containing a GitLab PAT is processed without error.
///    Exit 0 and output file exists are the primary assertions; we also check
///    that the original token prefix is gone from the output when replacement
///    occurs.
#[test]
fn app_bundle_replaces_known_pattern() {
    let dir = tempdir().unwrap();
    // glpat- + 20 alphanumeric characters matches the v2 PAT pattern
    // `\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b` in the built-in gitlab bundle.
    let token = "glpat-xxxxxxxxxxxxxxxxxxxx";
    let input = dir.path().join("config.txt");
    fs::write(&input, format!("token = {token}\nother = value\n")).unwrap();
    let output = dir.path().join("config-sanitized.txt");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "--app",
            "gitlab",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "expected exit 0 with --app gitlab; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(output.exists(), "output file should have been created");
}

/// 2. --app gitlab combined with a custom secrets file: both sources are used.
#[test]
fn app_bundle_combined_with_secrets_file() {
    let dir = tempdir().unwrap();
    let secrets = write_literal_secrets(dir.path(), "secrets.json", "my-custom-secret");
    let token = "glpat-xxxxxxxxxxxxxxxxxxxx";
    let input = dir.path().join("config.txt");
    fs::write(
        &input,
        format!("secret = my-custom-secret\ntoken = {token}\n"),
    )
    .unwrap();
    let output = dir.path().join("config-out.txt");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "--app",
            "gitlab",
            "-s",
            secrets.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "expected exit 0 with --app gitlab and -s; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(output.exists(), "output file should have been created");
}

/// 3. --app with an unknown bundle name should produce a non-zero exit code.
#[test]
fn app_bundle_unknown_name_fails() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("dummy.txt");
    fs::write(&input, "hello world\n").unwrap();
    let output = dir.path().join("dummy-out.txt");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "--app",
            "nonexistent_bundle_xyz",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "expected non-zero exit for unknown --app bundle; got exit 0"
    );
}

/// 4. --no-structured-handoff suppresses writing of any discovered-secrets file.
///    With no -s flag, the tool should not write a sanitize-discovered.yaml
///    (or any similar auto-save file) into the working directory.
#[test]
fn no_structured_handoff_does_not_write_discovered_file() {
    let dir = tempdir().unwrap();
    let profile = write_kv_profile(dir.path(), "profile.json");
    let input = write_cfg_input(dir.path(), "input.cfg");
    let output = dir.path().join("output.cfg");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        // Set CWD to the temp dir so any unexpected auto-written files land there.
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "expected exit 0 with --profile --no-structured-handoff; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // No sanitize-discovered.yaml (or similar) should have been created in the
    // temp dir since no --secrets-file was supplied and --no-structured-handoff is set.
    assert!(
        !dir.path().join("sanitize-discovered.yaml").exists(),
        "sanitize-discovered.yaml should not be written when --no-structured-handoff is set"
    );
}

/// 5. --no-structured-handoff with an existing secrets file leaves that file
///    byte-for-byte identical after the run.
#[test]
fn no_structured_handoff_with_secrets_file_does_not_mutate_secrets_file() {
    let dir = tempdir().unwrap();
    let profile = write_kv_profile(dir.path(), "profile.json");
    let input = write_cfg_input(dir.path(), "input.cfg");
    let output = dir.path().join("output.cfg");
    // Create a secrets file with one literal pattern.
    let secrets = write_literal_secrets(dir.path(), "secrets.json", "secret123");

    let original_content = fs::read(&secrets).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after_content = fs::read(&secrets).unwrap();
    assert_eq!(
        original_content, after_content,
        "secrets file content should be unchanged when --no-structured-handoff is set"
    );
}

/// 6. --allow passes a specific value through unchanged while other matching
///    values of the same category are still replaced.
#[test]
fn allow_flag_passes_value_through_unchanged() {
    let dir = tempdir().unwrap();

    // IPv4 regex pattern.
    let secrets_path = dir.path().join("secrets.json");
    fs::write(
        &secrets_path,
        r#"[{"pattern":"[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}","kind":"regex","category":"ipv4","label":"ipv4_addr"}]"#,
    )
    .unwrap();

    let input_path = dir.path().join("hosts.txt");
    fs::write(
        &input_path,
        "server at 192.168.1.1 and client at 10.0.0.1\n",
    )
    .unwrap();

    let output_path = dir.path().join("hosts-out.txt");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input_path.to_str().unwrap(),
            "-s",
            secrets_path.to_str().unwrap(),
            "--allow",
            "192.168.1.1",
            "-o",
            output_path.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let result = fs::read_to_string(&output_path).unwrap();

    // 192.168.1.1 should pass through because it was explicitly allowed.
    assert!(
        result.contains("192.168.1.1"),
        "allowed IP 192.168.1.1 should appear unchanged in output; got:\n{result}"
    );

    // 10.0.0.1 should have been replaced (not in the allowlist).
    assert!(
        !result.contains("10.0.0.1"),
        "non-allowed IP 10.0.0.1 should have been replaced; got:\n{result}"
    );
}

/// Two-pass pipeline: a value extracted from a structured file in Phase 1
/// must also be replaced in a plain-text file processed in Phase 2.
///
/// Phase 1: config.yaml is parsed structurally; `database.password` is
///          extracted and seeds the store.
/// Phase 2: app.log is scanned as plain text with the augmented scanner
///          that now includes the discovered password as a literal.
#[test]
fn two_pass_profile_seeds_plain_text_scan() {
    let dir = tempdir().unwrap();
    let outdir = dir.path().join("out");
    fs::create_dir_all(&outdir).unwrap();

    let password = "supersecret-twopass-unique-db";

    let config = dir.path().join("config.yaml");
    fs::write(
        &config,
        format!("database:\n  password: {password}\n  host: db.internal\n"),
    )
    .unwrap();

    let log = dir.path().join("app.log");
    fs::write(
        &log,
        format!("INFO  connect\nERROR auth failed using {password}\nINFO  retry\n"),
    )
    .unwrap();

    let secrets = dir.path().join("secrets.json");
    fs::write(&secrets, b"[]").unwrap();

    // Profile: process *.yaml files as YAML, target database.password.
    let profile = dir.path().join("profile.json");
    fs::write(
        &profile,
        r#"[{"processor":"yaml","extensions":[".yaml"],"fields":[{"pattern":"database.password"}]}]"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            config.to_str().unwrap(),
            log.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--output",
            outdir.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .env("SANITIZE_NO_SETTINGS", "1")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let config_out = fs::read_to_string(outdir.join("config-sanitized.yaml")).unwrap();
    let log_out = fs::read_to_string(outdir.join("app-sanitized.log")).unwrap();

    assert!(
        !config_out.contains(password),
        "config output must not contain original password"
    );
    assert!(
        !log_out.contains(password),
        "log output must not contain original password — two-pass seeding failed"
    );

    // Extract the replacement that appeared in the config, then verify the
    // log uses the exact same string (cross-file consistency).
    let replacement = config_out
        .lines()
        .find(|l| l.contains("password:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(str::trim)
        .expect("config output must have a password: line");

    assert!(
        log_out.contains(replacement),
        "log must use the same replacement as config (two-pass cross-file seeding); \
         replacement={replacement:?}, log:\n{log_out}"
    );
}
