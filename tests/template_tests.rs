//! Integration tests for the `scour-secrets template` subcommand.
//!
//! Covers:
//! - Default preset (balanced) generates a YAML file with pattern entries
//! - Named presets (balanced, aggressive, web, k8s, database, aws) generate preset-specific files
//! - Refusing to overwrite an existing file without `--overwrite`
//! - `--overwrite` replaces an existing file
//! - The generated template is accepted by a scour-secrets run

use std::fs;
use std::process::Command;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_template(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(std::iter::once("template").chain(args.iter().copied()))
        .env("SCOUR_SECRETS_LOG", "error")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn template_default_is_balanced() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("secrets.yaml");

    let out = run_template(&["-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("aws_access_key_id") || content.contains("github_token"),
        "default (balanced) template should contain well-known token labels; got:\n{content}"
    );
}

#[test]
fn template_preset_balanced_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("balanced.yaml");

    let out = run_template(&["balanced", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("stripe_key") || content.contains("github_token"),
        "balanced template should contain specific token labels; got:\n{content}"
    );
}

#[test]
fn template_preset_aggressive_includes_entropy() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("aggressive.yaml");

    let out = run_template(&["aggressive", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("entropy"),
        "aggressive template should contain entropy detection; got:\n{content}"
    );
    assert!(
        content.contains("bearer_token") || content.contains("Bearer"),
        "aggressive template should contain bearer token pattern; got:\n{content}"
    );
}

#[test]
fn template_preset_web_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("web-secrets.yaml");

    let out = run_template(&["web", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let content = fs::read_to_string(&out_path).unwrap();
    let lower = content.to_lowercase();
    assert!(
        lower.contains("jwt") || lower.contains("session"),
        "web template should contain 'jwt' or 'session'; got:\n{content}"
    );
}

#[test]
fn template_preset_k8s_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("k8s-secrets.yaml");

    let out = run_template(&["k8s", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let content = fs::read_to_string(&out_path).unwrap();
    let lower = content.to_lowercase();
    assert!(
        lower.contains("k8s")
            || lower.contains("kubernetes")
            || lower.contains("namespace")
            || lower.contains("serviceaccount"),
        "k8s template should contain k8s-related terminology; got:\n{content}"
    );
}

#[test]
fn template_preset_database_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("db-secrets.yaml");

    let out = run_template(&["database", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let content = fs::read_to_string(&out_path).unwrap();
    let lower = content.to_lowercase();
    assert!(
        lower.contains("password") || lower.contains("connection") || lower.contains("database"),
        "database template should contain password/connection/database; got:\n{content}"
    );
}

#[test]
fn template_preset_aws_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("aws-secrets.yaml");

    let out = run_template(&["aws", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let content = fs::read_to_string(&out_path).unwrap();
    let lower = content.to_lowercase();
    assert!(
        content.contains("AKIA") || lower.contains("aws") || lower.contains("arn:aws"),
        "aws template should contain AKIA/aws/arn:aws; got:\n{content}"
    );
}

#[test]
fn template_fails_without_overwrite_when_file_exists() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("secrets.yaml");

    let out1 = run_template(&["-o", out_path.to_str().unwrap()]);
    assert!(out1.status.success(), "first run failed: {}", stderr(&out1));
    assert!(out_path.exists());

    let out2 = run_template(&["-o", out_path.to_str().unwrap()]);
    assert!(
        !out2.status.success(),
        "expected failure when file already exists without --overwrite"
    );
}

#[test]
fn template_overwrite_flag_replaces_existing_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("secrets.yaml");

    fs::write(&out_path, b"dummy content that should be replaced\n").unwrap();

    let out = run_template(&["-o", out_path.to_str().unwrap(), "--overwrite"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("- pattern:") || content.contains("kind: entropy"),
        "file should contain pattern entries after overwrite; got:\n{content}"
    );
    assert!(
        !content.contains("dummy content"),
        "old content should have been replaced; got:\n{content}"
    );
}

#[test]
fn template_generated_file_is_valid_for_sanitize() {
    let dir = tempdir().unwrap();
    let template_path = dir.path().join("secrets.yaml");
    let input_path = dir.path().join("input.txt");
    let out_path = dir.path().join("out.txt");

    let tpl_out = run_template(&["balanced", "-o", template_path.to_str().unwrap()]);
    assert!(
        tpl_out.status.success(),
        "template generation failed: {}",
        stderr(&tpl_out)
    );

    fs::write(&input_path, b"safe text with no secrets here\n").unwrap();

    let run_out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input_path.to_str().unwrap(),
            "-s",
            template_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();

    assert!(
        run_out.status.success(),
        "scour-secrets run with generated template as secrets file should exit 0; stderr: {}",
        String::from_utf8_lossy(&run_out.stderr)
    );
}
