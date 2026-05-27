//! Integration tests for the `--llm` flag.
//!
//! Covers: prompt templates, sanitization in prompt, content blocks,
//! sanitization summary, notable events (--extract-context), validation
//! rejections, custom template files, and no-file-write guarantee.

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

fn secrets_file(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(
        &p,
        r#"[{"pattern":"MYSECRET","kind":"literal","category":"custom:token","label":"token"}]"#,
    )
    .unwrap();
    p
}

fn empty_secrets(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(&p, "[]").unwrap();
    p
}

/// Spawn the binary with piped stdin/stdout/stderr, write `input` to stdin,
/// and return the collected output.
fn run_stdin(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("SANITIZE_LOG", "error")
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

// ---------------------------------------------------------------------------
// Validation rejections (exit non-zero, error on stderr)
// ---------------------------------------------------------------------------

#[test]
fn llm_rejects_output_flag_combination() {
    let dir = tempdir().unwrap();
    let s = secrets_file(dir.path());
    let input = dir.path().join("in.log");
    fs::write(&input, "data\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--llm",
            "--output",
            dir.path().join("out.log").to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(!out.status.success(), "should exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--llm and --output cannot be combined"),
        "got: {stderr}"
    );
}

#[test]
fn llm_rejects_dry_run_combination() {
    let dir = tempdir().unwrap();
    let s = secrets_file(dir.path());
    let input = dir.path().join("in.log");
    fs::write(&input, "data\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--llm",
            "--dry-run",
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(!out.status.success(), "should exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--llm and --dry-run cannot be combined"),
        "got: {stderr}"
    );
}

#[test]
fn llm_rejects_nonexistent_template_path() {
    let dir = tempdir().unwrap();
    let s = secrets_file(dir.path());
    let input = dir.path().join("in.log");
    fs::write(&input, "data\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--llm",
            "/no/such/template.txt",
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(!out.status.success(), "should exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not exist"), "got: {stderr}");
}

// ---------------------------------------------------------------------------
// Template selection
// ---------------------------------------------------------------------------

#[test]
fn llm_default_uses_troubleshoot_template() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let out = run_stdin(&["-", "-s", s.to_str().unwrap(), "--llm"], b"log line\n");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Root cause") || stdout.contains("troubleshooting"),
        "default template should be troubleshoot, got:\n{stdout}"
    );
}

#[test]
fn llm_troubleshoot_template_explicit() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let out = run_stdin(
        &["-", "-s", s.to_str().unwrap(), "--llm", "troubleshoot"],
        b"log line\n",
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Root cause") && stdout.contains("Remediation"),
        "got:\n{stdout}"
    );
}

#[test]
fn llm_review_config_template() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let out = run_stdin(
        &["-", "-s", s.to_str().unwrap(), "--llm", "review-config"],
        b"host = localhost\n",
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Misconfigurations") && stdout.contains("Security concerns"),
        "got:\n{stdout}"
    );
}

#[test]
fn llm_custom_template_file_content_is_used() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let tmpl = dir.path().join("custom.txt");
    fs::write(&tmpl, "MY CUSTOM TEMPLATE HEADER\nDo this analysis:\n").unwrap();

    let out = run_stdin(
        &[
            "-",
            "-s",
            s.to_str().unwrap(),
            "--llm",
            tmpl.to_str().unwrap(),
        ],
        b"data\n",
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("MY CUSTOM TEMPLATE HEADER"),
        "custom template content should appear, got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// Prompt structure
// ---------------------------------------------------------------------------

#[test]
fn llm_stdout_contains_content_block_with_input() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let out = run_stdin(
        &["-", "-s", s.to_str().unwrap(), "--llm"],
        b"hello from stdin\n",
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("<content name=\"<stdin>\">"),
        "content block missing, got:\n{stdout}"
    );
    assert!(stdout.contains("hello from stdin"), "input text missing");
    assert!(stdout.contains("</content>"), "closing tag missing");
}

#[test]
fn llm_stdout_contains_sanitization_summary() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let out = run_stdin(&["-", "-s", s.to_str().unwrap(), "--llm"], b"data\n");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## Sanitization Summary"), "got:\n{stdout}");
    assert!(stdout.contains("Files processed:"), "got:\n{stdout}");
    assert!(stdout.contains("Total replacements:"), "got:\n{stdout}");
}

#[test]
fn llm_sanitizes_secrets_before_including_in_prompt() {
    let dir = tempdir().unwrap();
    let s = secrets_file(dir.path());
    let out = run_stdin(
        &["-", "-s", s.to_str().unwrap(), "--llm"],
        b"prefix MYSECRET suffix\n",
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("MYSECRET"),
        "raw secret must not appear in prompt"
    );
    assert!(
        stdout.contains("prefix"),
        "surrounding context should be preserved"
    );
    assert!(
        stdout.contains("suffix"),
        "surrounding context should be preserved"
    );
}

#[test]
fn llm_with_extract_context_includes_notable_events_section() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let out = run_stdin(
        &[
            "-",
            "-s",
            s.to_str().unwrap(),
            "--llm",
            "--extract-context",
            "--context-lines",
            "1",
        ],
        b"INFO start\nERROR disk full on /dev/sda1\nINFO retrying\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("<notable_events>"),
        "notable_events section missing, got:\n{stdout}"
    );
    assert!(
        stdout.contains("ERROR disk full"),
        "error line should appear in notable events"
    );
    assert!(stdout.contains("</notable_events>"), "closing tag missing");
}

// ---------------------------------------------------------------------------
// No-write guarantee
// ---------------------------------------------------------------------------

#[test]
fn llm_does_not_write_per_file_output() {
    let dir = tempdir().unwrap();
    let s = secrets_file(dir.path());
    let input = dir.path().join("data.log");
    fs::write(&input, "line with MYSECRET here\n").unwrap();
    let expected_out = dir.path().join("data-sanitized.log");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([input.to_str().unwrap(), "-s", s.to_str().unwrap(), "--llm"])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !expected_out.exists(),
        "--llm should not produce a sanitized output file"
    );
    // The prompt must be on stdout
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("<content name="),
        "prompt should be on stdout, got:\n{stdout}"
    );
}
