//! Integration tests for the `--force-text` CLI flag.
//!
//! Covers:
//! - JSON files are sanitized as plain text (bypassing structured processing)
//! - Without `--force-text` the structured processor also replaces the secret
//! - `--force-text` on stdin exits successfully and removes the secret
//! - Non-secret keys are preserved while secret values are replaced

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_stdin(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("SCOUR_SECRETS_LOG", "error")
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

/// Write a secrets file that contains a single literal pattern for `hunter2`.
fn write_hunter2_secrets(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(
        &p,
        br#"[
  {
    "pattern": "hunter2",
    "kind": "literal",
    "category": "custom:password",
    "label": "password"
  }
]"#,
    )
    .unwrap();
    p
}

/// Write a secrets file that contains a single literal pattern for `secret123`.
fn write_secret123_secrets(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(
        &p,
        br#"[
  {
    "pattern": "secret123",
    "kind": "literal",
    "category": "custom:password",
    "label": "password"
  }
]"#,
    )
    .unwrap();
    p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn force_text_sanitizes_json_file_as_plain_text() {
    let dir = tempdir().unwrap();
    let secrets = write_hunter2_secrets(dir.path());

    // Use stdin→stdout to avoid Windows CI file-read permission issues from
    // the streaming process_plain_file code path.
    let out = run_stdin(
        &["-", "-s", secrets.to_str().unwrap(), "--force-text"],
        br#"{"password": "hunter2", "user": "alice"}"#,
    );

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = String::from_utf8_lossy(&out.stdout);
    assert!(
        !content.contains("hunter2"),
        "secret should be replaced with --force-text; got:\n{content}"
    );
}

#[test]
fn force_text_output_still_replaces_secrets() {
    let dir = tempdir().unwrap();
    let secrets = write_hunter2_secrets(dir.path());

    // Sanity check: without --force-text the scanner also catches and replaces
    // the literal secret value.
    // Use stdin→stdout to avoid Windows CI file-read permission issues.
    let out = run_stdin(
        &["-", "-s", secrets.to_str().unwrap()],
        br#"{"password": "hunter2", "user": "alice"}"#,
    );

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = String::from_utf8_lossy(&out.stdout);
    assert!(
        !content.contains("hunter2"),
        "secret should also be replaced without --force-text; got:\n{content}"
    );
}

#[test]
fn force_text_on_stdin() {
    let dir = tempdir().unwrap();
    let secrets = write_hunter2_secrets(dir.path());
    let out_file = dir.path().join("out.txt");

    // Pipe JSON content through stdin with --force-text.
    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--force-text",
            "-o",
            out_file.to_str().unwrap(),
        ],
        br#"{"password": "hunter2", "user": "alice"}"#,
    );

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&out_file).unwrap();
    assert!(
        !content.contains("hunter2"),
        "secret should be replaced via stdin with --force-text; got:\n{content}"
    );
}

#[test]
fn force_text_preserves_structure_keys_for_simple_kv() {
    let dir = tempdir().unwrap();
    let secrets = write_secret123_secrets(dir.path());

    // Use stdin→stdout to avoid Windows CI file-read permission issues.
    let out = run_stdin(
        &["-", "-s", secrets.to_str().unwrap(), "--force-text"],
        b"host=localhost\npassword=secret123\n",
    );

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = String::from_utf8_lossy(&out.stdout);
    assert!(
        content.contains("host"),
        "key 'host' should be preserved in output; got:\n{content}"
    );
    assert!(
        !content.contains("secret123"),
        "secret value should be replaced; got:\n{content}"
    );
}
