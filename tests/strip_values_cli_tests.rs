//! Integration tests for `--strip-values`, `--strip-delimiter`, and
//! `--strip-comment-prefix` CLI flags.

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

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

#[test]
fn strip_values_default_delimiter_and_comment() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("out.txt");
    let input = b"# db settings\nhost = localhost\nport = 5432\n[section]\n";
    let result = run_stdin(&["--strip-values", "-o", out.to_str().unwrap(), "-"], input);
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let content = fs::read_to_string(&out).unwrap();
    assert!(content.contains("host =\n"), "got:\n{content}");
    assert!(content.contains("port =\n"), "got:\n{content}");
    assert!(!content.contains("localhost"), "got:\n{content}");
    assert!(!content.contains("5432"), "got:\n{content}");
    assert!(content.contains("# db settings\n"), "got:\n{content}");
    assert!(content.contains("[section]\n"), "got:\n{content}");
}

#[test]
fn strip_values_custom_delimiter() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("out.txt");
    let input = b"key: value\nother: secret\n";
    let result = run_stdin(
        &[
            "--strip-values",
            "--strip-delimiter",
            ":",
            "-o",
            out.to_str().unwrap(),
            "-",
        ],
        input,
    );
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let content = fs::read_to_string(&out).unwrap();
    assert!(content.contains("key:\n"), "got:\n{content}");
    assert!(content.contains("other:\n"), "got:\n{content}");
    assert!(!content.contains("value"), "got:\n{content}");
    assert!(!content.contains("secret"), "got:\n{content}");
}

#[test]
fn strip_values_custom_comment_prefix() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("out.txt");
    let input = b"// nginx config\nworker_processes = auto\n";
    let result = run_stdin(
        &[
            "--strip-values",
            "--strip-comment-prefix",
            "//",
            "-o",
            out.to_str().unwrap(),
            "-",
        ],
        input,
    );
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let content = fs::read_to_string(&out).unwrap();
    assert!(
        content.contains("// nginx config\n"),
        "comment should be preserved"
    );
    assert!(content.contains("worker_processes =\n"), "got:\n{content}");
    assert!(!content.contains("auto"), "got:\n{content}");
}

// NOTE: input is piped via stdin (rather than a file) so the binary uses
// the buffered-stdin code path.  The file-input + AtomicFileWriter-output
// combination triggers a multi-second ACCESS_DENIED hold on the renamed
// output file on the Windows CI runner when content looks credential-shaped
// (`db_pass = ...`).  See commit ad06f8f.
#[test]
fn strip_values_from_file() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("out.txt");
    let result = run_stdin(
        &["--strip-values", "-o", out.to_str().unwrap(), "-"],
        b"db_pass = hunter2\ndb_host = prod.example.com\n",
    );
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let content = fs::read_to_string(&out).unwrap();
    assert!(content.contains("db_pass =\n"), "got:\n{content}");
    assert!(content.contains("db_host =\n"), "got:\n{content}");
    assert!(!content.contains("hunter2"), "got:\n{content}");
    assert!(!content.contains("prod.example.com"), "got:\n{content}");
}

#[test]
fn strip_delimiter_without_strip_values_is_error() {
    let result = run_stdin(&["--strip-delimiter", ":", "-"], b"key: value\n");
    assert!(
        !result.status.success(),
        "should fail without --strip-values"
    );
}

#[test]
fn strip_comment_prefix_without_strip_values_is_error() {
    let result = run_stdin(&["--strip-comment-prefix", "//", "-"], b"// comment\n");
    assert!(
        !result.status.success(),
        "should fail without --strip-values"
    );
}
