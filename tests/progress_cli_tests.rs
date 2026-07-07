//! Integration tests for CLI progress behavior in redirected (non-TTY) runs.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

/// Read a file with retry on transient permission errors.
///
/// On Windows CI, real-time AV (Defender) can hold a lock on a file
/// immediately after `AtomicFileWriter::finish` renames it into place,
/// causing the test-side reopen to fail with `ERROR_ACCESS_DENIED` (os 5).
/// Retry on either `PermissionDenied` or raw OS error 5 (some Rust
/// versions don't map every flavor of ACCESS_DENIED to `PermissionDenied`)
/// for up to ~3 seconds with 50ms backoffs.
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

fn write_test_inputs() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.log");
    let secrets_path = dir.path().join("secrets.json");

    fs::write(&input_path, "prefix SUPERSECRET suffix\n").unwrap();
    fs::write(
        &secrets_path,
        r#"[
  {
    "pattern": "SUPERSECRET",
    "kind": "literal",
    "category": "custom:token",
    "label": "token"
  }
]"#,
    )
    .unwrap();

    (dir, input_path, secrets_path)
}

#[test]
fn forced_progress_uses_stderr_and_keeps_stdout_payload_clean() {
    let (_dir, input_path, secrets_path) = write_test_inputs();
    let output_path = input_path.with_file_name("input-sanitized.log");

    let output = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .arg(&input_path)
        .arg("-s")
        .arg(&secrets_path)
        .arg("--progress")
        .arg("on")
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "scour-secrets failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let file_output = read_to_string_retry(&output_path);

    // File input now defaults to a per-file output path.
    assert!(stdout.trim().is_empty());
    assert!(!file_output.contains("SUPERSECRET"));
    assert!(file_output.contains("prefix"));
    assert!(file_output.contains("suffix"));

    // Progress/status should be emitted on stderr only.
    assert!(stderr.contains("Scanning"));
    assert!(stderr.contains("done"));
    assert!(!stdout.contains("Scanning"));
    assert!(!stdout.contains("done"));
}

#[test]
fn auto_progress_is_silent_in_non_tty_mode() {
    let (_dir, input_path, secrets_path) = write_test_inputs();
    let output_path = input_path.with_file_name("input-sanitized.log");

    let output = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .arg(&input_path)
        .arg("-s")
        .arg(&secrets_path)
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "scour-secrets failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let file_output = read_to_string_retry(&output_path);

    assert!(stdout.trim().is_empty());
    assert!(!file_output.contains("SUPERSECRET"));
    // In auto/non-TTY mode the live spinner is suppressed (no \r overwrites),
    // but milestone lines ("Scanning", "done") are plain eprintln! and are
    // emitted so CI logs capture progress. Only verify no raw spinner chars.
    assert!(
        !stderr.contains('\r'),
        "spinner carriage-return must not appear in non-TTY mode, got: {stderr}"
    );
}

#[test]
fn stdin_pipeline_forced_progress_keeps_stdout_clean() {
    let dir = tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.json");
    fs::write(
        &secrets_path,
        r#"[
  {
    "pattern": "SUPERSECRET",
    "kind": "literal",
    "category": "custom:token",
    "label": "token"
  }
]"#,
    )
    .unwrap();
    let out_path = dir.path().join("out.txt");

    let mut child = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .arg("-")
        .arg("-s")
        .arg(&secrets_path)
        .arg("-o")
        .arg(&out_path)
        .arg("--progress")
        .arg("on")
        .env("SCOUR_SECRETS_LOG", "error")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .current_dir(dir.path())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"prefix SUPERSECRET suffix\n").unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "scour-secrets failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // stdout must be empty — sanitized content goes to the output file
    assert!(stdout.is_empty(), "unexpected stdout: {stdout}");

    let out_content = fs::read_to_string(&out_path).expect("output file not created");
    assert!(!out_content.contains("SUPERSECRET"));
    assert!(out_content.contains("prefix"));
    assert!(out_content.contains("suffix"));

    assert!(stderr.contains("Scanning stdin"));
    assert!(stderr.contains("done"));
    assert!(!stdout.contains("Scanning stdin"));
    assert!(!stdout.contains("done"));
}

#[test]
fn multi_input_writes_per_file_outputs_with_matching_extensions() {
    let dir = tempdir().unwrap();
    let txt = dir.path().join("test.txt");
    let json = dir.path().join("a.json");
    let zip = dir.path().join("b.zip");
    let secrets_path = dir.path().join("secrets.json");

    fs::write(&txt, "token=SUPERSECRET\n").unwrap();
    fs::write(&json, r#"{"token":"SUPERSECRET"}"#).unwrap();
    {
        let f = fs::File::create(&zip).unwrap();
        let mut zipw = zip::ZipWriter::new(f);
        zipw.start_file("nested.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        zipw.write_all(b"SUPERSECRET\n").unwrap();
        zipw.finish().unwrap();
    }
    fs::write(
        &secrets_path,
        r#"[
  {
    "pattern": "SUPERSECRET",
    "kind": "literal",
    "category": "custom:token",
    "label": "token"
  }
]"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .arg(&txt)
        .arg(&json)
        .arg(&zip)
        .arg("-s")
        .arg(&secrets_path)
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "scour-secrets failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let txt_out = dir.path().join("test-sanitized.txt");
    let json_out = dir.path().join("a-sanitized.json");
    let zip_out = dir.path().join("b.sanitized.zip");

    assert!(txt_out.exists());
    assert!(json_out.exists());
    assert!(zip_out.exists());

    let txt_contents = fs::read_to_string(txt_out).unwrap();
    let json_contents = fs::read_to_string(json_out).unwrap();
    assert!(!txt_contents.contains("SUPERSECRET"));
    assert!(!json_contents.contains("SUPERSECRET"));
}

// ===========================================================================
// Multi-input parallel: progress, fail-on-match, determinism
// ===========================================================================

/// Helper: write N plaintext files each containing SUPERSECRET, plus a
/// secrets file.  Returns `(dir, [input_paths], secrets_path)`.
fn write_multi_inputs(
    n: usize,
) -> (
    tempfile::TempDir,
    Vec<std::path::PathBuf>,
    std::path::PathBuf,
) {
    let dir = tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.json");
    fs::write(
        &secrets_path,
        r#"[{"pattern":"SUPERSECRET","kind":"literal","category":"custom:token","label":"token"}]"#,
    )
    .unwrap();

    let mut inputs = Vec::new();
    for i in 0..n {
        let p = dir.path().join(format!("file{i}.log"));
        fs::write(&p, format!("line1\ntoken=SUPERSECRET\nline3 {i}\n")).unwrap();
        inputs.push(p);
    }
    (dir, inputs, secrets_path)
}

/// When `--progress on` is used with multiple input files processed in
/// parallel each file should still emit its own "done" milestone line on
/// stderr.
#[test]
fn multi_input_progress_shows_done_for_every_file() {
    let (_dir, inputs, secrets_path) = write_multi_inputs(4);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scour-secrets"));
    for p in &inputs {
        cmd.arg(p);
    }
    cmd.arg("-s")
        .arg(&secrets_path)
        .arg("--progress")
        .arg("on")
        .arg("--threads")
        .arg("4")
        .env("SCOUR_SECRETS_LOG", "error")
        .stdin(std::process::Stdio::null());

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "scour-secrets failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Every file must have its own "done" milestone line.
    let done_count = stderr.lines().filter(|l| l.contains(": done")).count();
    assert_eq!(
        done_count, 4,
        "expected 4 'done' lines for 4 parallel files, got {done_count}. stderr:\n{stderr}"
    );
}

/// With multiple parallel files and `--fail-on-match`, the process must exit
/// with code 2 when any file contains a match.
#[test]
fn multi_input_fail_on_match_returns_exit_code_2() {
    let (_dir, inputs, secrets_path) = write_multi_inputs(3);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scour-secrets"));
    for p in &inputs {
        cmd.arg(p);
    }
    cmd.arg("-s")
        .arg(&secrets_path)
        .arg("--fail-on-match")
        .arg("--threads")
        .arg("3")
        .env("SCOUR_SECRETS_LOG", "error")
        .stdin(std::process::Stdio::null());

    let output = cmd.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit code 2 (--fail-on-match), got {:?}. stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `--threads 1` and `--threads 4` must produce byte-identical outputs when
/// `--deterministic` is used and inputs are the same.
#[test]
fn determinism_parallel_matches_serial() {
    // Build 5 plaintext files with the same repeating secret.  We encrypt
    // the secrets file so that --deterministic (which requires a password for
    // its Argon2id-derived seed) can be exercised via the CLI.
    use std::process::Stdio;

    let dir = tempdir().unwrap();
    let secrets_plain = dir.path().join("secrets.json");
    let secrets_enc = dir.path().join("secrets.enc");
    fs::write(
        &secrets_plain,
        r#"[{"pattern":"TOPSECRET","kind":"literal","category":"custom:token","label":"tok"}]"#,
    )
    .unwrap();

    // Encrypt the secrets file with a fixed test password.
    let enc_status = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .arg("encrypt")
        .arg(&secrets_plain)
        .arg(&secrets_enc)
        .env("SCOUR_SECRETS_PASSWORD", "det-test-key-bench")
        .env("SCOUR_SECRETS_LOG", "error")
        .status()
        .unwrap();
    assert!(enc_status.success(), "scour-secrets encrypt failed");

    let n_files = 5;
    let mut inputs = Vec::new();
    for i in 0..n_files {
        let p = dir.path().join(format!("data{i}.log"));
        fs::write(&p, format!("id={i} key=TOPSECRET extra=TOPSECRET\n")).unwrap();
        inputs.push(p);
    }

    let out1 = dir.path().join("out1");
    let out4 = dir.path().join("out4");
    fs::create_dir_all(&out1).unwrap();
    fs::create_dir_all(&out4).unwrap();

    // Run with --threads 1.
    let mut cmd1 = Command::new(env!("CARGO_BIN_EXE_scour-secrets"));
    for p in &inputs {
        cmd1.arg(p);
    }
    let status1 = cmd1
        .arg("-s")
        .arg(&secrets_enc)
        .arg("--encrypted-secrets")
        .arg("--output")
        .arg(&out1)
        .arg("--deterministic")
        .arg("--threads")
        .arg("1")
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_PASSWORD", "det-test-key-bench")
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(status1.success(), "threads=1 run failed");

    // Run with --threads 4.
    let mut cmd4 = Command::new(env!("CARGO_BIN_EXE_scour-secrets"));
    for p in &inputs {
        cmd4.arg(p);
    }
    let status4 = cmd4
        .arg("-s")
        .arg(&secrets_enc)
        .arg("--encrypted-secrets")
        .arg("--output")
        .arg(&out4)
        .arg("--deterministic")
        .arg("--threads")
        .arg("4")
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_PASSWORD", "det-test-key-bench")
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(status4.success(), "threads=4 run failed");

    // Compare output files byte-for-byte.
    for i in 0..n_files {
        let name = format!("data{i}-sanitized.log");
        let content1 = fs::read(out1.join(&name)).unwrap();
        let content4 = fs::read(out4.join(&name)).unwrap();
        assert_eq!(
            content1, content4,
            "determinism mismatch for {name}: threads=1 and threads=4 produced different output"
        );
    }

    // Verify the replacement is consistent across files.
    let first = fs::read_to_string(out1.join("data0-sanitized.log")).unwrap();
    let replacement = first
        .split("key=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("replacement token not found");

    for i in 0..n_files {
        let content = fs::read_to_string(out1.join(format!("data{i}-sanitized.log"))).unwrap();
        assert!(
            content.contains(replacement),
            "file data{i} has a different replacement for TOPSECRET than data0"
        );
        assert!(
            !content.contains("TOPSECRET"),
            "file data{i} still contains the raw secret"
        );
    }
}

/// Multi-file input with `--threads 1` must still produce one sanitized
/// output per input file with the correct `-sanitized.{ext}` name.
#[test]
fn multi_input_output_mapping_single_thread() {
    let (_dir, inputs, secrets_path) = write_multi_inputs(3);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scour-secrets"));
    for p in &inputs {
        cmd.arg(p);
    }
    let output = cmd
        .arg("-s")
        .arg(&secrets_path)
        .arg("--threads")
        .arg("1")
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "scour-secrets failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (i, input) in inputs.iter().enumerate() {
        let out = input.with_file_name(format!("file{i}-sanitized.log"));
        assert!(out.exists(), "expected output {}", out.display());
        let content = fs::read_to_string(&out).unwrap();
        assert!(
            !content.contains("SUPERSECRET"),
            "file{i} output still contains raw secret"
        );
    }
}
