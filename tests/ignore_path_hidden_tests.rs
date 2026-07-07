//! Integration tests for the `--exclude-path` and `--hidden` CLI flags when
//! sanitizing a directory tree.
//!
//! Covers:
//! - `--exclude-path` skips the named file entirely
//! - `--exclude-path` with a trailing `/` excludes an entire subtree
//! - `--hidden` is required to walk dot-files; without it they are skipped
//! - Hidden files are silently omitted from output by default

use std::fs;
use std::process::Command;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A secrets file that contains a single literal pattern for the sentinel
/// token used across these tests.
const SECRETS_JSON: &[u8] = br#"[
  {
    "pattern": "SUPERSECRET",
    "kind": "literal",
    "category": "custom:test",
    "label": "test_token"
  }
]"#;

fn write_secrets(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(&p, SECRETS_JSON).unwrap();
    p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn ignore_path_excludes_matched_file() {
    let dir = tempdir().unwrap();
    let secrets = write_secrets(dir.path());

    // Two files with the same sensitive token.
    let keep = dir.path().join("keep.log");
    let skip = dir.path().join("skip.log");
    fs::write(&keep, b"SUPERSECRET\n").unwrap();
    fs::write(&skip, b"SUPERSECRET\n").unwrap();

    let out_dir = dir.path().join("outdir");
    fs::create_dir_all(&out_dir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            dir.path().to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--exclude-path",
            "skip.log",
            "-o",
            out_dir.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // keep.log must appear in the output directory with the token replaced.
    let keep_out = out_dir.join("keep.log");
    assert!(
        keep_out.exists(),
        "keep.log should be present in outdir; outdir contents: {:?}",
        fs::read_dir(&out_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>()
    );
    let keep_content = fs::read_to_string(&keep_out).unwrap();
    assert!(
        !keep_content.contains("SUPERSECRET"),
        "token should be replaced in keep.log; got:\n{keep_content}"
    );

    // skip.log must NOT appear in the output directory (it was excluded).
    let skip_out = out_dir.join("skip.log");
    assert!(
        !skip_out.exists(),
        "skip.log should be absent from outdir (ignored by --exclude-path)"
    );
}

#[test]
fn ignore_path_glob_excludes_subtree() {
    let dir = tempdir().unwrap();
    let secrets = write_secrets(dir.path());

    // Create a two-level tree: logs/app.log and fixtures/test.log.
    fs::create_dir_all(dir.path().join("logs")).unwrap();
    fs::create_dir_all(dir.path().join("fixtures")).unwrap();
    fs::write(dir.path().join("logs").join("app.log"), b"SUPERSECRET\n").unwrap();
    fs::write(
        dir.path().join("fixtures").join("test.log"),
        b"SUPERSECRET\n",
    )
    .unwrap();

    let out_dir = dir.path().join("outdir");
    fs::create_dir_all(&out_dir).unwrap();

    // Use `**/fixtures/**` so the glob matches the absolute temp path.
    // A trailing `/` on a bare directory name like `fixtures/` is anchored
    // to the project config root (CWD), which doesn't apply when the input is
    // an absolute temp directory. The `**` prefix/suffix form matches
    // regardless of where the input lives.
    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            dir.path().to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--exclude-path",
            "**/fixtures/**",
            "-o",
            out_dir.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // logs/app.log should have been sanitized.
    let app_out = out_dir.join("logs").join("app.log");
    assert!(app_out.exists(), "logs/app.log should be present in outdir");
    let app_content = fs::read_to_string(&app_out).unwrap();
    assert!(
        !app_content.contains("SUPERSECRET"),
        "token should be replaced in logs/app.log; got:\n{app_content}"
    );

    // fixtures/test.log should not be in the output (subtree excluded).
    let fixture_out = out_dir.join("fixtures").join("test.log");
    assert!(
        !fixture_out.exists(),
        "fixtures/test.log should be absent from outdir (subtree excluded by --exclude-path **/fixtures/**)"
    );
}

#[test]
fn hidden_flag_walks_dotfiles() {
    let dir = tempdir().unwrap();
    let secrets = write_secrets(dir.path());

    let hidden_file = dir.path().join(".hidden_config");
    let normal_file = dir.path().join("normal.log");
    fs::write(&hidden_file, b"SUPERSECRET\n").unwrap();
    fs::write(&normal_file, b"safe\n").unwrap();

    // --- Run WITHOUT --hidden ---
    let out_no_hidden = dir.path().join("out_no_hidden");
    fs::create_dir_all(&out_no_hidden).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            dir.path().to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "-o",
            out_no_hidden.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !out_no_hidden.join(".hidden_config").exists(),
        ".hidden_config should not appear in outdir when --hidden is not set"
    );

    // --- Run WITH --hidden ---
    let out_with_hidden = dir.path().join("out_with_hidden");
    fs::create_dir_all(&out_with_hidden).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            dir.path().to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--hidden",
            "-o",
            out_with_hidden.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let hidden_out = out_with_hidden.join(".hidden_config");
    assert!(
        hidden_out.exists(),
        ".hidden_config should appear in outdir when --hidden is set"
    );
    let hidden_content = fs::read_to_string(&hidden_out).unwrap();
    assert!(
        !hidden_content.contains("SUPERSECRET"),
        "token should be replaced in .hidden_config; got:\n{hidden_content}"
    );
}

#[test]
fn hidden_skipped_by_default() {
    // Use separate directories for secrets and for the input to be scanned,
    // so the secrets file itself doesn't appear in the output directory.
    let secrets_dir = tempdir().unwrap();
    let input_dir = tempdir().unwrap();
    let secrets = write_secrets(secrets_dir.path());

    // Only file in the input directory is a hidden file.
    fs::write(input_dir.path().join(".env"), b"SUPERSECRET\n").unwrap();

    let out_dir = input_dir.path().join("outdir");
    fs::create_dir_all(&out_dir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input_dir.path().to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The output directory should be empty — the only input file was hidden
    // and hidden files are skipped by default.
    let entries: Vec<_> = fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        ".env should be skipped by default; found {} file(s) in outdir: {:?}",
        entries.len(),
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}

/// Regression: a hidden directory and a VCS directory must have their whole
/// subtrees pruned, not just their directory entry skipped. (A plain `continue`
/// during the walk skipped the dir entry but still descended into it, so a
/// `.git/config` or `.hidden/inner.txt` was processed and written.)
#[test]
fn hidden_and_vcs_directories_are_pruned() {
    let secrets_dir = tempdir().unwrap();
    let input_dir = tempdir().unwrap();
    let secrets = write_secrets(secrets_dir.path());

    // A VCS dir, a hidden dir, and a normal subdir — each with a *non-hidden*
    // child file (so only subtree pruning, not the per-file hidden check, can
    // keep them out of the output).
    fs::create_dir_all(input_dir.path().join(".git")).unwrap();
    fs::create_dir_all(input_dir.path().join(".secretdir")).unwrap();
    fs::create_dir_all(input_dir.path().join("sub")).unwrap();
    fs::write(input_dir.path().join(".git/config"), b"SUPERSECRET\n").unwrap();
    fs::write(
        input_dir.path().join(".secretdir/inner.txt"),
        b"SUPERSECRET\n",
    )
    .unwrap();
    fs::write(input_dir.path().join("sub/ok.txt"), b"SUPERSECRET\n").unwrap();

    let out_dir = input_dir.path().join("outdir");
    fs::create_dir_all(&out_dir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input_dir.path().to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !out_dir.join(".git").exists(),
        ".git subtree must be pruned (was processed into outdir)"
    );
    assert!(
        !out_dir.join(".secretdir").exists(),
        "hidden directory subtree must be pruned without --hidden"
    );
    assert!(
        out_dir.join("sub/ok.txt").exists(),
        "normal subdir file should be processed"
    );
}
