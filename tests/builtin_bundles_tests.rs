//! Regression guard for the built-in app bundles.
//!
//! The bundle YAML under `apps/<name>/` is embedded via `include_str!` and only
//! parsed (and its regexes compiled) at *runtime*, when a user runs
//! `--app <name>`. A malformed bundle — bad YAML, or a pattern that won't
//! compile — therefore slips past `cargo build`/`cargo test` and only surfaces
//! for whoever first runs that one bundle. Most bundles have no behavioral test,
//! so this exercises *every* one: load it, compile its patterns, and assert the
//! run is clean.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn apps_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("apps")
}

/// Names of every built-in bundle, taken from the `apps/` source tree (the
/// thing `include_str!` embeds).
fn bundle_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(apps_root())
        .expect("apps/ directory must exist")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(!names.is_empty(), "expected at least one built-in bundle");
    names
}

/// Run `--app <name>` against trivial stdin, forcing the *built-in* bundle by
/// pointing `SANITIZE_APPS_DIR` at an empty dir, and skipping the structured
/// handoff so nothing is written to user config.
fn run_app(name: &str, empty_apps_dir: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args(["--app", name, "--no-structured-handoff", "-"])
        .env("SANITIZE_LOG", "warn")
        .env("SANITIZE_APPS_DIR", empty_apps_dir)
        .env("SANITIZE_NO_SETTINGS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello world test@example.com 10.0.0.1\n")
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn every_builtin_bundle_loads_and_compiles() {
    let empty = tempfile::tempdir().unwrap();
    let empty_dir = empty.path().to_str().unwrap();

    for name in bundle_names() {
        let out = run_app(&name, empty_dir);
        let stderr = String::from_utf8_lossy(&out.stderr);

        // A YAML parse failure makes `load_app_bundle` return Err -> non-zero exit.
        assert!(
            out.status.success(),
            "--app {name} failed to load (exit {:?}):\n{stderr}",
            out.status.code(),
        );
        // A secret pattern that won't compile is logged (not fatal) — catch it
        // here so a dead detector can't ship silently. Matches the exact message
        // from the bundle-load path; the benign "allowlist pattern warning"
        // advisory (e.g. a literal '+' in a MIME type) is intentionally excluded.
        assert!(
            !stderr.contains("app bundle pattern warning"),
            "--app {name} has a secret pattern that failed to compile:\n{stderr}",
        );
        assert!(
            !stderr.to_lowercase().contains("failed to parse"),
            "--app {name} produced a parse error:\n{stderr}",
        );
    }
}

#[test]
fn apps_dir_and_embedded_registry_match() {
    // `sanitize apps` lists the bundles compiled into the binary (BUILTIN_APPS).
    // Every directory under apps/ must be embedded, and vice versa — a bundle
    // added to apps/ but not registered in apps.rs (or removed from one side
    // only) would be invisible / dangling.
    let empty = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args(["apps"])
        .env("SANITIZE_LOG", "error")
        .env("SANITIZE_APPS_DIR", empty.path().to_str().unwrap())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    let listing = String::from_utf8_lossy(&out.stdout);

    for name in bundle_names() {
        assert!(
            listing.contains(&name),
            "bundle '{name}' exists under apps/ but is not listed by `sanitize apps` \
             (missing include_str! entry in apps.rs?):\n{listing}",
        );
    }
}
