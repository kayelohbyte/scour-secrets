//! Integration tests for the `scour-secrets allow-test` subcommand.

use std::io::Write;
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(args)
        .env("SCOUR_SECRETS_LOG", "error")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap()
}

fn run_stdin(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(args)
        .env("SCOUR_SECRETS_LOG", "error")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(o: &std::process::Output) -> &str {
    std::str::from_utf8(&o.stdout).unwrap().trim()
}

fn stderr(o: &std::process::Output) -> &str {
    std::str::from_utf8(&o.stderr).unwrap().trim()
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn exact_match_prints_checkmark() {
    let out = run(&[
        "allow-test",
        "--allow",
        "localhost",
        "localhost",
        "github.com",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains('✓'), "expected ✓ in: {s}");
    assert!(s.contains('✗'), "expected ✗ in: {s}");
    assert!(s.contains("1/2 values allowed"), "got: {s}");
}

#[test]
fn glob_suffix_match() {
    let out = run(&[
        "allow-test",
        "--allow",
        "*.internal",
        "db.internal",
        "github.com",
        "staging.db.internal",
    ]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("2/3 values allowed"), "got: {s}");
}

#[test]
fn multiple_patterns_show_matched_pattern() {
    let out = run(&[
        "allow-test",
        "--allow",
        "*.internal",
        "--allow",
        "192.168.1.*",
        "db.internal",
        "192.168.1.5",
        "8.8.8.8",
    ]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("*.internal"), "matched pattern not shown: {s}");
    assert!(s.contains("192.168.1.*"), "matched pattern not shown: {s}");
    assert!(s.contains("2/3 values allowed"), "got: {s}");
}

#[test]
fn all_blocked() {
    let out = run(&[
        "allow-test",
        "--allow",
        "localhost",
        "github.com",
        "example.com",
    ]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("0/2 values allowed"));
}

#[test]
fn all_allowed() {
    let out = run(&["allow-test", "--allow", "*", "anything", "else"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("2/2 values allowed"));
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

#[test]
fn json_output_structure() {
    let out = run(&[
        "allow-test",
        "--allow",
        "*.internal",
        "--json",
        "db.internal",
        "github.com",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    let v: serde_json::Value =
        serde_json::from_str(s).unwrap_or_else(|e| panic!("invalid JSON: {e}\noutput: {s}"));

    assert_eq!(v["summary"]["total"], 2);
    assert_eq!(v["summary"]["allowed"], 1);
    assert_eq!(v["summary"]["blocked"], 1);

    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);

    let hit = results
        .iter()
        .find(|r| r["value"] == "db.internal")
        .unwrap();
    assert_eq!(hit["allowed"], true);
    assert_eq!(hit["pattern"], "*.internal");

    let miss = results.iter().find(|r| r["value"] == "github.com").unwrap();
    assert_eq!(miss["allowed"], false);
    assert!(miss.get("pattern").is_none() || miss["pattern"].is_null());
}

#[test]
fn json_all_blocked_no_pattern_field() {
    let out = run(&["allow-test", "--allow", "localhost", "--json", "github.com"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out)).unwrap();
    let r = &v["results"][0];
    assert_eq!(r["allowed"], false);
    // "pattern" key must be absent (skip_serializing_if = None)
    assert!(r.get("pattern").is_none() || r["pattern"].is_null());
}

// ---------------------------------------------------------------------------
// Stdin mode
// ---------------------------------------------------------------------------

#[test]
fn stdin_values_one_per_line() {
    let input = b"db.internal\ngithub.com\nstaging.internal\n";
    let out = run_stdin(&["allow-test", "--allow", "*.internal"], input);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("2/3 values allowed"));
}

#[test]
fn stdin_empty_lines_are_skipped() {
    let input = b"db.internal\n\n\ngithub.com\n";
    let out = run_stdin(&["allow-test", "--allow", "*.internal"], input);
    assert!(out.status.success());
    // only 2 non-empty values
    assert!(stdout(&out).contains("1/2 values allowed"));
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn missing_allow_flag_is_error() {
    let out = run(&["allow-test", "somevalue"]);
    assert!(!out.status.success());
}

#[test]
fn no_values_and_empty_stdin_is_error() {
    let out = run_stdin(&["allow-test", "--allow", "*.internal"], b"");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no values to test"),
        "got: {}",
        stderr(&out)
    );
}
