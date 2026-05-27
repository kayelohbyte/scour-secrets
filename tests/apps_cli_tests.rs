//! Integration tests for `sanitize apps` subcommands: list, add, remove, dir.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn run_with_apps_dir(args: &[&str], apps_dir: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args(args)
        .env("SANITIZE_LOG", "error")
        .env("SANITIZE_APPS_DIR", apps_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap()
}

fn stdout(o: &std::process::Output) -> &str {
    std::str::from_utf8(&o.stdout).unwrap().trim()
}

fn stderr(o: &std::process::Output) -> &str {
    std::str::from_utf8(&o.stderr).unwrap().trim()
}

fn write_profile(dir: &std::path::Path, filename: &str) {
    fs::write(
        dir.join(filename),
        b"# Test app profile\n- processor: yaml\n  extensions: [\".yaml\"]\n  fields:\n    - pattern: \"*.password\"\n      category: \"custom:password\"\n",
    )
    .unwrap();
}

fn write_secrets(dir: &std::path::Path, filename: &str) {
    fs::write(
        dir.join(filename),
        b"- pattern: \"test-secret\"\n  kind: literal\n  category: \"custom:secret\"\n  label: test\n",
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// apps list
// ---------------------------------------------------------------------------

#[test]
fn apps_list_shows_builtins() {
    let dir = tempdir().unwrap();
    let out = run_with_apps_dir(&["apps"], dir.path().to_str().unwrap());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("gitlab"), "expected gitlab in: {s}");
    assert!(s.contains("nginx"), "expected nginx in: {s}");
    assert!(s.contains("postgresql"), "expected postgresql in: {s}");
}

#[test]
fn apps_list_shows_user_defined_app() {
    let dir = tempdir().unwrap();
    let app_dir = dir.path().join("myapp");
    fs::create_dir_all(&app_dir).unwrap();
    write_profile(&app_dir, "profile.yaml");

    let out = run_with_apps_dir(&["apps"], dir.path().to_str().unwrap());
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("myapp"), "expected myapp in: {s}");
}

// ---------------------------------------------------------------------------
// apps dir
// ---------------------------------------------------------------------------

#[test]
fn apps_dir_prints_path() {
    let dir = tempdir().unwrap();
    let out = run_with_apps_dir(&["apps", "dir"], dir.path().to_str().unwrap());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains(dir.path().to_str().unwrap()),
        "got: {}",
        stdout(&out)
    );
}

// ---------------------------------------------------------------------------
// apps add — happy paths
// ---------------------------------------------------------------------------

#[test]
fn apps_add_profile_only() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("myapp.profile.yaml");
    write_profile(dir.path(), "myapp.profile.yaml");

    let apps_dir = dir.path().join("apps");
    let out = run_with_apps_dir(
        &["apps", "add", "myapp", "--profile", src.to_str().unwrap()],
        apps_dir.to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(apps_dir.join("myapp").join("profile.yaml").exists());
    assert!(!apps_dir.join("myapp").join("secrets.yaml").exists());
    assert!(stdout(&out).contains("myapp"), "got: {}", stdout(&out));
}

#[test]
fn apps_add_secrets_only() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("myapp.secrets.yaml");
    write_secrets(dir.path(), "myapp.secrets.yaml");

    let apps_dir = dir.path().join("apps");
    let out = run_with_apps_dir(
        &["apps", "add", "myapp", "--secrets-file", src.to_str().unwrap()],
        apps_dir.to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(apps_dir.join("myapp").join("secrets.yaml").exists());
    assert!(!apps_dir.join("myapp").join("profile.yaml").exists());
}

#[test]
fn apps_add_both_files() {
    let dir = tempdir().unwrap();
    write_profile(dir.path(), "p.yaml");
    write_secrets(dir.path(), "s.yaml");

    let apps_dir = dir.path().join("apps");
    let out = run_with_apps_dir(
        &[
            "apps",
            "add",
            "elastic",
            "--profile",
            dir.path().join("p.yaml").to_str().unwrap(),
            "--secrets-file",
            dir.path().join("s.yaml").to_str().unwrap(),
        ],
        apps_dir.to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(apps_dir.join("elastic").join("profile.yaml").exists());
    assert!(apps_dir.join("elastic").join("secrets.yaml").exists());
}

#[test]
fn apps_add_shows_in_list_after_install() {
    let dir = tempdir().unwrap();
    write_profile(dir.path(), "p.yaml");
    let apps_dir = dir.path().join("apps");

    run_with_apps_dir(
        &[
            "apps",
            "add",
            "newapp",
            "--profile",
            dir.path().join("p.yaml").to_str().unwrap(),
        ],
        apps_dir.to_str().unwrap(),
    );

    let list_out = run_with_apps_dir(&["apps"], apps_dir.to_str().unwrap());
    assert!(
        stdout(&list_out).contains("newapp"),
        "got: {}",
        stdout(&list_out)
    );
}

// ---------------------------------------------------------------------------
// apps add — overwrite
// ---------------------------------------------------------------------------

#[test]
fn apps_add_fails_if_exists_without_overwrite() {
    let dir = tempdir().unwrap();
    write_profile(dir.path(), "p.yaml");
    let apps_dir = dir.path().join("apps");
    let profile_src = dir.path().join("p.yaml");

    // First install succeeds.
    let out1 = run_with_apps_dir(
        &[
            "apps",
            "add",
            "myapp",
            "--profile",
            profile_src.to_str().unwrap(),
        ],
        apps_dir.to_str().unwrap(),
    );
    assert!(out1.status.success());

    // Second install without --overwrite fails.
    let out2 = run_with_apps_dir(
        &[
            "apps",
            "add",
            "myapp",
            "--profile",
            profile_src.to_str().unwrap(),
        ],
        apps_dir.to_str().unwrap(),
    );
    assert!(!out2.status.success());
    assert!(
        stderr(&out2).contains("already exists") || stderr(&out2).contains("--overwrite"),
        "got: {}",
        stderr(&out2)
    );
}

#[test]
fn apps_add_overwrite_succeeds() {
    let dir = tempdir().unwrap();
    write_profile(dir.path(), "p.yaml");
    let apps_dir = dir.path().join("apps");
    let profile_src = dir.path().join("p.yaml");

    run_with_apps_dir(
        &[
            "apps",
            "add",
            "myapp",
            "--profile",
            profile_src.to_str().unwrap(),
        ],
        apps_dir.to_str().unwrap(),
    );

    let out = run_with_apps_dir(
        &[
            "apps",
            "add",
            "myapp",
            "--profile",
            profile_src.to_str().unwrap(),
            "--overwrite",
        ],
        apps_dir.to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
}

// ---------------------------------------------------------------------------
// apps add — error cases
// ---------------------------------------------------------------------------

#[test]
fn apps_add_requires_at_least_one_file() {
    let dir = tempdir().unwrap();
    let apps_dir = dir.path().join("apps");
    let out = run_with_apps_dir(&["apps", "add", "myapp"], apps_dir.to_str().unwrap());
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--profile") || stderr(&out).contains("--secrets"),
        "got: {}",
        stderr(&out)
    );
}

#[test]
fn apps_add_invalid_name_rejected() {
    let dir = tempdir().unwrap();
    write_profile(dir.path(), "p.yaml");
    let apps_dir = dir.path().join("apps");
    let profile_src = dir.path().join("p.yaml");

    for bad_name in &["", "my app", "my/app", "../escape"] {
        let out = run_with_apps_dir(
            &[
                "apps",
                "add",
                bad_name,
                "--profile",
                profile_src.to_str().unwrap(),
            ],
            apps_dir.to_str().unwrap(),
        );
        assert!(
            !out.status.success(),
            "expected failure for name '{bad_name}', got success"
        );
    }
}

#[test]
fn apps_add_invalid_profile_yaml_rejected() {
    let dir = tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    fs::write(&bad, b"this is: not: valid: profile: yaml: [[[").unwrap();
    let apps_dir = dir.path().join("apps");

    let out = run_with_apps_dir(
        &["apps", "add", "myapp", "--profile", bad.to_str().unwrap()],
        apps_dir.to_str().unwrap(),
    );
    assert!(!out.status.success());
    // Directory must not be created when validation fails.
    assert!(!apps_dir.join("myapp").exists());
}

#[test]
fn apps_add_invalid_secrets_yaml_rejected() {
    let dir = tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    fs::write(&bad, b"not_an_array: true").unwrap();
    let apps_dir = dir.path().join("apps");

    let out = run_with_apps_dir(
        &["apps", "add", "myapp", "--secrets", bad.to_str().unwrap()],
        apps_dir.to_str().unwrap(),
    );
    assert!(!out.status.success());
    assert!(!apps_dir.join("myapp").exists());
}

// ---------------------------------------------------------------------------
// apps remove
// ---------------------------------------------------------------------------

#[test]
fn apps_remove_requires_yes_flag() {
    let dir = tempdir().unwrap();
    write_profile(dir.path(), "p.yaml");
    let apps_dir = dir.path().join("apps");

    run_with_apps_dir(
        &[
            "apps",
            "add",
            "myapp",
            "--profile",
            dir.path().join("p.yaml").to_str().unwrap(),
        ],
        apps_dir.to_str().unwrap(),
    );

    let out = run_with_apps_dir(&["apps", "remove", "myapp"], apps_dir.to_str().unwrap());
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--yes") || stderr(&out).contains("-y"),
        "got: {}",
        stderr(&out)
    );
    // App must still exist.
    assert!(apps_dir.join("myapp").exists());
}

#[test]
fn apps_remove_with_yes_deletes_app() {
    let dir = tempdir().unwrap();
    write_profile(dir.path(), "p.yaml");
    let apps_dir = dir.path().join("apps");

    run_with_apps_dir(
        &[
            "apps",
            "add",
            "myapp",
            "--profile",
            dir.path().join("p.yaml").to_str().unwrap(),
        ],
        apps_dir.to_str().unwrap(),
    );

    let out = run_with_apps_dir(
        &["apps", "remove", "myapp", "--yes"],
        apps_dir.to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!apps_dir.join("myapp").exists());
}

#[test]
fn apps_remove_nonexistent_is_error() {
    let dir = tempdir().unwrap();
    let apps_dir = dir.path().join("apps");
    let out = run_with_apps_dir(
        &["apps", "remove", "doesnotexist", "--yes"],
        apps_dir.to_str().unwrap(),
    );
    assert!(!out.status.success());
}

#[test]
fn apps_remove_builtin_is_rejected() {
    let dir = tempdir().unwrap();
    let apps_dir = dir.path().join("apps");
    let out = run_with_apps_dir(
        &["apps", "remove", "gitlab", "--yes"],
        apps_dir.to_str().unwrap(),
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("built-in"), "got: {}", stderr(&out));
}

#[test]
fn apps_remove_and_gone_from_list() {
    let dir = tempdir().unwrap();
    write_profile(dir.path(), "p.yaml");
    let apps_dir = dir.path().join("apps");
    let profile_src = dir.path().join("p.yaml");

    run_with_apps_dir(
        &[
            "apps",
            "add",
            "tempapp",
            "--profile",
            profile_src.to_str().unwrap(),
        ],
        apps_dir.to_str().unwrap(),
    );
    run_with_apps_dir(
        &["apps", "remove", "tempapp", "--yes"],
        apps_dir.to_str().unwrap(),
    );

    let list_out = run_with_apps_dir(&["apps"], apps_dir.to_str().unwrap());
    assert!(
        !stdout(&list_out).contains("tempapp"),
        "got: {}",
        stdout(&list_out)
    );
}
