//! Integration tests for the `--app` flag in the main sanitize flow and `--no-structured-handoff`.

use std::fs;
use std::process::{Command, Stdio};
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

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "--app",
            "gitlab",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
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

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "--app",
            "gitlab",
            "-s",
            secrets.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
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

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "--app",
            "nonexistent_bundle_xyz",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "expected non-zero exit for unknown --app bundle; got exit 0"
    );
}

/// 4. --no-structured-handoff suppresses writing of any discovered-secrets file.
///    With no -s flag, the tool should not write a scour-secrets-discovered.yaml
///    (or any similar auto-save file) into the working directory.
#[test]
fn no_structured_handoff_does_not_write_discovered_file() {
    let dir = tempdir().unwrap();
    let profile = write_kv_profile(dir.path(), "profile.json");
    let input = write_cfg_input(dir.path(), "input.cfg");
    let output = dir.path().join("output.cfg");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--no-structured-handoff",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        // Set CWD to the temp dir so any unexpected auto-written files land there.
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "expected exit 0 with --profile --no-structured-handoff; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // No scour-secrets-discovered.yaml (or similar) should have been created in the
    // temp dir since no --secrets-file was supplied and --no-structured-handoff is set.
    assert!(
        !dir.path().join("scour-secrets-discovered.yaml").exists(),
        "scour-secrets-discovered.yaml should not be written when --no-structured-handoff is set"
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

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
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
        .env("SCOUR_SECRETS_LOG", "error")
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
///
/// Uses stdin→stdout to avoid reading an output file written by the child
/// process, which can trigger spurious PermissionDenied errors on Windows CI.
#[test]
fn allow_flag_passes_value_through_unchanged() {
    use std::io::Write as _;

    let dir = tempdir().unwrap();

    // IPv4 regex pattern.
    let secrets_path = dir.path().join("secrets.json");
    fs::write(
        &secrets_path,
        r#"[{"pattern":"[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}","kind":"regex","category":"ipv4","label":"ipv4_addr"}]"#,
    )
    .unwrap();

    // Pipe input via stdin so the output arrives on stdout — no output file to
    // read back, which sidesteps Windows CI file-permission flakiness.
    let mut child = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            "-", // read from stdin
            "-s",
            secrets_path.to_str().unwrap(),
            "--allow",
            "192.168.1.1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .current_dir(dir.path())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"server at 192.168.1.1 and client at 10.0.0.1\n")
        .unwrap();

    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let result = String::from_utf8_lossy(&out.stdout);

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

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
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
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
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
    // log uses the exact same string (cross-file consistency). Span-based YAML
    // editing emits the value double-quoted (`password: "TOKEN"`), so strip any
    // surrounding quotes to get the bare token that appears in the log.
    let replacement = config_out
        .lines()
        .find(|l| l.contains("password:"))
        .and_then(|l| l.split_once(':').map(|x| x.1))
        .map(|v| v.trim().trim_matches('"'))
        .expect("config output must have a password: line");

    assert!(
        log_out.contains(replacement),
        "log must use the same replacement as config (two-pass cross-file seeding); \
         replacement={replacement:?}, log:\n{log_out}"
    );
}

/// Regression: a value appearing in the structured fields of **two** structured
/// files must be redacted in **both**, not only the first one processed.
///
/// Previously each structured file built its format-preserving scanner from the
/// per-file discovery delta, so a value already in the store from an earlier
/// file was skipped in later files (silent plaintext leak). The discovery
/// pre-pass + full-store output pass fixes this and makes the result
/// independent of command-line order.
#[test]
fn duplicate_value_across_structured_files_redacted_in_both() {
    let shared = "dup-pii-shared@corp.example";

    // Two JSON files, each with the same email in a structured field, plus the
    // value embedded in a string ("comment"-like) region of the first.
    for order in [["a.json", "b.json"], ["b.json", "a.json"]] {
        let dir = tempdir().unwrap();
        let outdir = dir.path().join("out");
        fs::create_dir_all(&outdir).unwrap();

        let a = dir.path().join("a.json");
        fs::write(
            &a,
            format!(r#"{{"user":{{"email":"{shared}"}},"note":"ping {shared} for access"}}"#),
        )
        .unwrap();
        let b = dir.path().join("b.json");
        fs::write(&b, format!(r#"{{"acct":{{"email":"{shared}"}}}}"#)).unwrap();

        let secrets = dir.path().join("secrets.json");
        fs::write(&secrets, b"[]").unwrap();

        let profile = dir.path().join("profile.json");
        fs::write(
            &profile,
            r#"[{"processor":"json","extensions":[".json"],"fields":[{"pattern":"*.email","category":"email"}]}]"#,
        )
        .unwrap();

        let first = dir.path().join(order[0]);
        let second = dir.path().join(order[1]);
        let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
            .args([
                first.to_str().unwrap(),
                second.to_str().unwrap(),
                "-s",
                secrets.to_str().unwrap(),
                "--profile",
                profile.to_str().unwrap(),
                "--output",
                outdir.to_str().unwrap(),
            ])
            .env("SCOUR_SECRETS_LOG", "error")
            .env("SCOUR_SECRETS_NO_SETTINGS", "1")
            .output()
            .unwrap();

        assert!(
            out.status.success(),
            "order {order:?} stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let a_out = fs::read_to_string(outdir.join("a-sanitized.json")).unwrap();
        let b_out = fs::read_to_string(outdir.join("b-sanitized.json")).unwrap();

        assert!(
            !a_out.contains(shared),
            "order {order:?}: first/second file a.json leaked the shared value:\n{a_out}"
        );
        assert!(
            !b_out.contains(shared),
            "order {order:?}: file b.json leaked the shared value (the regression):\n{b_out}"
        );
    }
}

/// Regression: a value containing characters that are *escaped* by a format
/// (a `"` and a `\`) — discovered in a matched field of one file — must still
/// be redacted where it reappears in an **unmatched** field of another file,
/// even though that field escapes it differently (JSON `\"`, CSV `""`).
///
/// The earlier cross-file test used a value with no escapable characters, so
/// the raw-byte phase-2 scanner caught it directly and never exercised the
/// escaped-alias path. When span editing ("Solution A") replaced the old
/// re-serialize path it dropped alias registration in the discovery path, and
/// nothing covered "special-char value in an unmatched field of another file"
/// — so the leak went uncaught. This test pins that path shut.
#[test]
fn escaped_value_in_unmatched_field_redacted_cross_file() {
    // Parsed value carries a special-char-free marker so any escaped leak
    // (JSON `\"`, CSV `""`) is caught by a single substring check.
    let marker = "SECXMARK";
    let dir = tempdir().unwrap();
    let outdir = dir.path().join("out");
    fs::create_dir_all(&outdir).unwrap();

    // Discovery file: token field matched by `*.token`. Raw bytes are the
    // JSON-escaped form, so the parsed value is `tok"SECXMARK\val`.
    let disc = dir.path().join("disc.json");
    fs::write(&disc, r#"{"creds":{"token":"tok\"SECXMARK\\val"}}"#).unwrap();

    // Unmatched JSON field (escaped) in a second file.
    let unj = dir.path().join("un.json");
    fs::write(&unj, r#"{"other":"tok\"SECXMARK\\val"}"#).unwrap();

    // Unmatched CSV column (quote-doubled) in a third file.
    let unc = dir.path().join("un.csv");
    fs::write(unc, "zzz\n\"tok\"\"SECXMARK\\val\"\n").unwrap();

    let secrets = dir.path().join("secrets.json");
    fs::write(&secrets, b"[]").unwrap();
    let profile = dir.path().join("profile.json");
    fs::write(
        &profile,
        r#"[{"processor":"json","extensions":[".json"],"fields":[{"pattern":"*.token","category":"auth_token"}]},
           {"processor":"csv","extensions":[".csv"],"fields":[{"pattern":"col_with_no_match","category":"auth_token"}]}]"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            disc.to_str().unwrap(),
            unj.to_str().unwrap(),
            dir.path().join("un.csv").to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--output",
            outdir.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let un_json = fs::read_to_string(outdir.join("un-sanitized.json")).unwrap();
    let un_csv = fs::read_to_string(outdir.join("un-sanitized.csv")).unwrap();
    assert!(
        !un_json.contains(marker),
        "escaped value leaked in unmatched JSON field:\n{un_json}"
    );
    assert!(
        !un_csv.contains(marker),
        "escaped value leaked in unmatched CSV column:\n{un_csv}"
    );
}

/// Build a `.tar.gz` file on disk from `(name, bytes)` entries.
fn write_targz(path: &std::path::Path, entries: &[(&str, &[u8])]) {
    let f = fs::File::create(path).unwrap();
    let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
    let mut builder = tar::Builder::new(enc);
    for (name, data) in entries {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_size(data.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_mtime(1_700_000_000);
        hdr.set_cksum();
        builder.append_data(&mut hdr, *name, *data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap();
}

/// Read all file entries of a `.tar.gz` into one concatenated string.
fn read_targz(path: &std::path::Path) -> String {
    use std::io::Read;
    let f = fs::File::open(path).unwrap();
    let dec = flate2::read::GzDecoder::new(f);
    let mut ar = tar::Archive::new(dec);
    let mut s = String::new();
    for e in ar.entries().unwrap() {
        e.unwrap().read_to_string(&mut s).unwrap();
    }
    s
}

/// Regression: a value found in a structured entry of one archive must be
/// redacted in *another* archive in the same run (cross-archive seeding via the
/// discovery pre-pass), not only in the archive it was discovered in.
#[test]
fn cross_archive_duplicate_value_redacted_in_both_archives() {
    let dir = tempdir().unwrap();
    let outdir = dir.path().join("out");
    fs::create_dir_all(&outdir).unwrap();
    let shared = "cross-arch-shared@corp.example";

    let a1 = dir.path().join("a1.tar.gz");
    write_targz(
        &a1,
        &[(
            "users.json",
            format!(r#"{{"email":"{shared}"}}"#).as_bytes(),
        )],
    );
    let a2 = dir.path().join("a2.tar.gz");
    write_targz(
        &a2,
        &[(
            "accounts.json",
            format!(r#"{{"email":"{shared}"}}"#).as_bytes(),
        )],
    );

    let secrets = dir.path().join("secrets.json");
    fs::write(&secrets, b"[]").unwrap();
    let profile = dir.path().join("profile.json");
    fs::write(
        &profile,
        r#"[{"processor":"json","extensions":[".json"],"fields":[{"pattern":"*.email","category":"email"}]}]"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            a1.to_str().unwrap(),
            a2.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--output",
            outdir.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let a1_out = read_targz(&outdir.join("a1.sanitized.tar.gz"));
    let a2_out = read_targz(&outdir.join("a2.sanitized.tar.gz"));
    assert!(
        !a1_out.contains(shared),
        "a1 leaked the shared value:\n{a1_out}"
    );
    assert!(
        !a2_out.contains(shared),
        "a2 leaked the shared value (cross-archive seeding failed):\n{a2_out}"
    );
}

/// A profile that declares a non-structured extension (e.g. `.log`) must still
/// route the file through structured processing — the file-format gate is
/// profile-aware, not extension-only. Regression: `.log` JSONL log profiles
/// (GitLab production/sidekiq/etc.) were silently dropped to the scanner and
/// never fired. Also covers JSONL: every line must be scrubbed, not just the
/// first.
#[test]
fn profile_custom_log_extension_is_structured() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("production_json.log");
    // Two JSON objects on separate lines (JSONL) — the real GitLab log shape.
    fs::write(
        &input,
        "{\"meta\":{\"user\":\"alice-secret\"}}\n{\"meta\":{\"user\":\"bob-secret\"}}\n",
    )
    .unwrap();
    let output = dir.path().join("out.log");

    let secrets = dir.path().join("secrets.json");
    fs::write(&secrets, b"[]").unwrap();
    let profile = dir.path().join("profile.json");
    fs::write(
        &profile,
        r#"[{"processor":"jsonl","extensions":[".log"],"include":["production_json.log"],"fields":[{"pattern":"meta.user","category":"name"}]}]"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let result = fs::read_to_string(&output).unwrap();
    assert!(
        !result.contains("alice-secret"),
        "first-line value leaked (profile .log not structured):\n{result}"
    );
    assert!(
        !result.contains("bob-secret"),
        "second-line value leaked (JSONL only scrubbed first object):\n{result}"
    );
}

/// In-place structured field edits must be counted in the run summary.
/// Regression: profile field redactions on a plain structured file were applied
/// but never reflected in `total_matches`, so the summary printed
/// "Redacted: nothing" while the file was correctly scrubbed.
#[test]
fn structured_field_edits_are_counted_in_summary() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("values.yaml");
    // Two Helm credential fields the gitlab bundle redacts via span edits only
    // (no baseline scanner pattern matches these key paths).
    fs::write(
        &input,
        "global:\n  initialRootPassword: superSecret123\n  smtp:\n    password: smtpPass456\n",
    )
    .unwrap();
    let output = dir.path().join("out.yaml");

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([
            input.to_str().unwrap(),
            "--app",
            "gitlab",
            "-o",
            output.to_str().unwrap(),
        ])
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .output()
        .unwrap();
    assert!(out.status.success());

    // The summary is printed to stderr. It must report the field edits, not
    // "nothing".
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("profile-field"),
        "summary should count structured field edits; stderr was:\n{stderr}"
    );
    assert!(
        !stderr.contains("Redacted: nothing"),
        "summary undercounted structured edits; stderr was:\n{stderr}"
    );
    // And the values were actually redacted.
    let result = fs::read_to_string(&output).unwrap();
    assert!(!result.contains("superSecret123") && !result.contains("smtpPass456"));
}
