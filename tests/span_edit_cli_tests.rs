//! CLI-level integration tests for span-based structured editing (Solution A).
//!
//! Each test drives the real `sanitize` binary end-to-end for one format with a
//! `--profile`, asserting two properties: (1) the secret — including values that
//! are *escaped in the source* — is gone, and (2) comments / formatting /
//! non-matched content are preserved byte-for-byte.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

/// `app.toml` -> `app-sanitized.toml`.
fn sanitized_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}-sanitized.{ext}"),
        None => format!("{name}-sanitized"),
    }
}

/// Run the binary on `input` with `profile_json`, returning the sanitized output.
fn sanitize(input_name: &str, input: &[u8], profile_json: &str) -> String {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join(input_name);
    fs::write(&input_path, input).unwrap();
    let profile = dir.path().join("profile.json");
    fs::write(&profile, profile_json).unwrap();
    let secrets = dir.path().join("secrets.json");
    fs::write(&secrets, b"[]").unwrap();
    let outdir = dir.path().join("out");
    fs::create_dir_all(&outdir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input_path.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--output",
            outdir.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .env("SANITIZE_NO_SETTINGS", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sanitize failed for {input_name}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::read_to_string(outdir.join(sanitized_name(input_name))).unwrap()
}

fn assert_gone(text: &str, secrets: &[&str]) {
    for s in secrets {
        assert!(!text.contains(s), "leaked {s:?} in output:\n{text}");
    }
}

fn assert_kept(text: &str, fragments: &[&str]) {
    for f in fragments {
        assert!(
            text.contains(f),
            "expected {f:?} to be preserved in:\n{text}"
        );
    }
}

#[test]
fn cli_toml_span_edit() {
    let input = br#"# top comment
[database]
password = "p@ss-SEC1"   # inline comment
host = "keep.local"
literal = 'lit-SEC2'
escaped = "a\"b-SEC3"
port = 5432
"#;
    let profile = r#"[{"processor":"toml","extensions":[".toml"],"fields":[
        {"pattern":"*password*","category":"custom:password"},
        {"pattern":"database.literal","category":"auth_token"},
        {"pattern":"database.escaped","category":"auth_token"}
    ]}]"#;
    let out = sanitize("app.toml", input, profile);
    assert_gone(&out, &["p@ss-SEC1", "lit-SEC2", "a\"b-SEC3"]);
    assert_kept(
        &out,
        &[
            "# top comment",
            "# inline comment",
            "host = \"keep.local\"",
            "port = 5432",
        ],
    );
}

#[test]
fn cli_json_span_edit() {
    // \/ (PHP-style), \uXXXX (unicode), \" (escaped quote) — the alias-leak cases.
    let input = br#"{"u":"http:\/\/SEC1.x","n":"caf\u00e9-SEC2","a":"x\"y-SEC3","keep":"ok"}"#;
    let profile = r#"[{"processor":"json","extensions":[".json"],"fields":[
        {"pattern":"u","category":"url"},
        {"pattern":"n","category":"auth_token"},
        {"pattern":"a","category":"auth_token"}
    ]}]"#;
    let out = sanitize("data.json", input, profile);
    assert_gone(&out, &["SEC1", "SEC2", "SEC3"]);
    assert_kept(&out, &[r#""keep":"ok""#]);
    assert!(!out.contains('\n'), "compact formatting changed:\n{out}");
}

#[test]
fn cli_jsonl_span_edit() {
    let input = b"{\"email\":\"a-SEC1@e.test\"}\n{\"u\":\"http:\\/\\/SEC2.x\"}\nnot json line\n";
    let profile = r#"[{"processor":"jsonl","extensions":[".jsonl"],"options":{"skip_invalid":"true"},"fields":[
        {"pattern":"email","category":"email"},
        {"pattern":"u","category":"url"}
    ]}]"#;
    let out = sanitize("logs.jsonl", input, profile);
    assert_gone(&out, &["SEC1", "SEC2"]);
    assert_kept(&out, &["not json line"]);
}

#[test]
fn cli_yaml_span_edit() {
    let input = br#"# top comment
db:
  password: plain-SEC1   # inline comment
  quoted: "dq-SEC2"
  escaped: "a\"b-SEC3"
  host: keep.local
"#;
    let profile = r#"[{"processor":"yaml","extensions":[".yaml"],"fields":[
        {"pattern":"db.password","category":"custom:password"},
        {"pattern":"db.quoted","category":"auth_token"},
        {"pattern":"db.escaped","category":"auth_token"}
    ]}]"#;
    let out = sanitize("conf.yaml", input, profile);
    assert_gone(&out, &["plain-SEC1", "dq-SEC2", "a\"b-SEC3"]);
    assert_kept(
        &out,
        &["# top comment", "# inline comment", "host: keep.local"],
    );
}

#[cfg(feature = "structured")]
#[test]
fn cli_xml_span_edit() {
    let input =
        b"<!-- doc --><c><db pw=\"a&lt;b-SEC1\" host=\"keep\"/><t>tok-SEC2</t><k>ok</k></c>";
    let profile = r#"[{"processor":"xml","extensions":[".xml"],"fields":[
        {"pattern":"c/db/@pw","category":"auth_token"},
        {"pattern":"c/t","category":"auth_token"}
    ]}]"#;
    let out = sanitize("doc.xml", input, profile);
    // SEC1 is entity-encoded in source (a&lt;b-SEC1); SEC2 is element text.
    assert_gone(&out, &["SEC1", "SEC2"]);
    assert_kept(&out, &["<!-- doc -->", "host=\"keep\"", "<k>ok</k>"]);
}

#[cfg(feature = "structured")]
#[test]
fn cli_csv_span_edit() {
    // Quoted field with an embedded comma, and a ""-escaped quote.
    let input = b"name,email,note\nAlice,a-SEC1@e.test,\"has,comma-SEC2\"\nBob,\"b\"\"q-SEC3@e.test\",plain\n";
    let profile = r#"[{"processor":"csv","extensions":[".csv"],"fields":[
        {"pattern":"email","category":"email"},
        {"pattern":"note","category":"auth_token"}
    ]}]"#;
    let out = sanitize("rows.csv", input, profile);
    assert_gone(&out, &["SEC1", "SEC2", "SEC3"]);
    // Header and the non-matched `name` column are intact.
    assert_kept(&out, &["name,email,note", "Alice,", "Bob,"]);
}
