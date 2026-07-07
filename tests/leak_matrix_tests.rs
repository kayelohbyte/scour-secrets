//! Systematic leak + format-preservation matrix.
//!
//! These tests pin the two core guarantees — **zero leaks** and **byte-exact
//! format preservation** — across the combinatorial space that previously hid
//! regressions:
//!
//! * **format**: TOML / JSON / JSONL / YAML / XML / CSV
//! * **value class**: plain (no escapable chars) vs special (quote, backslash,
//!   forward slash, comma, single quote — i.e. characters each format escapes
//!   differently), including a *mix* of escaped and unescaped runs
//! * **location**: matched field (span editor) / unmatched field (alias net) /
//!   comment / free text (raw scanner)
//! * **scope**: same-file and cross-file (discovered in one file, reappears in
//!   another)
//! * **EOF / line endings**: LF, CRLF, and no-trailing-newline
//!
//! Each canary value carries a special-char-free MARKER substring, so a leak in
//! *any* format's escaping is caught by a single substring check.

#![cfg(feature = "structured")]

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

const M_PLAIN: &str = "MARKPLAIN";
const M_SPEC: &str = "MARKSPEC";
const M_UNI: &str = "MARKUNI";
const MARKERS: [&str; 3] = [M_PLAIN, M_SPEC, M_UNI];

/// Plain value: no characters that any format escapes.
fn plain() -> String {
    format!("{M_PLAIN}-token-abcdef-987654")
}
/// Special value: a mix of escaped specials (`"` `\` `,` `'`) and unescaped
/// runs, with the marker up front so any partial/escaped leak is detectable.
fn spec() -> String {
    format!("{M_SPEC}-a\"b\\c/d,e'f-plainrun-42")
}
/// Unicode value: multi-byte UTF-8 (accented, emoji/snowman, Greek) interleaved
/// with the escapable specials — exercises byte-span slicing on char boundaries.
/// The ASCII marker ensures any partial/escaped leak is still detectable.
fn unicode() -> String {
    format!("{M_UNI}-café\"☃/λ\\x,β'γ-Ünïcödé")
}

// ---- per-format encoders: embed `v` as a quoted/escaped scalar literal ----
fn e_json(v: &str) -> String {
    serde_json::to_string(v).unwrap()
}
fn e_toml(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}
fn e_yaml(v: &str) -> String {
    // YAML double-quoted is a superset of JSON string escaping for our chars.
    serde_json::to_string(v).unwrap()
}
fn e_xml_attr(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
}
fn e_xml_text(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
fn e_csv(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

fn sanitized_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}-sanitized.{ext}"),
        None => format!("{name}-sanitized"),
    }
}

/// Write `files` into a temp dir, run the binary with `profile`, and return the
/// sanitized output of every input keyed by its sanitized filename.
fn run(files: &[(&str, Vec<u8>)], profile: &str) -> BTreeMap<String, String> {
    let dir = tempdir().unwrap();
    let outdir = dir.path().join("out");
    fs::create_dir_all(&outdir).unwrap();
    let mut args: Vec<String> = Vec::new();
    for (name, bytes) in files {
        let p = dir.path().join(name);
        fs::write(&p, bytes).unwrap();
        args.push(p.to_str().unwrap().to_string());
    }
    let secrets = dir.path().join("secrets.json");
    fs::write(&secrets, b"[]").unwrap();
    let prof = dir.path().join("profile.json");
    fs::write(&prof, profile).unwrap();
    args.extend([
        "-s".into(),
        secrets.to_str().unwrap().into(),
        "--profile".into(),
        prof.to_str().unwrap().into(),
        "--output".into(),
        outdir.to_str().unwrap().into(),
    ]);

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(&args)
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scour-secrets failed; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut res = BTreeMap::new();
    for (name, _) in files {
        let san = sanitized_name(name);
        let p = outdir.join(&san);
        if let Ok(text) = fs::read_to_string(&p) {
            res.insert(san, text);
        }
    }
    res
}

/// Assert no marker (plain or special) survives in any output entry.
fn assert_no_leak(label: &str, outs: &BTreeMap<String, String>) {
    for (name, text) in outs {
        for m in MARKERS {
            assert!(!text.contains(m), "[{label}] leaked {m} in {name}:\n{text}");
        }
    }
}

/// Assert every fragment is preserved verbatim somewhere in the named output.
fn assert_kept(label: &str, outs: &BTreeMap<String, String>, name: &str, fragments: &[&str]) {
    let text = outs
        .get(name)
        .unwrap_or_else(|| panic!("[{label}] missing output {name}"));
    for f in fragments {
        assert!(
            text.contains(f),
            "[{label}] expected {f:?} preserved in {name}:\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Leak matrix, per format. Each run discovers V in a matched field, then
// requires it gone from: a same-file comment, a cross-file unmatched field,
// and (where the format has one) free text — for both plain and special V.
// ---------------------------------------------------------------------------

#[test]
fn matrix_toml() {
    for v in [plain(), spec(), unicode()] {
        let disc = format!(
            "# header comment with raw secret: {v}\n\
             [s]\n\
             secret = {}   # inline keep-comment\n\
             keep = \"KEEPVAL\"\n",
            e_toml(&v)
        );
        let unmatched = format!("[other]\nnote = {}\nkeep2 = \"KEEPVAL2\"\n", e_toml(&v));
        let profile = r#"[{"processor":"toml","extensions":[".toml"],
            "fields":[{"pattern":"s.secret","category":"auth_token"}]}]"#;
        let outs = run(
            &[
                ("disc.toml", disc.into_bytes()),
                ("un.toml", unmatched.into_bytes()),
            ],
            profile,
        );
        assert_no_leak("toml", &outs);
        assert_kept(
            "toml",
            &outs,
            "disc-sanitized.toml",
            &["[s]", "# inline keep-comment", "KEEPVAL"],
        );
        assert_kept("toml", &outs, "un-sanitized.toml", &["[other]", "KEEPVAL2"]);
    }
}

#[test]
fn matrix_json() {
    for v in [plain(), spec(), unicode()] {
        let disc = format!(
            r#"{{"creds":{{"secret":{}}},"keep":"KEEPVAL"}}"#,
            e_json(&v)
        );
        let unmatched = format!(r#"{{"other":{},"keep2":"KEEPVAL2"}}"#, e_json(&v));
        let profile = r#"[{"processor":"json","extensions":[".json"],
            "fields":[{"pattern":"*.secret","category":"auth_token"}]}]"#;
        let outs = run(
            &[
                ("disc.json", disc.into_bytes()),
                ("un.json", unmatched.into_bytes()),
            ],
            profile,
        );
        assert_no_leak("json", &outs);
        assert_kept(
            "json",
            &outs,
            "disc-sanitized.json",
            &[r#""keep":"KEEPVAL""#],
        );
        assert_kept(
            "json",
            &outs,
            "un-sanitized.json",
            &[r#""keep2":"KEEPVAL2""#],
        );
    }
}

#[test]
fn matrix_jsonl() {
    for v in [plain(), spec(), unicode()] {
        // line 1: matched field; line 2: unmatched field (same file);
        // line 3: a non-JSON text line carrying the raw value (skip_invalid).
        let disc = format!(
            "{{\"secret\":{}}}\n{{\"other\":{}}}\nraw text line: {} keepline\n",
            e_json(&v),
            e_json(&v),
            v
        );
        let profile = r#"[{"processor":"jsonl","extensions":[".jsonl"],"options":{"skip_invalid":"true"},
            "fields":[{"pattern":"secret","category":"auth_token"}]}]"#;
        let outs = run(&[("disc.jsonl", disc.into_bytes())], profile);
        assert_no_leak("jsonl", &outs);
        assert_kept(
            "jsonl",
            &outs,
            "disc-sanitized.jsonl",
            &["raw text line:", "keepline"],
        );
    }
}

#[test]
fn matrix_yaml() {
    for v in [plain(), spec(), unicode()] {
        let disc = format!(
            "# header comment with raw secret: {v}\n\
             s:\n  secret: {}   # inline keep-comment\n  keep: KEEPVAL\n",
            e_yaml(&v)
        );
        let unmatched = format!("other:\n  note: {}\n  keep2: KEEPVAL2\n", e_yaml(&v));
        let profile = r#"[{"processor":"yaml","extensions":[".yaml"],
            "fields":[{"pattern":"s.secret","category":"auth_token"}]}]"#;
        let outs = run(
            &[
                ("disc.yaml", disc.into_bytes()),
                ("un.yaml", unmatched.into_bytes()),
            ],
            profile,
        );
        assert_no_leak("yaml", &outs);
        assert_kept(
            "yaml",
            &outs,
            "disc-sanitized.yaml",
            &["# inline keep-comment", "keep: KEEPVAL"],
        );
        assert_kept("yaml", &outs, "un-sanitized.yaml", &["keep2: KEEPVAL2"]);
    }
}

#[test]
fn matrix_xml() {
    for v in [plain(), spec(), unicode()] {
        // matched attribute + same-file comment (raw) + text (escaped);
        // cross-file unmatched attribute and unmatched element text.
        let disc = format!(
            "<!-- comment raw secret: {} --><r><db pw=\"{}\" keep=\"KEEPVAL\"/><t>{}</t></r>",
            v,
            e_xml_attr(&v),
            e_xml_text(&v)
        );
        let unmatched = format!(
            "<r2 other=\"{}\" keep2=\"KEEPVAL2\"><note>{}</note></r2>",
            e_xml_attr(&v),
            e_xml_text(&v)
        );
        let profile = r#"[{"processor":"xml","extensions":[".xml"],
            "fields":[{"pattern":"r/db/@pw","category":"auth_token"},
                      {"pattern":"r/t","category":"auth_token"}]}]"#;
        let outs = run(
            &[
                ("disc.xml", disc.into_bytes()),
                ("un.xml", unmatched.into_bytes()),
            ],
            profile,
        );
        assert_no_leak("xml", &outs);
        assert_kept("xml", &outs, "disc-sanitized.xml", &["keep=\"KEEPVAL\""]);
        assert_kept("xml", &outs, "un-sanitized.xml", &["keep2=\"KEEPVAL2\""]);
    }
}

#[test]
fn matrix_csv() {
    for v in [plain(), spec(), unicode()] {
        // matched column `secret`; cross-file unmatched column `zzz`.
        let disc = format!("name,secret,keep\nAlice,{},KEEPVAL\n", e_csv(&v));
        let unmatched = format!("zzz,keep2\n{},KEEPVAL2\n", e_csv(&v));
        let profile = r#"[{"processor":"csv","extensions":[".csv"],
            "fields":[{"pattern":"secret","category":"auth_token"}]}]"#;
        let outs = run(
            &[
                ("disc.csv", disc.into_bytes()),
                ("un.csv", unmatched.into_bytes()),
            ],
            profile,
        );
        assert_no_leak("csv", &outs);
        assert_kept(
            "csv",
            &outs,
            "disc-sanitized.csv",
            &["name,secret,keep", "Alice,", "KEEPVAL"],
        );
        assert_kept("csv", &outs, "un-sanitized.csv", &["zzz,keep2", "KEEPVAL2"]);
    }
}

/// A leading UTF-8 BOM (common from Windows/Java exporters) must not stop a
/// matched secret from being redacted, and the BOM itself must be preserved.
/// Regression: jiter rejects a BOM, so BOM-prefixed JSON/JSONL silently leaked.
#[test]
fn bom_prefixed_files_redact_and_preserve() {
    const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
    let cases: &[(&str, Vec<u8>, &str)] = &[
        (
            "b.json",
            format!(r#"{{"secret":{},"keep":"BOMKEEP"}}"#, e_json("BOMSEC-a\"b")).into_bytes(),
            r#"[{"processor":"json","extensions":[".json"],"fields":[{"pattern":"secret","category":"auth_token"}]}]"#,
        ),
        (
            "b.jsonl",
            format!("{{\"secret\":{}}}\n", e_json("BOMSEC-l")).into_bytes(),
            r#"[{"processor":"jsonl","extensions":[".jsonl"],"options":{"skip_invalid":"true"},"fields":[{"pattern":"secret","category":"auth_token"}]}]"#,
        ),
    ];
    for (file, body, profile) in cases {
        let mut content = BOM.to_vec();
        content.extend_from_slice(body);
        let outs = run(&[(file, content)], profile);
        assert_no_leak(&format!("bom/{file}"), &outs);
        let out = &outs[&sanitized_name(file)];
        assert!(
            out.as_bytes().starts_with(BOM),
            "bom/{file}: BOM not preserved: {out:?}"
        );
        assert!(
            out.contains("BOMKEEP") || file.ends_with(".jsonl"),
            "bom/{file}: keep lost"
        );
    }
}

/// The non-span `process()` / `replace_value` path (INI, env, key-value, and the
/// oversized-file fallback) must register the same cross-format escaped aliases
/// as the span-edit path. Here a special-char value discovered in an INI file
/// (no span editor) must be redacted where it reappears — JSON-escaped — in an
/// unmatched field of another file.
#[test]
fn process_path_registers_escaped_aliases_cross_file() {
    let marker = "MARKINI";
    let value = format!("a\"b\\c-{marker}-x"); // quote + backslash
    let ini = format!("[s]\nsecret = {value}\nkeep = plain\n");
    let unmatched = format!(r#"{{"other":{}}}"#, e_json(&value));
    let profile = r#"[{"processor":"ini","extensions":[".ini"],"fields":[{"pattern":"s.secret","category":"auth_token"}]},
        {"processor":"json","extensions":[".json"],"fields":[{"pattern":"col_with_no_match","category":"auth_token"}]}]"#;
    let outs = run(
        &[
            ("disc.ini", ini.into_bytes()),
            ("un.json", unmatched.into_bytes()),
        ],
        profile,
    );
    assert_no_leak("process-path", &outs);
}

/// TSV (tab-delimited CSV via the `delimiter` option): a matched column with a
/// special-char value in the LAST column and NO trailing newline — exercises
/// the EOF flush with a non-comma delimiter. Header + unmatched column kept.
#[test]
fn tsv_tab_delimited_redacts_and_preserves() {
    for v in [spec(), unicode()] {
        // TSV-quote on tab/quote/newline (comma is an ordinary char here).
        let field = if v.contains(['\t', '"', '\n', '\r']) {
            format!("\"{}\"", v.replace('"', "\"\""))
        } else {
            v.clone()
        };
        // last column `secret` is matched; no trailing newline.
        let content = format!("name\tsecret\nAlice\t{field}");
        // `\t` inside the raw-string profile is the two bytes `\t` → JSON tab escape.
        let profile = r#"[{"processor":"csv","extensions":[".tsv"],"options":{"delimiter":"\t"},
            "fields":[{"pattern":"secret","category":"auth_token"}]}]"#;
        let outs = run(&[("rows.tsv", content.into_bytes())], profile);
        assert_no_leak("tsv", &outs);
        assert_kept(
            "tsv",
            &outs,
            "rows-sanitized.tsv",
            &["name\tsecret", "Alice\t"],
        );
    }
}

// ---------------------------------------------------------------------------
// EOF / line-ending sweep: every format must redact a matched secret and keep
// non-secret content regardless of LF / CRLF / missing trailing newline.
// ---------------------------------------------------------------------------

/// (filename, body-with-`{S}`-and-`{NL}`-placeholders, profile, keep-fragment).
/// `{S}` is replaced by the encoded secret, `{NL}` by the line ending.
struct EofCase {
    file: &'static str,
    body: &'static str,
    profile: &'static str,
    enc: fn(&str) -> String,
    keep: &'static str,
}

#[test]
fn eof_and_line_endings_per_format() {
    let secret = format!("{M_SPEC}-eof\"v\\x/y");
    let cases = [
        EofCase {
            file: "a.toml",
            body: "[s]{NL}secret = {S}{NL}keep = \"EOFKEEP\"",
            profile: r#"[{"processor":"toml","extensions":[".toml"],"fields":[{"pattern":"s.secret","category":"auth_token"}]}]"#,
            enc: e_toml,
            keep: "EOFKEEP",
        },
        EofCase {
            file: "a.json",
            body: "{\"secret\":{S},\"keep\":\"EOFKEEP\"}",
            profile: r#"[{"processor":"json","extensions":[".json"],"fields":[{"pattern":"secret","category":"auth_token"}]}]"#,
            enc: e_json,
            keep: "EOFKEEP",
        },
        EofCase {
            file: "a.jsonl",
            body: "{\"secret\":{S}}{NL}{\"keep\":\"EOFKEEP\"}",
            profile: r#"[{"processor":"jsonl","extensions":[".jsonl"],"options":{"skip_invalid":"true"},"fields":[{"pattern":"secret","category":"auth_token"}]}]"#,
            enc: e_json,
            keep: "EOFKEEP",
        },
        EofCase {
            file: "a.yaml",
            body: "s:{NL}  secret: {S}{NL}  keep: EOFKEEP",
            profile: r#"[{"processor":"yaml","extensions":[".yaml"],"fields":[{"pattern":"s.secret","category":"auth_token"}]}]"#,
            enc: e_yaml,
            keep: "EOFKEEP",
        },
        EofCase {
            file: "a.xml",
            body: "<r><s>{S}</s><keep>EOFKEEP</keep></r>",
            profile: r#"[{"processor":"xml","extensions":[".xml"],"fields":[{"pattern":"r/s","category":"auth_token"}]}]"#,
            enc: e_xml_text,
            keep: "EOFKEEP",
        },
        EofCase {
            file: "a.csv",
            body: "secret,keep{NL}{S},EOFKEEP",
            profile: r#"[{"processor":"csv","extensions":[".csv"],"fields":[{"pattern":"secret","category":"auth_token"}]}]"#,
            enc: e_csv,
            keep: "EOFKEEP",
        },
    ];

    for c in &cases {
        for (variant, nl, trailing) in [
            ("LF", "\n", "\n"),
            ("CRLF", "\r\n", "\r\n"),
            ("no-eol", "\n", ""),
        ] {
            let body = c.body.replace("{S}", &(c.enc)(&secret)).replace("{NL}", nl);
            let content = format!("{body}{trailing}");
            let outs = run(&[(c.file, content.into_bytes())], c.profile);
            let label = format!("{}/{variant}", c.file);
            assert_no_leak(&label, &outs);
            assert_kept(&label, &outs, &sanitized_name(c.file), &[c.keep]);
        }
    }
}
