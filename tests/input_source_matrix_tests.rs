//! Input-source matrix: the **core rule** is that a secret value must NEVER
//! leak — not in output, not in stdout, not in stderr/logs, anywhere — across
//! every combination of input sources (stdin / file / archive and their mixes),
//! including archives nested inside archives, a file for every processor type,
//! values that span multiple sources, special characters, escaped values, and
//! multi-byte UTF-8 / Unicode.
//!
//! These tests make **no assumptions about the output shape**: they read the
//! actual bytes of every produced artifact — every output file and every entry
//! inside every output archive, recursing into nested archives — plus the
//! captured stdout and stderr, and assert that no canary marker survives.

#![cfg(all(feature = "archive", feature = "structured"))]

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::tempdir;

// Each canary carries a special-char-free MARKER substring, so a leak in ANY
// escaping (JSON `\"`, CSV `""`, XML `&quot;`, …) is caught by one substring
// check. The values mix specials (`"` `\` `/` `,` `'`) and, for `b`, multi-byte
// UTF-8 (accented / emoji / Greek).
const MARKERS: [&str; 3] = ["CANARYAaa", "CANARYBbb", "CANARYCcc"];
fn canaries() -> [String; 3] {
    [
        "CANARYAaa-x\"y\\z/w,v'u".to_string(),
        "CANARYBbb-café\"☃/λ\\x,β'γ-Ünïcödé".to_string(),
        "CANARYCcc-span-2468-token".to_string(),
    ]
}

// ---- per-format string-literal encoders (embed value `v` as a scalar) ----
fn e_json(v: &str) -> String {
    serde_json::to_string(v).unwrap()
}
fn e_toml(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
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

/// Build a file for processor `proc`, embedding all three canaries in matched
/// fields plus a non-secret KEEP value (so we also see format is preserved).
/// One file exercises one processor type.
fn gen_file(proc: &str) -> (String, Vec<u8>) {
    let [a, b, c] = canaries();
    let body = match proc {
        "json" => format!(
            r#"{{"s1":{},"s2":{},"s3":{},"keep":"KEEPME"}}"#,
            e_json(&a),
            e_json(&b),
            e_json(&c)
        ),
        "jsonl" => format!(
            "{{\"s1\":{}}}\n{{\"s2\":{}}}\n{{\"s3\":{}}}\nplain non-json keepline\n",
            e_json(&a),
            e_json(&b),
            e_json(&c)
        ),
        "yaml" => format!(
            "# yaml comment\ns1: {}\ns2: {}\ns3: {}\nkeep: KEEPME\n",
            e_json(&a),
            e_json(&b),
            e_json(&c)
        ),
        "toml" => format!(
            "# toml comment\ns1 = {}\ns2 = {}\ns3 = {}\nkeep = \"KEEPME\"\n",
            e_toml(&a),
            e_toml(&b),
            e_toml(&c)
        ),
        "xml" => format!(
            "<!-- xml --><r><s1>{}</s1><s2>{}</s2><s3>{}</s3><keep>KEEPME</keep></r>",
            e_xml_text(&a),
            e_xml_text(&b),
            e_xml_text(&c)
        ),
        "csv" => format!(
            "s1,s2,s3,keep\n{},{},{},KEEPME\n",
            e_csv(&a),
            e_csv(&b),
            e_csv(&c)
        ),
        "ini" => format!("; ini comment\n[s]\ns1 = {a}\ns2 = {b}\ns3 = {c}\nkeep = KEEPME\n"),
        "env" => format!("S1={a}\nS2={b}\nS3={c}\nKEEP=KEEPME\n"),
        "conf" => format!("# key-value\ns1 = '{a}'\ns2 = '{b}'\ns3 = '{c}'\nkeep = 'KEEPME'\n"),
        other => panic!("unknown processor {other}"),
    };
    (format!("{proc}_file.{proc}"), body.into_bytes())
}

/// All processor file types in one set (used to fill files & archives).
const PROCS: [&str; 9] = [
    "json", "jsonl", "yaml", "toml", "xml", "csv", "ini", "env", "conf",
];

fn all_proc_files() -> Vec<(String, Vec<u8>)> {
    PROCS.iter().map(|p| gen_file(p)).collect()
}

/// The profile matching `s1/s2/s3` (and section/keys) for every processor.
fn profile_json() -> String {
    let mut entries: Vec<String> = Vec::new();
    let span = |proc: &str, ext: &str, pats: &[&str]| {
        let fields: Vec<String> = pats
            .iter()
            .map(|p| format!(r#"{{"pattern":"{p}","category":"auth_token"}}"#))
            .collect();
        format!(
            r#"{{"processor":"{proc}","extensions":[".{ext}"],"fields":[{}]}}"#,
            fields.join(",")
        )
    };
    entries.push(span("json", "json", &["s1", "s2", "s3"]));
    entries.push(
        r#"{"processor":"jsonl","extensions":[".jsonl"],"options":{"skip_invalid":"true"},"fields":[{"pattern":"s1","category":"auth_token"},{"pattern":"s2","category":"auth_token"},{"pattern":"s3","category":"auth_token"}]}"#
            .to_string(),
    );
    entries.push(span("yaml", "yaml", &["s1", "s2", "s3"]));
    entries.push(span("toml", "toml", &["s1", "s2", "s3"]));
    entries.push(span("xml", "xml", &["r/s1", "r/s2", "r/s3"]));
    entries.push(span("csv", "csv", &["s1", "s2", "s3"]));
    entries.push(span("ini", "ini", &["s.s1", "s.s2", "s.s3"]));
    entries.push(span("env", "env", &["S1", "S2", "S3"]));
    // `.conf` files are handled by the `key-value` processor.
    entries.push(span("key-value", "conf", &["s1", "s2", "s3"]));
    format!("[{}]", entries.join(","))
}

// ---------------------------------------------------------------------------
// Archive builders
// ---------------------------------------------------------------------------

fn zip_bytes(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            w.start_file(name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    buf
}

fn targz_bytes(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::fast());
        let mut b = tar::Builder::new(enc);
        for (name, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(1_700_000_000);
            h.set_cksum();
            b.append_data(&mut h, name, data.as_slice()).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap();
    }
    buf
}

// ---------------------------------------------------------------------------
// Recursive output collection — read the ACTUAL bytes of every artifact,
// recursing into archives (incl. nested archives).
// ---------------------------------------------------------------------------

fn collect_bytes(name: &str, data: &[u8], sink: &mut Vec<u8>) {
    let lname = name.to_ascii_lowercase();
    if lname.ends_with(".zip") {
        if let Ok(mut z) = zip::ZipArchive::new(Cursor::new(data)) {
            for i in 0..z.len() {
                let mut f = z.by_index(i).unwrap();
                let entry = f.name().to_string();
                let mut v = Vec::new();
                f.read_to_end(&mut v).unwrap();
                collect_bytes(&entry, &v, sink);
            }
            return;
        }
    } else if lname.ends_with(".tar.gz") || lname.ends_with(".tgz") {
        let dec = flate2::read::GzDecoder::new(data);
        let mut ar = tar::Archive::new(dec);
        if let Ok(entries) = ar.entries() {
            for e in entries.flatten() {
                let mut e = e;
                let entry = e.path().unwrap().to_string_lossy().into_owned();
                let mut v = Vec::new();
                e.read_to_end(&mut v).unwrap();
                collect_bytes(&entry, &v, sink);
            }
            return;
        }
    } else if lname.ends_with(".tar") {
        let mut ar = tar::Archive::new(data);
        if let Ok(entries) = ar.entries() {
            for e in entries.flatten() {
                let mut e = e;
                let entry = e.path().unwrap().to_string_lossy().into_owned();
                let mut v = Vec::new();
                e.read_to_end(&mut v).unwrap();
                collect_bytes(&entry, &v, sink);
            }
            return;
        }
    }
    // Leaf (non-archive): record the raw bytes.
    sink.extend_from_slice(data);
    sink.push(b'\n');
}

/// Walk a directory recursively, collecting all leaf bytes (recursing into any
/// archive files).
fn collect_dir(dir: &Path, sink: &mut Vec<u8>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_dir(&p, sink);
        } else {
            let data = fs::read(&p).unwrap();
            collect_bytes(&p.file_name().unwrap().to_string_lossy(), &data, sink);
        }
    }
}

/// One input source for a run.
enum Src {
    /// A plain file written into the input dir.
    File(String, Vec<u8>),
    /// An archive (built from entries) written into the input dir.
    Archive(String, Vec<u8>),
}

/// Run the binary with the given file/archive inputs (+ optional stdin of a
/// single `--format`), then assert NO canary marker survives in any output
/// artifact (recursively, incl. nested archives), stdout, or stderr.
fn run_no_leak(label: &str, sources: Vec<Src>, stdin: Option<(&str, Vec<u8>)>) {
    let dir = tempdir().unwrap();
    let indir = dir.path().join("in");
    let outdir = dir.path().join("out");
    fs::create_dir_all(&indir).unwrap();
    fs::create_dir_all(&outdir).unwrap();

    let mut args: Vec<String> = Vec::new();
    let mut markers_in_input = false;
    for s in &sources {
        let (name, data) = match s {
            Src::File(n, d) | Src::Archive(n, d) => (n, d),
        };
        let p = indir.join(name);
        fs::write(&p, data).unwrap();
        args.push(p.to_str().unwrap().to_string());
        // Files embed markers in plain bytes; archives embed them compressed.
        // Either way every input we build carries markers by construction.
        markers_in_input = true;
    }

    let secrets = dir.path().join("secrets.json");
    // Backstop: the raw canary values as literals (catches raw occurrences in
    // comments / plaintext / non-matched keys). Escaped occurrences still rely
    // on the structured editor + aliases, so escaped leaks are still caught by
    // the marker check.
    let secret_list: Vec<String> = canaries()
        .iter()
        .map(|c| {
            format!(
                r#"{{"pattern":{},"kind":"literal","category":"auth_token"}}"#,
                e_json(c)
            )
        })
        .collect();
    fs::write(&secrets, format!("[{}]", secret_list.join(","))).unwrap();
    let prof = dir.path().join("profile.json");
    fs::write(&prof, profile_json()).unwrap();

    if let Some((fmt, _)) = &stdin {
        args.push("-".into());
        args.push("--format".into());
        args.push((*fmt).to_string());
    }
    args.extend([
        "-s".into(),
        secrets.to_str().unwrap().into(),
        "--profile".into(),
        prof.to_str().unwrap().into(),
    ]);
    // `--output <dir>` is for file/archive inputs (multi-input). For stdin-only
    // there are no file inputs, so the sanitized stream goes to stdout (which we
    // capture and leak-check below); passing a directory there would error.
    let has_file_inputs = !sources.is_empty();
    if has_file_inputs {
        args.push("--output".into());
        args.push(outdir.to_str().unwrap().into());
    }

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sanitize"));
    cmd.args(&args)
        .env("SANITIZE_LOG", "debug") // verbose: maximize chance of a log leak surfacing
        .env("SANITIZE_NO_SETTINGS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    {
        let mut si = child.stdin.take().unwrap();
        if let Some((_, data)) = &stdin {
            si.write_all(data).unwrap();
            if MARKERS
                .iter()
                .any(|m| String::from_utf8_lossy(data).contains(m))
            {
                markers_in_input = true;
            }
        }
    }
    let out = child.wait_with_output().unwrap();

    assert!(
        markers_in_input,
        "[{label}] test bug: no markers in any input"
    );
    assert!(
        out.status.success(),
        "[{label}] exited non-zero; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Collect every output artifact (recursively, incl. nested archives).
    let mut collected: Vec<u8> = Vec::new();
    collect_dir(&outdir, &mut collected);
    // stdin output may go to stdout — include it. And the core rule covers
    // stderr/logs, so include both.
    collected.extend_from_slice(&out.stdout);
    collected.push(b'\n');
    collected.extend_from_slice(&out.stderr);

    let hay = String::from_utf8_lossy(&collected);
    for m in MARKERS {
        assert!(
            !hay.contains(m),
            "[{label}] LEAK: marker {m} survived in output/stdout/stderr"
        );
    }
    // Sanity: redaction actually happened (token marker present somewhere).
    assert!(
        hay.contains("__SANITIZED_") || hay.contains("KEEPME"),
        "[{label}] produced no recognizable sanitized output"
    );
}

// Convenience builders.
fn file(proc: &str) -> Src {
    let (n, d) = gen_file(proc);
    Src::File(n, d)
}
fn archive_zip(name: &str) -> Src {
    Src::Archive(name.to_string(), zip_bytes(&all_proc_files()))
}
fn archive_targz(name: &str) -> Src {
    Src::Archive(name.to_string(), targz_bytes(&all_proc_files()))
}
/// A zip containing a tar.gz that contains all processor files (archive-in-archive).
fn nested_archive(name: &str) -> Src {
    let inner = targz_bytes(&all_proc_files());
    let entries = vec![("inner_bundle.tar.gz".to_string(), inner)];
    Src::Archive(name.to_string(), zip_bytes(&entries))
}
fn stdin_json() -> (&'static str, Vec<u8>) {
    let (_, d) = gen_file("json");
    ("json", d)
}

// ---------------------------------------------------------------------------
// The input-source matrix.
// ---------------------------------------------------------------------------

#[test]
fn src_stdin_only() {
    run_no_leak("stdin", vec![], Some(stdin_json()));
}

#[test]
fn src_file_only() {
    run_no_leak("file", vec![file("json")], None);
}

#[test]
fn src_archive_only() {
    run_no_leak("archive", vec![archive_zip("bundle.zip")], None);
}

#[test]
fn src_stdin_plus_file() {
    run_no_leak("stdin+file", vec![file("yaml")], Some(stdin_json()));
}

#[test]
fn src_stdin_plus_archive() {
    run_no_leak(
        "stdin+archive",
        vec![archive_targz("bundle.tar.gz")],
        Some(stdin_json()),
    );
}

#[test]
fn src_stdin_plus_file_plus_archive() {
    run_no_leak(
        "stdin+file+archive",
        vec![file("xml"), archive_zip("bundle.zip")],
        Some(stdin_json()),
    );
}

#[test]
fn src_stdin_plus_file_plus_file() {
    run_no_leak(
        "stdin+file+file",
        vec![file("toml"), file("csv")],
        Some(stdin_json()),
    );
}

#[test]
fn src_stdin_plus_file_plus_archive_plus_archive() {
    run_no_leak(
        "stdin+file+archive+archive",
        vec![file("ini"), archive_zip("a.zip"), archive_targz("b.tar.gz")],
        Some(stdin_json()),
    );
}

#[test]
fn src_file_plus_file() {
    run_no_leak("file+file", vec![file("json"), file("yaml")], None);
}

#[test]
fn src_archive_plus_archive() {
    run_no_leak(
        "archive+archive",
        vec![archive_zip("a.zip"), archive_targz("b.tar.gz")],
        None,
    );
}

#[test]
fn src_nested_archive() {
    run_no_leak("nested-archive", vec![nested_archive("outer.zip")], None);
}

#[test]
fn src_everything_all_processors_all_sources() {
    // The richest case: stdin + two files + two archives + a nested archive,
    // every processor type represented, canaries spanning all of them.
    run_no_leak(
        "everything",
        vec![
            file("env"),
            file("conf"),
            archive_zip("z.zip"),
            archive_targz("t.tar.gz"),
            nested_archive("nested.zip"),
        ],
        Some(stdin_json()),
    );
}
