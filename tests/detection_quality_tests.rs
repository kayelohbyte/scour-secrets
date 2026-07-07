//! Detection-quality corpus tests.
//!
//! `tests/detection_corpus/*.yaml` hold per-pattern positive samples
//! (synthetic, format-valid secrets embedded in realistic log/config lines)
//! and hard-negative lookalikes. The contract for the built-in balanced
//! pattern set:
//!
//! - **Recall 1.0 on positives** — every corpus secret must be absent from
//!   zero-config sanitized output. A missed positive is a CI failure, so
//!   pattern edits cannot silently regress detection.
//! - **Precision floor on negatives** — every negative line must pass
//!   through byte-identical. A matched negative is a CI failure.
//! - **Chunk-boundary stability** — positives are re-run padded across
//!   scanner chunk boundaries (the leak-matrix technique) so boundary
//!   regressions surface here too.
//!
//! `docs/detection-quality.md` is generated from the corpus; the
//! `scorecard_is_current` test keeps the committed file honest. Regenerate
//! with: `cargo test --test detection_quality_tests regenerate_scorecard -- --ignored`

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct CorpusFile {
    #[serde(default)]
    cases: Vec<Case>,
    #[serde(default)]
    negatives: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    /// Context line with `{{SECRET}}` where the secret goes.
    text: String,
    /// The secret, stored with `~|~` split markers so the committed corpus
    /// never contains a contiguous scannable token — GitHub push protection
    /// (and any downstream secret scanner run against a checkout) would
    /// otherwise flag the synthetic keys.
    secret: String,
}

impl Case {
    /// Reassembled secret (split markers removed).
    fn secret(&self) -> String {
        self.secret.replace("~|~", "")
    }

    /// Context line with the reassembled secret spliced in.
    fn text(&self) -> String {
        self.text.replace("{{SECRET}}", &self.secret())
    }
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/detection_corpus")
}

/// Load every corpus file, sorted by file name for stable ordering.
fn load_corpus() -> Vec<(String, CorpusFile)> {
    let mut files: Vec<PathBuf> = fs::read_dir(corpus_dir())
        .expect("corpus dir must exist")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "detection corpus is empty");
    files
        .into_iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            let raw = fs::read_to_string(&p).unwrap();
            let parsed: CorpusFile = serde_yaml_ng::from_str(&raw)
                .unwrap_or_else(|e| panic!("corpus file {} is invalid: {e}", p.display()));
            (name, parsed)
        })
        .collect()
}

/// Run the zero-config scan (built-in balanced patterns, isolated config dir)
/// over `input` and return sanitized stdout.
fn run_default_scan(input: &str, extra_args: &[&str]) -> String {
    let dir = tempdir().unwrap();
    let config_home = dir.path().join("config");
    fs::create_dir_all(&config_home).unwrap();
    let input_path = dir.path().join("input.log");
    fs::write(&input_path, input).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args([input_path.to_str().unwrap(), "-o", "-"])
        .args(extra_args)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("APPDATA", &config_home)
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_NO_SETTINGS", "1")
        .env("SCOUR_NO_CONFIG", "1")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn corpus_positives_detected_by_default_patterns() {
    let mut missed: Vec<String> = Vec::new();
    for (file, corpus) in load_corpus() {
        if corpus.cases.is_empty() {
            continue;
        }
        let input: String = corpus
            .cases
            .iter()
            .map(Case::text)
            .collect::<Vec<_>>()
            .join("\n");
        let output = run_default_scan(&input, &[]);
        // Non-vacuous: output must exist and must differ from the input
        // (every corpus file contains at least one detectable secret).
        assert!(
            !output.is_empty() && output != input,
            "{file}: sanitized output identical to input — scan did not run?"
        );
        for case in &corpus.cases {
            if output.contains(&case.secret()) {
                missed.push(format!("{file}::{} — secret leaked", case.label));
            }
        }
    }
    assert!(
        missed.is_empty(),
        "recall regression — {} positive(s) not detected:\n  {}",
        missed.len(),
        missed.join("\n  ")
    );
}

#[test]
fn corpus_negatives_pass_through_unchanged() {
    let mut mangled: Vec<String> = Vec::new();
    for (file, corpus) in load_corpus() {
        if corpus.negatives.is_empty() {
            continue;
        }
        let input = corpus.negatives.join("\n");
        let output = run_default_scan(&input, &[]);
        for neg in &corpus.negatives {
            if !output.contains(neg.as_str()) {
                mangled.push(format!("{file} — false positive on: {neg}"));
            }
        }
    }
    assert!(
        mangled.is_empty(),
        "precision regression — {} negative(s) modified:\n  {}",
        mangled.len(),
        mangled.join("\n  ")
    );
}

/// Chunk-boundary stability: pad heavily between cases so secrets land near
/// scanner window edges with a small chunk size, then assert none leak.
#[test]
fn corpus_positives_detected_across_chunk_boundaries() {
    let filler = "lorem ipsum dolor sit amet consectetur adipiscing elit \n".repeat(90);
    let mut missed: Vec<String> = Vec::new();
    for (file, corpus) in load_corpus() {
        if corpus.cases.is_empty() {
            continue;
        }
        let mut input = String::new();
        for case in &corpus.cases {
            input.push_str(&filler);
            input.push_str(&case.text());
            input.push('\n');
        }
        // 8 KiB chunks (must exceed the 4 KiB overlap); filler is ~5 KiB per
        // case so successive secrets straddle successive chunk boundaries.
        let output = run_default_scan(&input, &["--chunk-size", "8192"]);
        for case in &corpus.cases {
            if output.contains(&case.secret()) {
                missed.push(format!("{file}::{} — leaked across chunk", case.label));
            }
        }
    }
    assert!(
        missed.is_empty(),
        "chunk-boundary regression:\n  {}",
        missed.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Scorecard generation + freshness
// ---------------------------------------------------------------------------

fn render_scorecard() -> String {
    let corpus = load_corpus();
    let mut out = String::from(
        "# Detection Quality Scorecard\n\n\
         Generated from [`tests/detection_corpus/`](../tests/detection_corpus/) by\n\
         `cargo test --test detection_quality_tests regenerate_scorecard -- --ignored`.\n\
         Do not edit by hand — CI fails if this file is stale.\n\n\
         **Contract:** every positive below is detected by the zero-config built-in\n\
         pattern set (recall 1.0 on the corpus), every negative passes through\n\
         unchanged, and positives survive chunk-boundary padding. Corpus cases are\n\
         synthetic but format-valid; shapes adapted from public gitleaks/trufflehog\n\
         rule tests (MIT) and provider format documentation.\n\n\
         | Corpus file | Pattern | Positives |\n\
         |-------------|---------|-----------|\n",
    );
    let mut total_pos = 0usize;
    let mut total_neg = 0usize;
    for (file, corpus_file) in &corpus {
        total_neg += corpus_file.negatives.len();
        let mut labels: Vec<&str> = corpus_file.cases.iter().map(|c| c.label.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        for label in labels {
            let n = corpus_file
                .cases
                .iter()
                .filter(|c| c.label == label)
                .count();
            total_pos += n;
            out.push_str(&format!("| {file} | `{label}` | {n} |\n"));
        }
    }
    out.push_str(&format!(
        "\n**Totals:** {total_pos} positives across {} corpus files, \
         {total_neg} hard negatives.\n",
        corpus.len()
    ));
    out
}

fn scorecard_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/detection-quality.md")
}

#[test]
fn scorecard_is_current() {
    let expected = render_scorecard();
    let committed = fs::read_to_string(scorecard_path())
        .expect("docs/detection-quality.md missing — run the regenerate_scorecard test")
        .replace("\r\n", "\n");
    assert_eq!(
        committed, expected,
        "docs/detection-quality.md is stale — regenerate with:\n\
         cargo test --test detection_quality_tests regenerate_scorecard -- --ignored"
    );
}

#[test]
#[ignore = "writes docs/detection-quality.md; run explicitly to regenerate"]
fn regenerate_scorecard() {
    fs::write(scorecard_path(), render_scorecard()).unwrap();
}
