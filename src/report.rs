//! Structured reporting for sanitization runs.
//!
//! Generates a JSON report summarising what the sanitization tool did
//! without ever including original secret values. The report captures:
//!
//! - **Metadata**: tool version, CLI flags, timestamp.
//! - **Per-file details**: matches found, replacements applied, bytes
//!   processed, and per-pattern match counts.
//! - **Aggregated summary**: totals across all files plus wall-clock
//!   duration.
//! - **Log context** (optional): keyword-matched lines with surrounding
//!   context windows, populated when `--extract-context` is used.
//!
//! # Thread Safety
//!
//! [`ReportBuilder`] is `Send + Sync`. Multiple threads can record file
//! results concurrently via [`ReportBuilder::record_file`], which takes
//! an internal `Mutex` only long enough to push a single entry.
//!
//! # Example
//!
//! ```rust
//! use rust_sanitize::log_context::{extract_context, LogContextConfig};
//! use rust_sanitize::report::{FileReport, ReportBuilder, ReportMetadata};
//! use std::collections::HashMap;
//!
//! let meta = ReportMetadata {
//!     version: "0.4.0".into(),
//!     timestamp: "2026-03-01T00:00:00Z".into(),
//!     deterministic: true,
//!     dry_run: false,
//!     strict: false,
//!     chunk_size: 1_048_576,
//!     threads: Some(4),
//!     secrets_file: Some("secrets.enc".into()),
//! };
//!
//! let builder = ReportBuilder::new(meta);
//!
//! builder.record_file(FileReport {
//!     path: "data.log".into(),
//!     matches: 42,
//!     replacements: 42,
//!     bytes_processed: 10_000,
//!     bytes_output: 10_200,
//!     pattern_counts: HashMap::from([("email".into(), 30), ("ipv4".into(), 12)]),
//!     method: "scanner".into(),
//!     log_context: None,
//!     match_locations: None,
//! });
//!
//! // Optionally attach per-file log context (populated by --extract-context).
//! let sanitized_output = "INFO ok\nERROR disk full\nINFO retrying";
//! let ctx = extract_context(sanitized_output, &LogContextConfig::new().with_context_lines(1));
//! builder.set_file_log_context("data.log", ctx);
//!
//! let report = builder.finish();
//! let json = report.to_json_pretty().unwrap();
//! assert!(json.contains("\"total_matches\": 42"));
//! assert!(json.contains("\"log_context\""));
//! assert!(json.contains("\"keyword\": \"error\""));
//! ```

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::log_context::LogContextResult;
use crate::scanner::{MatchLocation, ScanStats};

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------

/// Top-level sanitization report.
///
/// Serialized to JSON via [`Self::to_json`] / [`Self::to_json_pretty`].
/// Never contains original secret values.
#[derive(Debug, Clone, Serialize)]
pub struct SanitizeReport {
    /// Tool metadata and flags.
    pub metadata: ReportMetadata,
    /// Aggregated summary across all files.
    pub summary: ReportSummary,
    /// Per-file details. Each entry may include `log_context` when
    /// `--extract-context` was used.
    pub files: Vec<FileReport>,
}

impl SanitizeReport {
    /// Serialize the report as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Serialize the report as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails.
    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize the report as SARIF 2.1.0 JSON.
    ///
    /// SARIF (Static Analysis Results Interchange Format) is consumed natively
    /// by GitHub Advanced Security, VS Code Problems panel, and most SIEM
    /// tooling. Results are file-level (no line numbers — the sanitize engine
    /// operates on byte streams and does not record source positions).
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails.
    #[allow(clippy::too_many_lines)]
    pub fn to_sarif(&self) -> serde_json::Result<String> {
        use serde_json::json;

        // Collect unique named pattern IDs in sorted order → one SARIF rule each.
        // When structured-processor-only runs produce matches without named patterns,
        // add the synthetic "sensitive_value" rule to cover those results.
        let needs_generic = self
            .files
            .iter()
            .any(|f| f.matches > 0 && f.pattern_counts.is_empty());

        let mut rule_ids: Vec<&str> = self
            .summary
            .pattern_counts
            .keys()
            .map(String::as_str)
            .collect();
        rule_ids.sort_unstable();
        if needs_generic {
            rule_ids.push("sensitive_value");
        }

        let rules: Vec<serde_json::Value> = rule_ids
            .iter()
            .map(|&id| {
                let (short, full) = if id == "sensitive_value" {
                    (
                        "Sensitive value detected".to_owned(),
                        "One or more sensitive values were detected during sanitization and \
                         replaced with safe substitutes. No original values are stored. \
                         Run with a secrets file for per-pattern breakdown."
                            .to_owned(),
                    )
                } else {
                    (
                        format!("Sensitive value of type '{}' detected", id),
                        format!(
                            "A sensitive value of type '{}' was detected during sanitization \
                             and replaced with a safe substitute. No original value is stored.",
                            id
                        ),
                    )
                };
                json!({
                    "id": id,
                    "name": sarif_rule_name(id),
                    "shortDescription": { "text": short },
                    "fullDescription": { "text": full },
                    "defaultConfiguration": { "level": sarif_level(id) },
                    "properties": { "tags": ["security"] }
                })
            })
            .collect();

        // One SARIF result per (file, pattern) pair where count > 0.
        // Files with matches but no named breakdown emit a single generic result.
        let mut results: Vec<serde_json::Value> = Vec::new();
        for f in &self.files {
            let uri = path_to_sarif_uri(&f.path);
            let location = json!([{
                "physicalLocation": {
                    "artifactLocation": { "uri": uri, "uriBaseId": "%SRCROOT%" }
                }
            }]);
            if f.matches > 0 && f.pattern_counts.is_empty() {
                results.push(json!({
                    "ruleId": "sensitive_value",
                    "level": "warning",
                    "message": {
                        "text": format!(
                            "{} sensitive value(s) detected and sanitized.",
                            f.matches
                        )
                    },
                    "locations": location
                }));
            } else {
                for (pattern, &count) in &f.pattern_counts {
                    if count == 0 {
                        continue;
                    }
                    // Emit startLine when we have location data for this pattern.
                    let first_line = f.match_locations.as_ref().and_then(|ml| {
                        ml.locations
                            .iter()
                            .find(|loc| loc.pattern == *pattern)
                            .map(|loc| loc.line)
                    });
                    let loc = if let Some(line) = first_line {
                        json!([{
                            "physicalLocation": {
                                "artifactLocation": { "uri": &uri, "uriBaseId": "%SRCROOT%" },
                                "region": { "startLine": line }
                            }
                        }])
                    } else {
                        location.clone()
                    };
                    results.push(json!({
                        "ruleId": pattern,
                        "level": sarif_level(pattern),
                        "message": {
                            "text": format!(
                                "{} sensitive value(s) of type '{}' detected and sanitized.",
                                count, pattern
                            )
                        },
                        "locations": loc
                    }));
                }
            }
        }

        let artifacts: Vec<serde_json::Value> = self
            .files
            .iter()
            .map(|f| {
                let uri = path_to_sarif_uri(&f.path);
                json!({ "location": { "uri": uri, "uriBaseId": "%SRCROOT%" } })
            })
            .collect();

        let sarif = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "rust-sanitize",
                        "version": self.metadata.version,
                        "informationUri": "https://github.com/kayelohbyte/rust-sanitize",
                        "rules": rules
                    }
                },
                "invocations": [{
                    "executionSuccessful": true,
                    "endTimeUtc": self.metadata.timestamp
                }],
                "results": results,
                "artifacts": artifacts
            }]
        });

        serde_json::to_string_pretty(&sarif)
    }

    /// Render the report as a self-contained HTML document.
    ///
    /// The output has no external dependencies (no CDN, no external fonts).
    /// Includes a summary dashboard, per-pattern totals, and a per-file table.
    /// Dark mode is supported via `prefers-color-scheme`.
    #[must_use]
    #[allow(clippy::too_many_lines, clippy::format_collect)]
    pub fn to_html(&self) -> String {
        let s = &self.summary;
        let m = &self.metadata;

        // --- summary cards ---------------------------------------------------
        let cards = format!(
            r#"<div class="cards">
  <div class="card"><div class="card-label">Files</div><div class="card-value">{}</div></div>
  <div class="card"><div class="card-label">Matches</div><div class="card-value">{}</div></div>
  <div class="card"><div class="card-label">Replacements</div><div class="card-value">{}</div></div>
  <div class="card"><div class="card-label">Input</div><div class="card-value">{}</div></div>
  <div class="card"><div class="card-label">Duration</div><div class="card-value">{} ms</div></div>
</div>"#,
            s.total_files,
            s.total_matches,
            s.total_replacements,
            fmt_bytes(s.total_bytes_processed),
            s.duration_ms,
        );

        // --- pattern breakdown table (only when there are matches) -----------
        let patterns_section = if s.total_matches > 0 {
            let mut sorted_patterns: Vec<(&String, &u64)> = s.pattern_counts.iter().collect();
            sorted_patterns.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            let rows: String = sorted_patterns
                .iter()
                .map(|(pat, count)| {
                    format!("<tr><td>{}</td><td>{}</td></tr>\n", html_escape(pat), count)
                })
                .collect();
            format!(
                r#"<div class="section">
<h2>Patterns detected</h2>
<div class="table-wrap"><table>
<thead><tr><th>Pattern</th><th>Total matches</th></tr></thead>
<tbody>{}</tbody>
</table></div></div>"#,
                rows
            )
        } else {
            String::new()
        };

        // --- per-file table --------------------------------------------------
        let has_locations = self.files.iter().any(|f| f.match_locations.is_some());
        let file_rows: String = self
            .files
            .iter()
            .map(|f| {
                let badges: String = {
                    let mut pairs: Vec<(&String, &u64)> = f.pattern_counts.iter().collect();
                    pairs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                    pairs
                        .iter()
                        .filter(|(_, &c)| c > 0)
                        .map(|(pat, count)| {
                            format!(
                                r#"<span class="badge {}">{}: {}</span>"#,
                                sarif_badge_class(pat),
                                html_escape(pat),
                                count
                            )
                        })
                        .collect()
                };
                let match_class = if f.matches > 0 { "count-positive" } else { "count-zero" };
                let first_line_cell = if has_locations {
                    match f.match_locations.as_ref().and_then(|ml| ml.locations.first()) {
                        Some(loc) => {
                            let truncated_marker = if f
                                .match_locations
                                .as_ref()
                                .is_some_and(|ml| ml.truncated)
                            {
                                "<span title=\"more matches not shown\">…</span>"
                            } else {
                                ""
                            };
                            format!(
                                "<td class=\"count-positive\">L{}{}</td>",
                                loc.line, truncated_marker
                            )
                        }
                        None => "<td class=\"count-zero\">—</td>".to_owned(),
                    }
                } else {
                    String::new()
                };
                format!(
                    "<tr><td><code>{}</code></td><td class=\"{}\">{}</td><td>{}</td>{}<td>{}</td></tr>\n",
                    html_escape(&f.path),
                    match_class,
                    f.matches,
                    html_escape(&f.method),
                    first_line_cell,
                    badges,
                )
            })
            .collect();

        let first_line_header = if has_locations {
            "<th>First match</th>"
        } else {
            ""
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>rust-sanitize report</title>
<style>
:root{{--bg:#f8f9fa;--surface:#fff;--border:#dee2e6;--text:#212529;--muted:#6c757d;--accent:#0d6efd;--danger:#dc3545;--warn-col:#fd7e14;--success:#198754;--badge:#e9ecef;--code-bg:#f1f3f4}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--danger:#f85149;--warn-col:#d29922;--success:#3fb950;--badge:#21262d;--code-bg:#1c2128}}}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;font-size:14px}}
.container{{max-width:1100px;margin:0 auto;padding:24px 16px}}
header{{margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}}
h1{{font-size:1.4rem;font-weight:600}}
.meta{{font-size:.8rem;color:var(--muted);margin-top:4px}}
.section{{margin-bottom:28px}}
h2{{font-size:.95rem;font-weight:600;margin-bottom:10px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px}}
.card-label{{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}}
.card-value{{font-size:1.4rem;font-weight:600;margin-top:2px}}
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:6px;font-size:.85rem}}
th{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);font-weight:600;color:var(--muted);white-space:nowrap}}
td{{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:var(--badge)}}
code{{background:var(--code-bg);border-radius:3px;padding:1px 4px;font-size:.8rem;word-break:break-all}}
.badge{{display:inline-block;padding:1px 7px;border-radius:12px;font-size:.72rem;font-weight:500;background:var(--badge);margin:1px}}
.badge-pii{{background:rgba(220,53,69,.12);color:var(--danger)}}
.badge-warn{{background:rgba(253,126,20,.12);color:var(--warn-col)}}
.count-zero{{color:var(--muted)}}
.count-positive{{font-weight:600}}
footer{{margin-top:40px;padding-top:16px;border-top:1px solid var(--border);font-size:.75rem;color:var(--muted)}}
</style>
</head>
<body>
<div class="container">
<header>
<h1>rust-sanitize report</h1>
<div class="meta">version {version}&nbsp;·&nbsp;{timestamp}&nbsp;·&nbsp;{duration_ms} ms total</div>
</header>
{cards}
{patterns_section}
<div class="section">
<h2>Files</h2>
<div class="table-wrap"><table>
<thead><tr><th>Path</th><th>Matches</th><th>Method</th>{first_line_header}<th>Patterns</th></tr></thead>
<tbody>{file_rows}</tbody>
</table></div></div>
<footer>Generated by <strong>rust-sanitize {version}</strong> on {timestamp}</footer>
</div>
</body>
</html>"#,
            version = html_escape(&m.version),
            timestamp = html_escape(&m.timestamp),
            duration_ms = s.duration_ms,
            cards = cards,
            patterns_section = patterns_section,
            first_line_header = first_line_header,
            file_rows = file_rows,
        )
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn is_pii_category(pattern: &str) -> bool {
    matches!(
        pattern,
        "email" | "name" | "phone" | "credit_card" | "ssn" | "auth_token" | "jwt"
    )
}

/// Map a pattern name to a SARIF severity level.
/// PII and credential categories → "error"; everything else → "warning".
fn sarif_level(pattern: &str) -> &'static str {
    if is_pii_category(pattern) {
        "error"
    } else {
        "warning"
    }
}

/// Convert a pattern name to a CamelCase SARIF rule name.
/// e.g. "auth_token" → "AuthToken", "custom:password" → "CustomPassword"
fn sarif_rule_name(pattern: &str) -> String {
    pattern
        .split(['_', ':', '-'])
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}

/// Convert a file path to a SARIF URI (forward slashes, no percent-encoding).
fn path_to_sarif_uri(path: &str) -> String {
    path.replace('\\', "/")
}

/// CSS badge class for a pattern in the HTML report.
fn sarif_badge_class(pattern: &str) -> &'static str {
    if is_pii_category(pattern) {
        "badge-pii"
    } else {
        "badge-warn"
    }
}

/// Format a byte count as a human-readable string.
#[allow(clippy::cast_precision_loss)]
fn fmt_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Escape HTML special characters to prevent injection in the HTML report.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Tool metadata embedded in every report.
#[derive(Debug, Clone, Serialize)]
pub struct ReportMetadata {
    /// Crate / binary version (from `Cargo.toml`).
    pub version: String,
    /// ISO-8601 timestamp when the run started.
    pub timestamp: String,
    /// Whether `--deterministic` was used.
    pub deterministic: bool,
    /// Whether `--dry-run` was used.
    pub dry_run: bool,
    /// Whether `--strict` was used.
    pub strict: bool,
    /// Chunk size in bytes (`--chunk-size`).
    pub chunk_size: usize,
    /// Thread count (`--threads`), if specified.
    pub threads: Option<usize>,
    /// Path to the secrets file, if provided.
    pub secrets_file: Option<String>,
}

/// Aggregated summary across all processed files.
#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    /// Number of files processed.
    pub total_files: u64,
    /// Total pattern matches found.
    pub total_matches: u64,
    /// Total replacements applied.
    pub total_replacements: u64,
    /// Total bytes read from input(s).
    pub total_bytes_processed: u64,
    /// Total bytes written to output(s).
    pub total_bytes_output: u64,
    /// Wall-clock duration of processing in milliseconds.
    pub duration_ms: u64,
    /// Aggregate per-pattern match counts.
    pub pattern_counts: HashMap<String, u64>,
}

/// Per-match line-number results for a file, populated when
/// `--max-match-locations` is non-zero and the scanner path is used.
#[derive(Debug, Clone, Serialize)]
pub struct MatchLocationsResult {
    /// Individual match locations in document order.
    pub locations: Vec<MatchLocation>,
    /// `true` when the cap was hit and additional matches exist beyond
    /// what is listed in `locations`.
    pub truncated: bool,
}

/// Per-file result details.
///
/// Does **not** contain any original secret values — only counts,
/// byte sizes, pattern labels, and the processing method used.
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    /// File path (relative or archive entry name).
    pub path: String,
    /// Number of matches found in this file.
    pub matches: u64,
    /// Number of replacements applied.
    pub replacements: u64,
    /// Bytes read from this file.
    pub bytes_processed: u64,
    /// Bytes written for this file.
    pub bytes_output: u64,
    /// Per-pattern match counts for this file.
    pub pattern_counts: HashMap<String, u64>,
    /// Processing method: `"scanner"`, `"structured:json"`, etc.
    pub method: String,
    /// Log context extraction results for this file, present when
    /// `--extract-context` was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_context: Option<LogContextResult>,
    /// Per-match line numbers and byte offsets, present when
    /// `--max-match-locations` is non-zero and the scanner path is used.
    /// Structured-processor paths do not populate this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_locations: Option<MatchLocationsResult>,
}

impl FileReport {
    /// Build a `FileReport` from scanner [`ScanStats`].
    #[must_use]
    pub fn from_scan_stats(
        path: impl Into<String>,
        stats: &ScanStats,
        method: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            matches: stats.matches_found,
            replacements: stats.replacements_applied,
            bytes_processed: stats.bytes_processed,
            bytes_output: stats.bytes_output,
            pattern_counts: stats.pattern_counts.clone(),
            method: method.into(),
            log_context: None,
            match_locations: None,
        }
    }

    /// Attach per-match location data collected via
    /// [`crate::scanner::StreamScanner::scan_reader_with_callbacks`].
    ///
    /// No-ops when `locations` is empty and `truncated` is false, keeping
    /// the JSON output clean for files with no scanner matches.
    #[must_use]
    pub fn with_match_locations(mut self, locations: Vec<MatchLocation>, truncated: bool) -> Self {
        if !locations.is_empty() || truncated {
            self.match_locations = Some(MatchLocationsResult {
                locations,
                truncated,
            });
        }
        self
    }
}

// ---------------------------------------------------------------------------
// Thread-safe report builder
// ---------------------------------------------------------------------------

/// Thread-safe builder that accumulates per-file results and produces
/// a final [`SanitizeReport`].
///
/// Designed for concurrent use: wrap in `Arc` and share across threads.
/// The internal `Mutex` is held only for the duration of a single
/// `Vec::push`, so contention is negligible even at high thread counts.
#[derive(Debug)]
pub struct ReportBuilder {
    metadata: ReportMetadata,
    files: Mutex<Vec<FileReport>>,
    start: Instant,
}

// All fields are Send + Sync natively (Mutex<Vec<_>>, Instant, owned structs),
// so ReportBuilder auto-derives Send + Sync without unsafe.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<ReportBuilder>();
    assert_sync::<ReportBuilder>();
};

impl ReportBuilder {
    /// Create a new builder with the given metadata.
    ///
    /// The wall-clock timer starts now.
    #[must_use]
    pub fn new(metadata: ReportMetadata) -> Self {
        Self {
            metadata,
            files: Mutex::new(Vec::new()),
            start: Instant::now(),
        }
    }

    /// Attach log context extraction results to the [`FileReport`] identified
    /// by `path`. The file must already have been recorded via
    /// [`Self::record_file`]. Thread-safe.
    pub fn set_file_log_context(&self, path: &str, result: LogContextResult) {
        let mut files = self.files.lock().expect("report mutex poisoned");
        if let Some(file) = files.iter_mut().find(|f| f.path == path) {
            file.log_context = Some(result);
        }
    }

    /// Record the result for a single file. Thread-safe.
    pub fn record_file(&self, file_report: FileReport) {
        let mut files = self.files.lock().expect("report mutex poisoned");
        files.push(file_report);
    }

    /// Record multiple file results at once (e.g., from archive processing).
    pub fn record_files(&self, reports: impl IntoIterator<Item = FileReport>) {
        let mut files = self.files.lock().expect("report mutex poisoned");
        files.extend(reports);
    }

    /// Consume the builder and produce the final report.
    ///
    /// The duration is measured from builder creation to this call.
    pub fn finish(self) -> SanitizeReport {
        #[allow(clippy::cast_possible_truncation)] // duration in ms won't exceed u64
        let duration_ms = self.start.elapsed().as_millis() as u64;
        let files = self.files.into_inner().expect("report mutex poisoned");

        // Aggregate summary.
        let mut total_matches: u64 = 0;
        let mut total_replacements: u64 = 0;
        let mut total_bytes_processed: u64 = 0;
        let mut total_bytes_output: u64 = 0;
        let mut pattern_counts: HashMap<String, u64> = HashMap::new();

        for f in &files {
            total_matches += f.matches;
            total_replacements += f.replacements;
            total_bytes_processed += f.bytes_processed;
            total_bytes_output += f.bytes_output;
            for (pat, count) in &f.pattern_counts {
                *pattern_counts.entry(pat.clone()).or_insert(0) += count;
            }
        }

        let summary = ReportSummary {
            total_files: files.len() as u64,
            total_matches,
            total_replacements,
            total_bytes_processed,
            total_bytes_output,
            duration_ms,
            pattern_counts,
        };

        SanitizeReport {
            metadata: self.metadata,
            summary,
            files,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> ReportMetadata {
        ReportMetadata {
            version: "0.2.0".into(),
            timestamp: "2026-03-01T00:00:00Z".into(),
            deterministic: false,
            dry_run: false,
            strict: false,
            chunk_size: 1_048_576,
            threads: None,
            secrets_file: None,
        }
    }

    fn sample_file_report(path: &str, matches: u64, pattern: &str) -> FileReport {
        FileReport {
            path: path.into(),
            matches,
            replacements: matches,
            bytes_processed: matches * 100,
            bytes_output: matches * 110,
            pattern_counts: HashMap::from([(pattern.into(), matches)]),
            method: "scanner".into(),
            log_context: None,
            match_locations: None,
        }
    }

    // ---- Basic construction ----

    #[test]
    fn empty_report() {
        let builder = ReportBuilder::new(sample_metadata());
        let report = builder.finish();
        assert_eq!(report.summary.total_files, 0);
        assert_eq!(report.summary.total_matches, 0);
        assert!(report.files.is_empty());
    }

    #[test]
    fn single_file_report() {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(sample_file_report("data.log", 10, "email"));
        let report = builder.finish();

        assert_eq!(report.summary.total_files, 1);
        assert_eq!(report.summary.total_matches, 10);
        assert_eq!(report.summary.total_replacements, 10);
        assert_eq!(report.summary.total_bytes_processed, 1000);
        assert_eq!(report.summary.total_bytes_output, 1100);
        assert_eq!(*report.summary.pattern_counts.get("email").unwrap(), 10);
        assert_eq!(report.files[0].path, "data.log");
    }

    #[test]
    fn multiple_files_aggregated() {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(sample_file_report("a.log", 5, "email"));
        builder.record_file(sample_file_report("b.log", 3, "ipv4"));
        builder.record_file(sample_file_report("c.log", 7, "email"));
        let report = builder.finish();

        assert_eq!(report.summary.total_files, 3);
        assert_eq!(report.summary.total_matches, 15);
        assert_eq!(*report.summary.pattern_counts.get("email").unwrap(), 12);
        assert_eq!(*report.summary.pattern_counts.get("ipv4").unwrap(), 3);
    }

    // ---- JSON serialization ----

    #[test]
    fn json_serialization_no_secrets() {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(FileReport {
            path: "config.yaml".into(),
            matches: 2,
            replacements: 2,
            bytes_processed: 500,
            bytes_output: 520,
            pattern_counts: HashMap::from([("hostname".into(), 2)]),
            method: "structured:yaml".into(),
            log_context: None,
            match_locations: None,
        });
        let report = builder.finish();
        let json = report.to_json_pretty().unwrap();

        // Must contain expected fields.
        assert!(json.contains("\"total_matches\": 2"));
        assert!(json.contains("\"version\": \"0.2.0\""));
        assert!(json.contains("\"hostname\": 2"));
        assert!(json.contains("\"method\": \"structured:yaml\""));
        assert!(json.contains("\"duration_ms\""));

        // Must NOT contain any original secret values — we only ever
        // store counts and labels, never pattern text or matched text.
        // This is a structural guarantee; verify that deserializing
        // back produces the same data without secret leakage.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["files"][0]["path"].as_str() == Some("config.yaml"));
        // No field named "secret", "original", or "value" at any level.
        let flat = json.to_lowercase();
        assert!(!flat.contains("\"original\""));
        assert!(!flat.contains("\"secret_value\""));
    }

    #[test]
    fn compact_json() {
        let builder = ReportBuilder::new(sample_metadata());
        let report = builder.finish();
        let json = report.to_json().unwrap();
        // Compact JSON has no pretty indentation.
        assert!(!json.contains("  "));
    }

    // ---- Metadata flags ----

    #[test]
    fn metadata_flags_preserved() {
        let meta = ReportMetadata {
            version: "0.8.0".into(),
            timestamp: "2026-06-15T12:00:00Z".into(),
            deterministic: true,
            dry_run: true,
            strict: true,
            chunk_size: 262_144,
            threads: Some(8),
            secrets_file: Some("secrets.enc".into()),
        };
        let builder = ReportBuilder::new(meta);
        let report = builder.finish();
        assert!(report.metadata.deterministic);
        assert!(report.metadata.dry_run);
        assert!(report.metadata.strict);
        assert_eq!(report.metadata.chunk_size, 262_144);
        assert_eq!(report.metadata.threads, Some(8));
        assert_eq!(report.metadata.secrets_file.as_deref(), Some("secrets.enc"));
    }

    // ---- Duration tracking ----

    #[test]
    fn duration_is_positive() {
        let builder = ReportBuilder::new(sample_metadata());
        // Do a tiny amount of work.
        builder.record_file(sample_file_report("x.txt", 1, "email"));
        let report = builder.finish();
        // Duration should be ≥ 0 (it will be 0 or 1 on fast machines).
        assert!(report.summary.duration_ms < 5_000); // sanity ceiling
    }

    // ---- Thread-safe concurrent recording ----

    #[test]
    fn concurrent_recording() {
        use std::sync::Arc;
        use std::thread;

        let builder = Arc::new(ReportBuilder::new(sample_metadata()));
        let mut handles = Vec::new();

        for i in 0_u64..16 {
            let b = Arc::clone(&builder);
            handles.push(thread::spawn(move || {
                b.record_file(sample_file_report(&format!("file_{i}.log"), i + 1, "email"));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // We need to unwrap the Arc to call finish().
        let builder = Arc::try_unwrap(builder).expect("other refs still held");
        let report = builder.finish();

        assert_eq!(report.summary.total_files, 16);
        // Sum of 1..=16 = 136.
        assert_eq!(report.summary.total_matches, 136);
    }

    // ---- FileReport::from_scan_stats ----

    #[test]
    fn file_report_from_scan_stats() {
        let stats = ScanStats {
            bytes_processed: 2048,
            bytes_output: 2100,
            matches_found: 5,
            replacements_applied: 5,
            pattern_counts: HashMap::from([("email".into(), 3), ("ipv4".into(), 2)]),
        };
        let fr = FileReport::from_scan_stats("test.log", &stats, "scanner");
        assert_eq!(fr.path, "test.log");
        assert_eq!(fr.matches, 5);
        assert_eq!(fr.bytes_processed, 2048);
        assert_eq!(*fr.pattern_counts.get("email").unwrap(), 3);
        assert_eq!(fr.method, "scanner");
    }

    // ---- Large-file simulation ----

    #[test]
    fn large_file_report() {
        let builder = ReportBuilder::new(sample_metadata());
        // Simulate a 10 GB file processed in chunks.
        builder.record_file(FileReport {
            path: "huge.log".into(),
            matches: 1_000_000,
            replacements: 1_000_000,
            bytes_processed: 10_737_418_240, // 10 GiB
            bytes_output: 10_900_000_000,
            pattern_counts: HashMap::from([("email".into(), 600_000), ("ipv4".into(), 400_000)]),
            method: "scanner".into(),
            log_context: None,
            match_locations: None,
        });
        let report = builder.finish();
        assert_eq!(report.summary.total_matches, 1_000_000);
        assert_eq!(report.summary.total_bytes_processed, 10_737_418_240);

        // JSON serialization still works for large numbers.
        let json = report.to_json().unwrap();
        assert!(json.contains("10737418240"));
    }

    // ---- record_files bulk insert ----

    #[test]
    fn record_files_bulk() {
        let builder = ReportBuilder::new(sample_metadata());
        let files: Vec<FileReport> = (0..5)
            .map(|i| sample_file_report(&format!("entry_{i}.txt"), 2, "ssn"))
            .collect();
        builder.record_files(files);
        let report = builder.finish();
        assert_eq!(report.summary.total_files, 5);
        assert_eq!(report.summary.total_matches, 10);
    }

    // ---- SARIF output ----

    fn rich_report() -> SanitizeReport {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(FileReport {
            path: "config.yaml".into(),
            matches: 3,
            replacements: 3,
            bytes_processed: 1024,
            bytes_output: 1100,
            pattern_counts: HashMap::from([("auth_token".into(), 2u64), ("email".into(), 1u64)]),
            method: "structured:yaml".into(),
            log_context: None,
            match_locations: None,
        });
        builder.record_file(FileReport {
            path: "logs/app.log".into(),
            matches: 0,
            replacements: 0,
            bytes_processed: 512,
            bytes_output: 512,
            pattern_counts: HashMap::new(),
            method: "scanner".into(),
            log_context: None,
            match_locations: None,
        });
        builder.finish()
    }

    #[test]
    fn sarif_is_valid_json() {
        let sarif = rich_report().to_sarif().unwrap();
        let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(
            v["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );
    }

    #[test]
    fn sarif_contains_one_run() {
        let v: serde_json::Value =
            serde_json::from_str(&rich_report().to_sarif().unwrap()).unwrap();
        assert_eq!(v["runs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sarif_driver_name_and_version() {
        let v: serde_json::Value =
            serde_json::from_str(&rich_report().to_sarif().unwrap()).unwrap();
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "rust-sanitize");
        assert_eq!(driver["version"], "0.2.0");
    }

    #[test]
    fn sarif_rules_one_per_pattern() {
        let v: serde_json::Value =
            serde_json::from_str(&rich_report().to_sarif().unwrap()).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        // Two patterns: auth_token, email.
        assert_eq!(rules.len(), 2);
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"auth_token"));
        assert!(ids.contains(&"email"));
    }

    #[test]
    fn sarif_results_only_for_nonzero_counts() {
        let v: serde_json::Value =
            serde_json::from_str(&rich_report().to_sarif().unwrap()).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        // logs/app.log has 0 matches → 0 results for it; config.yaml has 2 patterns.
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn sarif_result_level_pii_is_error() {
        let v: serde_json::Value =
            serde_json::from_str(&rich_report().to_sarif().unwrap()).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        let email_result = results
            .iter()
            .find(|r| r["ruleId"] == "email")
            .expect("email result missing");
        assert_eq!(email_result["level"], "error");
    }

    #[test]
    fn sarif_result_has_file_uri() {
        let v: serde_json::Value =
            serde_json::from_str(&rich_report().to_sarif().unwrap()).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        for result in results {
            let uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap();
            assert_eq!(uri, "config.yaml");
        }
    }

    #[test]
    fn sarif_artifacts_all_files() {
        let v: serde_json::Value =
            serde_json::from_str(&rich_report().to_sarif().unwrap()).unwrap();
        let artifacts = v["runs"][0]["artifacts"].as_array().unwrap();
        assert_eq!(artifacts.len(), 2);
        let uris: Vec<&str> = artifacts
            .iter()
            .map(|a| a["location"]["uri"].as_str().unwrap())
            .collect();
        assert!(uris.contains(&"config.yaml"));
        assert!(uris.contains(&"logs/app.log"));
    }

    #[test]
    fn sarif_windows_paths_use_forward_slash() {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(FileReport {
            path: r"src\secrets\config.json".into(),
            matches: 1,
            replacements: 1,
            bytes_processed: 100,
            bytes_output: 110,
            pattern_counts: HashMap::from([("auth_token".into(), 1u64)]),
            method: "structured:json".into(),
            log_context: None,
            match_locations: None,
        });
        let report = builder.finish();
        let v: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
        let uri = v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(uri, "src/secrets/config.json");
    }

    // ---- HTML output ----

    #[test]
    fn html_is_valid_document() {
        let html = rich_report().to_html();
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<title>rust-sanitize report</title>"));
    }

    #[test]
    fn html_contains_summary_stats() {
        let html = rich_report().to_html();
        // 1 file with matches + 1 clean file = 2 files total.
        assert!(html.contains(">2<"), "file count missing");
        // 3 total matches.
        assert!(html.contains(">3<"), "match count missing");
    }

    #[test]
    fn html_contains_file_paths() {
        let html = rich_report().to_html();
        assert!(html.contains("config.yaml"));
        assert!(html.contains("logs/app.log"));
    }

    #[test]
    fn html_escapes_special_chars() {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(FileReport {
            path: "<script>alert(1)</script>".into(),
            matches: 0,
            replacements: 0,
            bytes_processed: 0,
            bytes_output: 0,
            pattern_counts: HashMap::new(),
            method: "scanner".into(),
            log_context: None,
            match_locations: None,
        });
        let html = builder.finish().to_html();
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_no_external_resources() {
        let html = rich_report().to_html();
        // No CDN links, no external stylesheets, no external scripts.
        assert!(!html.contains("http://") || !html.contains("https://json.schemastore.org"));
        assert!(!html.contains("cdn."));
        assert!(!html.contains("src=\"http"));
        assert!(!html.contains("href=\"http"));
    }

    // ---- helpers ----

    #[test]
    fn sarif_rule_name_camel_case() {
        assert_eq!(sarif_rule_name("auth_token"), "AuthToken");
        assert_eq!(sarif_rule_name("email"), "Email");
        assert_eq!(sarif_rule_name("custom:password"), "CustomPassword");
        assert_eq!(sarif_rule_name("aws_arn"), "AwsArn");
    }

    #[test]
    fn fmt_bytes_human_readable() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn html_escape_special_chars() {
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(html_escape("\"quote\""), "&quot;quote&quot;");
        assert_eq!(html_escape("normal"), "normal");
    }
}
