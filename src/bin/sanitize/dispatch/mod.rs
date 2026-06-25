use std::collections::HashMap;
use std::fs;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use rust_sanitize::secrets::SecretEntry;
use rust_sanitize::{
    atomic_write, atomic_write_private, extract_context, extract_context_reader, ArchiveFilter,
    ArchiveFormat, ArchiveProcessor, ArchiveProgress, AtomicFileWriter, EntryCallback, FileReport,
    FileTypeProfile, LlmEntry, LogContextConfig, LogContextResult, MappingStore, Processor,
    ProcessorRegistry, ReportBuilder, ScanPattern, ScanStats, StreamScanner,
};

use crate::cli_args::Cli;
use crate::entropy::{
    entropy_histogram_bytes, entropy_scan_bytes, scanner_fallback, EntropyBuckets, EntropyConfig,
    NullSeekWriter, HISTOGRAM_THRESHOLDS,
};
use crate::input::{format_to_ext, is_structured_filename};
use crate::progress::{with_progress_scope, SharedProgressReporter};

/// Maximum output size buffered in memory when `--extract-context` is used
/// and the sanitized output is directed to stdout.
pub(crate) const MAX_CONTEXT_BUFFER_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

/// Shared per-run collector for `--llm`: (label, sanitized_bytes) pairs in input order.
pub(crate) type LlmCollector = Arc<Mutex<Vec<LlmEntry>>>;

/// All per-run context needed to process a single file, stdin, or archive.
/// Every field is a reference or `Copy` type, so `FileProcessor<'a>` is `Copy`.
#[derive(Copy, Clone)]
pub(crate) struct FileProcessor<'a> {
    pub(crate) cli: &'a crate::cli_args::Cli,
    pub(crate) scanner: &'a Arc<StreamScanner>,
    pub(crate) registry: &'a Arc<ProcessorRegistry>,
    pub(crate) store: &'a Arc<MappingStore>,
    pub(crate) profiles: &'a [FileTypeProfile],
    pub(crate) report_builder: Option<&'a ReportBuilder>,
    pub(crate) progress: Option<&'a SharedProgressReporter>,
    pub(crate) llm_collector: Option<&'a LlmCollector>,
    pub(crate) entropy_configs: &'a Arc<Vec<crate::entropy::EntropyConfig>>,
    pub(crate) entropy_histogram_acc: Option<&'a Arc<Mutex<Vec<crate::entropy::EntropyBuckets>>>>,
    /// When `true`, a structured file's format-preserving scanner is built from
    /// the **entire** mapping store rather than only the values discovered while
    /// processing that file. This lets values found in *other* structured files
    /// (e.g. the same email or password in two configs) be redacted here too —
    /// including where they appear in comments or unstructured regions. Set on
    /// the output pass that runs after the discovery pre-pass has populated the
    /// store; the discovery pass itself uses the per-file delta.
    pub(crate) full_store_pass: bool,
}

fn merge_entropy_counts(stats: &mut ScanStats, label_counts: HashMap<String, u64>) {
    let total: u64 = label_counts.values().sum();
    stats.matches_found += total;
    stats.replacements_applied += total;
    for (label, count) in label_counts {
        *stats.pattern_counts.entry(label).or_insert(0) += count;
    }
}

/// Run entropy scanning on `bytes` in-place, merging label counts into `stats`.
/// Returns the (potentially modified) bytes; does nothing when entropy configs
/// is empty, which is the common case.
fn apply_entropy_inplace(bytes: Vec<u8>, stats: &mut ScanStats, fp: FileProcessor<'_>) -> Vec<u8> {
    if fp.entropy_configs.is_empty() {
        return bytes;
    }
    let (out, lc) = entropy_scan_bytes(&bytes, fp.entropy_configs, fp.store);
    merge_entropy_counts(stats, lc);
    out
}

/// Complete a buffered scan: record the result to the report, run
/// context extraction, write or collect the output, and return
/// `had_matches`.
///
/// Called from every code path that already has the full sanitized
/// bytes in memory (structured path, `scan_plain_scanner` buffered
/// branches, etc.).
fn finalize_buffered_scan(
    output_bytes: &[u8],
    stats: &ScanStats,
    label: &str,
    method: &str,
    output_path: Option<&Path>,
    cli: &crate::cli_args::Cli,
    fp: FileProcessor<'_>,
) -> Result<bool, String> {
    let had_matches = stats.matches_found > 0;

    if let Some(rb) = fp.report_builder {
        rb.record_file(FileReport::from_scan_stats(
            label.to_string(),
            stats,
            method,
        ));
    }

    if cli.dry_run {
        tracing::info!(
            matches = stats.matches_found,
            replacements = stats.replacements_applied,
            "dry-run complete"
        );
        return Ok(had_matches);
    }

    maybe_extract_context(output_bytes, label, cli, fp.report_builder);
    write_or_collect(output_bytes, label, output_path, fp.llm_collector)?;
    Ok(had_matches)
}

fn accumulate_entropy_histogram(
    acc: &Arc<Mutex<Vec<EntropyBuckets>>>,
    buf: &[u8],
    configs: &[EntropyConfig],
) {
    let local = entropy_histogram_bytes(buf, configs);
    let mut guard = acc.lock().expect("entropy histogram lock");
    if guard.is_empty() {
        *guard = local;
    } else {
        for (dst, src) in guard.iter_mut().zip(local.iter()) {
            dst.merge(src);
        }
    }
}

pub(crate) fn print_entropy_histogram(buckets: &[EntropyBuckets]) {
    for b in buckets {
        let label_suffix = if b.label != "high_entropy_token" {
            format!(" [{}]", b.label)
        } else {
            String::new()
        };
        if b.total_candidates == 0 {
            eprintln!(
                "Entropy calibration{} — {} ({}–{} chars): no candidates found",
                label_suffix, b.charset_desc, b.min_length, b.max_length
            );
            continue;
        }
        eprintln!(
            "Entropy calibration{} — {} ({}–{} chars):",
            label_suffix, b.charset_desc, b.min_length, b.max_length
        );
        for (i, &thresh) in HISTOGRAM_THRESHOLDS.iter().enumerate() {
            let count = b.counts[i];
            let marker = if (thresh - b.configured_threshold).abs() < 1e-9 {
                "  ← threshold"
            } else {
                ""
            };
            eprintln!("  ≥{:.1} bits  {:>6}{}", thresh, count, marker);
        }
        if !HISTOGRAM_THRESHOLDS
            .iter()
            .any(|&t| (t - b.configured_threshold).abs() < 1e-9)
        {
            eprintln!(
                "  (configured threshold {:.2} bits falls between standard levels above)",
                b.configured_threshold
            );
        }
        eprintln!("  {} candidates examined", b.total_candidates);
    }
}

fn make_scan_callback(
    progress: Option<SharedProgressReporter>,
    label: impl Into<String>,
) -> impl FnMut(&rust_sanitize::ScanProgress) {
    let label = label.into();
    move |scan_progress| {
        if let Some(reporter) = &progress {
            reporter
                .lock()
                .expect("progress reporter lock")
                .update_scan(&label, scan_progress);
        }
    }
}

fn scan_with_locations<R, W>(
    scanner: &StreamScanner,
    reader: R,
    writer: W,
    total_bytes: Option<u64>,
    progress_cb: impl FnMut(&rust_sanitize::ScanProgress),
    max_locations: usize,
) -> Result<(ScanStats, Vec<rust_sanitize::scanner::MatchLocation>, bool), String>
where
    R: std::io::Read,
    W: std::io::Write,
{
    let mut locations: Vec<rust_sanitize::scanner::MatchLocation> = Vec::new();
    let mut truncated = false;
    let stats = scanner
        .scan_reader_with_callbacks(reader, writer, total_bytes, progress_cb, |loc| {
            if max_locations == 0 {
                return;
            }
            if locations.len() < max_locations {
                locations.push(loc);
            } else {
                truncated = true;
            }
        })
        .map_err(|e| format!("scanner error: {e}"))?;
    Ok((stats, locations, truncated))
}

/// Return `true` if the first 512 bytes look like binary.
fn looks_binary(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(512)];
    if sample.contains(&0u8) {
        return true;
    }
    let non_text = sample
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    non_text as f64 / sample.len().max(1) as f64 > 0.10
}

fn build_log_context_config(cli: &Cli) -> LogContextConfig {
    let mut config = LogContextConfig::new()
        .with_context_lines(cli.context_lines)
        .with_max_matches(cli.max_context_matches)
        .case_sensitive(cli.context_case_sensitive);
    if !cli.context_keywords.is_empty() {
        config = if cli.context_keywords_replace {
            config.with_keywords(cli.context_keywords.iter().cloned())
        } else {
            config.with_extra_keywords(cli.context_keywords.iter().cloned())
        };
    }
    config
}

fn maybe_extract_context(
    bytes: &[u8],
    report_path: &str,
    cli: &Cli,
    report_builder: Option<&ReportBuilder>,
) {
    if !cli.extract_context {
        return;
    }
    let Some(rb) = report_builder else { return };
    let text = String::from_utf8_lossy(bytes);
    rb.set_file_log_context(
        report_path,
        extract_context(&text, &build_log_context_config(cli)),
    );
}

fn maybe_extract_context_reader(
    out_path: &Path,
    report_path: &str,
    cli: &Cli,
    report_builder: Option<&ReportBuilder>,
) {
    if !cli.extract_context {
        return;
    }
    let Some(rb) = report_builder else { return };
    let config = build_log_context_config(cli);
    let file = match fs::File::open(out_path) {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, path = %out_path.display(), "--extract-context: failed to open output file for context scan");
            return;
        }
    };
    match extract_context_reader(BufReader::new(file), &config) {
        Ok(result) => rb.set_file_log_context(report_path, result),
        Err(e) => warn!(error = %e, "--extract-context: failed to read output for log context"),
    }
}

pub(crate) fn abs_label(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(path))
        .display()
        .to_string()
}

fn maybe_collect_for_llm(bytes: &[u8], label: &str, collector: Option<&LlmCollector>) {
    if let Some(c) = collector {
        if let Ok(mut guard) = c.lock() {
            guard.push((label.to_string(), bytes.to_vec()));
        }
    }
}

pub(crate) fn write_output(output_path: Option<&Path>, data: &[u8]) -> Result<(), String> {
    match output_path {
        Some(path) if path != Path::new("-") => {
            atomic_write(path, data)
                .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
            info!(output = %path.display(), "output written");
        }
        _ => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(data)
                .map_err(|e| format!("failed to write to stdout: {e}"))?;
        }
    }
    Ok(())
}

fn write_or_collect(
    data: &[u8],
    label: &str,
    output_path: Option<&Path>,
    collector: Option<&LlmCollector>,
) -> Result<(), String> {
    if let Some(c) = collector {
        maybe_collect_for_llm(data, label, Some(c));
        Ok(())
    } else {
        write_output(output_path, data)
    }
}

fn file_size(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|e| format!("failed to stat {}: {e}", path.display()))
}

fn try_structured_processing(
    content: &[u8],
    filename: &str,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    profiles: &[FileTypeProfile],
) -> Option<Result<Vec<u8>, String>> {
    let profile = profiles.iter().find(|p| p.matches_filename(filename))?;
    match registry.process(content, profile, store) {
        Ok(Some(result)) => Some(Ok(result)),
        Ok(None) => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

/// Span-based structured processing: returns `Some(Ok(edited_bytes))` when a
/// profile matches *and* its processor supports byte-span edits (field values
/// replaced in place, format-preserving and leak-free); `None` when no profile
/// matches or the processor doesn't support edits (caller falls back to
/// [`try_structured_processing`]); `Some(Err)` on parse failure.
fn try_structured_edits(
    content: &[u8],
    filename: &str,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    profiles: &[FileTypeProfile],
) -> Option<Result<(Vec<u8>, usize), String>> {
    let profile = profiles.iter().find(|p| p.matches_filename(filename))?;
    match registry.process_to_edits(content, profile, store) {
        Ok(Some(result)) => Some(Ok(result)),
        Ok(None) => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

/// Compute the bytes the format-preserving scanner should run over for a
/// structured file, paired with the number of in-place field edits made (so the
/// caller can count profile-field redactions in the run summary). Returns:
///
/// - edit-applied bytes with the edit count, when the processor supports span edits;
/// - the original bytes with a zero count, when only the literal structured pass
///   applies (the store still gets populated and those values are counted later
///   by the scanner);
/// - `None` when no structured processing happened (caller uses the plain
///   scanner over the originals).
pub(crate) fn structured_base_bytes(
    input_bytes: &[u8],
    filename: &str,
    fp: &FileProcessor,
    strict: bool,
) -> Result<Option<(Vec<u8>, usize)>, String> {
    // Prefer span-based edit mode: exact, format-preserving, leak-free.
    match try_structured_edits(input_bytes, filename, fp.registry, fp.store, fp.profiles) {
        Some(Ok((edited, count))) => return Ok(Some((edited, count))),
        Some(Err(e)) if strict => return Err(format!("structured processing failed: {e}")),
        Some(Err(e)) => warn!(error = %e, "structured edit pass failed, trying literal pass"),
        None => {}
    }
    // Fall back to the literal structured pass (populates the store; the
    // format-preserving scanner then runs over the original bytes and counts the
    // re-matched values, so the edit count here is 0).
    match try_structured_processing(input_bytes, filename, fp.registry, fp.store, fp.profiles) {
        Some(Ok(_)) => Ok(Some((input_bytes.to_vec(), 0))),
        Some(Err(e)) if strict => Err(format!("structured processing failed: {e}")),
        Some(Err(e)) => {
            warn!(error = %e, "structured processing failed, falling back to scanner");
            Ok(None)
        }
        None => Ok(None),
    }
}

fn build_format_preserving_scanner(
    base_scanner: &Arc<StreamScanner>,
    store: &Arc<MappingStore>,
    snapshot: rust_sanitize::store::StoreSnapshot,
) -> Result<StreamScanner, rust_sanitize::error::SanitizeError> {
    let extra: Vec<ScanPattern> = store
        .iter_since(snapshot)
        .filter(|(_, orig, _)| orig.len() >= 4)
        .filter_map(|(category, original, _)| {
            let s = original.as_str();
            // Label by category, never the value (labels appear in user-facing
            // report/findings/summary output, which must contain no secrets).
            let label = format!("field:{category}");
            match ScanPattern::from_literal(s, category, label) {
                Ok(pat) => Some(pat),
                Err(e) => {
                    warn!(error = %e, "could not compile field literal pattern");
                    None
                }
            }
        })
        .collect();

    base_scanner.for_structured_pass(extra)
}

pub(crate) fn load_profiles(path: &Path) -> Result<Vec<FileTypeProfile>, String> {
    let raw =
        fs::read(path).map_err(|e| format!("failed to read profile '{}': {e}", path.display()))?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| format!("profile '{}' is not valid UTF-8", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let profiles: Vec<FileTypeProfile> = match ext {
        "json" => serde_json::from_str(text)
            .map_err(|e| format!("profile '{}': invalid JSON: {e}", path.display())),
        "yaml" | "yml" => serde_yaml_ng::from_str(text)
            .map_err(|e| format!("profile '{}': invalid YAML: {e}", path.display())),
        _ => serde_json::from_str(text)
            .or_else(|_| serde_yaml_ng::from_str(text))
            .map_err(|e| {
                format!(
                    "profile '{}': could not parse as JSON or YAML: {e}",
                    path.display()
                )
            }),
    }?;

    for (i, p) in profiles.iter().enumerate() {
        for pat in p.include.iter().chain(p.exclude.iter()) {
            glob::Pattern::new(pat).map_err(|e| {
                format!(
                    "profile '{}' entry {i}: invalid glob '{pat}': {e}",
                    path.display()
                )
            })?;
        }
    }

    Ok(profiles)
}

pub(crate) fn save_discovered_secrets(
    store: &Arc<MappingStore>,
    path: &Path,
) -> std::result::Result<usize, String> {
    let mut new_entries: Vec<SecretEntry> = store
        .iter()
        .filter(|(_, original, _)| !original.is_empty())
        .map(|(category, original, _)| SecretEntry {
            pattern: original.to_string(),
            kind: "literal".into(),
            category: category.to_string(),
            label: Some("discovered".into()),
            values: vec![],
            min_length: None,
            max_length: None,
            threshold: None,
            charset: None,
        })
        .collect();

    if new_entries.is_empty() {
        return Ok(0);
    }

    let existing: Vec<SecretEntry> = if path.exists() {
        let raw = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
        serde_yaml_ng::from_str::<Vec<SecretEntry>>(text)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))?
    } else {
        vec![]
    };

    let existing_patterns: std::collections::HashSet<&str> =
        existing.iter().map(|e| e.pattern.as_str()).collect();

    new_entries.retain(|e| !existing_patterns.contains(e.pattern.as_str()));
    let added = new_entries.len();

    if added == 0 {
        return Ok(0);
    }

    let mut all_entries: Vec<&SecretEntry> = existing.iter().collect();
    all_entries.extend(new_entries.iter());

    let yaml = serde_yaml_ng::to_string(&all_entries)
        .map_err(|e| format!("failed to serialize discovered secrets: {e}"))?;

    atomic_write_private(path, yaml.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;

    Ok(added)
}

fn record_archive_stats(rb: &ReportBuilder, stats: &rust_sanitize::ArchiveStats) {
    for (path, method) in &stats.file_methods {
        if let Some(scan_stats) = stats.file_scan_stats.get(path) {
            rb.record_file(FileReport::from_scan_stats(
                path.clone(),
                scan_stats,
                method.clone(),
            ));
        } else {
            rb.record_file(FileReport {
                path: path.clone(),
                matches: 0,
                replacements: 0,
                bytes_processed: 0,
                bytes_output: 0,
                pattern_counts: std::collections::HashMap::new(),
                method: method.clone(),
                log_context: None,
                match_locations: None,
            });
        }
    }

    if stats.file_methods.is_empty() {
        rb.record_file(FileReport {
            path: "(archive)".into(),
            matches: 0,
            replacements: 0,
            bytes_processed: stats.total_input_bytes,
            bytes_output: stats.total_output_bytes,
            pattern_counts: std::collections::HashMap::new(),
            method: format!(
                "archive({} files, {} structured, {} scanner)",
                stats.files_processed, stats.structured_hits, stats.scanner_fallback
            ),
            log_context: None,
            match_locations: None,
        });
    }
}

fn print_archive_stats(output: &Path, stats: &rust_sanitize::ArchiveStats) {
    info!(
        files = stats.files_processed,
        structured = stats.structured_hits,
        scanner = stats.scanner_fallback,
        output = %output.display(),
        "archive processing complete"
    );
}

mod archive;
mod file;
mod stdin;

#[cfg(test)]
mod tests {
    use super::*;
    use rust_sanitize::{MappingStore, RandomGenerator};
    use std::sync::Arc;

    fn empty_store() -> Arc<MappingStore> {
        Arc::new(MappingStore::new(Arc::new(RandomGenerator::new()), None))
    }

    fn store_with_entry(original: &str) -> Arc<MappingStore> {
        let store = empty_store();
        store
            .get_or_insert(&rust_sanitize::Category::AuthToken, original)
            .unwrap();
        store
    }

    // ── save_discovered_secrets ──────────────────────────────────────────────

    #[test]
    fn save_discovered_secrets_empty_store_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.yaml");
        let n = save_discovered_secrets(&empty_store(), &path).unwrap();
        assert_eq!(n, 0);
        assert!(
            !path.exists(),
            "no file should be created when store is empty"
        );
    }

    #[test]
    fn save_discovered_secrets_writes_new_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.yaml");
        let store = store_with_entry("abc123");

        let n = save_discovered_secrets(&store, &path).unwrap();
        assert_eq!(n, 1);
        let content = fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("abc123"),
            "written file should contain the literal value"
        );
        assert!(
            content.contains("literal"),
            "entry kind should be 'literal'"
        );
    }

    #[test]
    fn save_discovered_secrets_skips_existing_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.yaml");

        // First write.
        let store = store_with_entry("abc123");
        save_discovered_secrets(&store, &path).unwrap();

        // Second write with the same value — should add 0 new entries.
        let n = save_discovered_secrets(&store, &path).unwrap();
        assert_eq!(n, 0);

        // File should still have exactly one entry.
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches("abc123").count(), 1);
    }

    #[test]
    fn save_discovered_secrets_adds_to_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.yaml");

        let store1 = store_with_entry("first_secret");
        save_discovered_secrets(&store1, &path).unwrap();

        let store2 = store_with_entry("second_secret");
        let n = save_discovered_secrets(&store2, &path).unwrap();
        assert_eq!(n, 1);

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("first_secret"));
        assert!(content.contains("second_secret"));
    }

    #[test]
    fn save_discovered_secrets_errors_on_malformed_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.yaml");
        fs::write(&path, b"this: is: not: valid: yaml: ][[[").unwrap();

        let store = store_with_entry("abc123");
        let result = save_discovered_secrets(&store, &path);
        assert!(
            result.is_err(),
            "malformed YAML should return an error, not silently lose data"
        );
    }

    // ── looks_binary ─────────────────────────────────────────────────────────

    #[test]
    fn looks_binary_detects_null_byte() {
        assert!(looks_binary(b"hello\x00world"));
    }

    #[test]
    fn looks_binary_detects_high_control_char_ratio() {
        // Build a buffer where >10% of bytes are non-text control chars.
        let mut data = vec![0x01u8; 60]; // SOH — control char, not \n/\r/\t
        data.extend_from_slice(&[b'a'; 40]);
        assert!(looks_binary(&data), "60% control chars should look binary");
    }

    #[test]
    fn looks_binary_passes_plain_text() {
        let text = b"key = \"some value\"\nfoo = bar\npath = /tmp/file.txt\n";
        assert!(!looks_binary(text));
    }

    #[test]
    fn looks_binary_passes_text_with_tabs_and_cr() {
        let text = b"col1\tcol2\r\nval1\tval2\r\n";
        assert!(
            !looks_binary(text),
            "tabs and CR should not count as binary"
        );
    }

    #[test]
    fn looks_binary_samples_only_first_512_bytes() {
        // Put NUL after position 512 — should not be detected.
        let mut data = vec![b'a'; 600];
        data[513] = 0x00;
        assert!(
            !looks_binary(&data),
            "NUL after byte 512 should not trigger binary detection"
        );
    }

    // ── merge_entropy_counts ─────────────────────────────────────────────────

    #[test]
    fn merge_entropy_counts_adds_to_stats() {
        use rust_sanitize::ScanStats;
        let mut stats = ScanStats::default();
        let mut counts = HashMap::new();
        counts.insert("high_entropy_token".to_string(), 3u64);
        counts.insert("other_label".to_string(), 2u64);
        merge_entropy_counts(&mut stats, counts);
        assert_eq!(stats.matches_found, 5);
        assert_eq!(stats.replacements_applied, 5);
        assert_eq!(stats.pattern_counts["high_entropy_token"], 3);
        assert_eq!(stats.pattern_counts["other_label"], 2);
    }

    #[test]
    fn merge_entropy_counts_empty_map_is_noop() {
        use rust_sanitize::ScanStats;
        let mut stats = ScanStats::default();
        merge_entropy_counts(&mut stats, HashMap::new());
        assert_eq!(stats.matches_found, 0);
        assert_eq!(stats.replacements_applied, 0);
        assert!(stats.pattern_counts.is_empty());
    }
}
