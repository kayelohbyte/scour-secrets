use std::collections::HashMap;
use std::fs;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use sanitize_engine::secrets::SecretEntry;
use sanitize_engine::{
    atomic_write, atomic_write_private, extract_context, extract_context_reader, ArchiveFilter, ArchiveFormat,
    ArchiveProcessor, ArchiveProgress, AtomicFileWriter, EntryCallback, FileReport,
    FileTypeProfile, LlmEntry, LogContextConfig, LogContextResult, MappingStore, ProcessorRegistry,
    ReportBuilder, ScanPattern, ScanStats, StreamScanner,
};

use crate::cli_args::Cli;
use crate::entropy::{
    entropy_histogram_bytes, entropy_scan_bytes, scanner_fallback, EntropyBuckets, EntropyConfig,
    NullSeekWriter, HISTOGRAM_THRESHOLDS,
};
use crate::input::format_to_ext;
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
    pub(crate) cli:                   &'a crate::cli_args::Cli,
    pub(crate) scanner:               &'a Arc<StreamScanner>,
    pub(crate) registry:              &'a Arc<ProcessorRegistry>,
    pub(crate) store:                 &'a Arc<MappingStore>,
    pub(crate) profiles:              &'a [FileTypeProfile],
    pub(crate) report_builder:        Option<&'a ReportBuilder>,
    pub(crate) progress:              Option<&'a SharedProgressReporter>,
    pub(crate) llm_collector:         Option<&'a LlmCollector>,
    pub(crate) entropy_configs:       &'a Arc<Vec<crate::entropy::EntropyConfig>>,
    pub(crate) entropy_histogram_acc: Option<&'a Arc<Mutex<Vec<crate::entropy::EntropyBuckets>>>>,
}

fn merge_entropy_counts(stats: &mut ScanStats, label_counts: HashMap<String, u64>) {
    let total: u64 = label_counts.values().sum();
    stats.matches_found += total;
    stats.replacements_applied += total;
    for (label, count) in label_counts {
        *stats.pattern_counts.entry(label).or_insert(0) += count;
    }
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
) -> impl FnMut(&sanitize_engine::ScanProgress) {
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
    progress_cb: impl FnMut(&sanitize_engine::ScanProgress),
    max_locations: usize,
) -> Result<
    (
        ScanStats,
        Vec<sanitize_engine::scanner::MatchLocation>,
        bool,
    ),
    String,
>
where
    R: std::io::Read,
    W: std::io::Write,
{
    let mut locations: Vec<sanitize_engine::scanner::MatchLocation> = Vec::new();
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

fn build_format_preserving_scanner(
    base_scanner: &Arc<StreamScanner>,
    store: &Arc<MappingStore>,
    snapshot: usize,
) -> Result<StreamScanner, sanitize_engine::error::SanitizeError> {
    let extra: Vec<ScanPattern> = store
        .iter_since(snapshot)
        .filter(|(_, orig, _)| orig.len() >= 4)
        .filter_map(|(category, original, _)| {
            let s = original.as_str();
            match ScanPattern::from_literal(s, category, format!("field:{s}")) {
                Ok(pat) => Some(pat),
                Err(e) => {
                    warn!(value = %s, error = %e, "could not compile field literal pattern");
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

fn record_archive_stats(rb: &ReportBuilder, stats: &sanitize_engine::ArchiveStats) {
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

fn print_archive_stats(output: &Path, stats: &sanitize_engine::ArchiveStats) {
    info!(
        files = stats.files_processed,
        structured = stats.structured_hits,
        scanner = stats.scanner_fallback,
        output = %output.display(),
        "archive processing complete"
    );
}

impl<'a> FileProcessor<'a> {
    /// Process input from stdin. Returns `true` if matches were found.
    pub(crate) fn process_stdin(self, output_path: Option<&Path>) -> Result<bool, String> {
        let cli = self.cli;
        let structured_ext = if cli.force_text {
            None
        } else {
            cli.format.as_deref().and_then(format_to_ext)
        };

        let mut had_matches = false;
        let fp = self;

        if let Some(ext) = structured_ext {
            let mut input_bytes = Vec::new();
            let limit = cli.max_structured_size;
            io::stdin()
                .take(limit + 1)
                .read_to_end(&mut input_bytes)
                .map_err(|e| format!("failed to read stdin: {e}"))?;
            if input_bytes.len() as u64 > limit {
                warn!(
                    max = limit,
                    "stdin exceeds --max-structured-size, falling back to streaming scanner"
                );
                let cursor = Cursor::new(input_bytes);
                let chained = cursor.chain(io::stdin().lock());
                let reader = BufReader::new(chained);
                return fp.process_stdin_streaming(reader, output_path);
            }

            let store_len_before = fp.store.len();
            let store_snapshot = fp.store.snapshot();
            let label = format!("Processing structured stdin ({ext})");
            return with_progress_scope(fp.progress, &label, move |_| {
                let structured_result = try_structured_processing(
                    &input_bytes,
                    &format!("stdin.{ext}"),
                    fp.registry,
                    fp.store,
                    fp.profiles,
                );

                match structured_result {
                    Some(Ok(_structured_bytes)) => {
                        let per_content_scanner =
                            build_format_preserving_scanner(fp.scanner, fp.store, store_snapshot)
                                .map_err(|e| format!("failed to build content scanner: {e}"))?;
                        let (mut output_bytes, scan_stats) =
                            scanner_fallback(&per_content_scanner, &input_bytes)?;
                        let (ent_out, ent_lc) =
                            entropy_scan_bytes(&output_bytes, fp.entropy_configs, fp.store);
                        output_bytes = ent_out;
                        let ent_total: u64 = ent_lc.values().sum();
                        let method = format!("structured+scan:{ext}");
                        let structured_reps =
                            fp.store.len().saturating_sub(store_len_before) as u64;
                        let total_replacements =
                            structured_reps + scan_stats.replacements_applied + ent_total;
                        if total_replacements > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = fp.report_builder {
                            let mut pattern_counts = scan_stats.pattern_counts.clone();
                            for (label, count) in &ent_lc {
                                *pattern_counts.entry(label.clone()).or_insert(0) += count;
                            }
                            let stats = ScanStats {
                                matches_found: total_replacements,
                                replacements_applied: total_replacements,
                                bytes_processed: input_bytes.len() as u64,
                                bytes_output: output_bytes.len() as u64,
                                pattern_counts,
                            };
                            rb.record_file(FileReport::from_scan_stats(
                                "<stdin>".to_string(),
                                &stats,
                                method,
                            ));
                        }
                        maybe_extract_context(&output_bytes, "<stdin>", cli, fp.report_builder);
                        if !cli.dry_run {
                            write_or_collect(
                                &output_bytes,
                                "<stdin>",
                                output_path,
                                fp.llm_collector,
                            )?;
                        }
                        return Ok(had_matches);
                    }
                    Some(Err(e)) => {
                        if cli.strict {
                            return Err(format!("structured processing failed: {e}"));
                        }
                        warn!(error = %e, "structured processing failed, falling back to scanner");
                    }
                    None => {}
                }

                let (mut output_bytes, mut stats) = scanner_fallback(fp.scanner, &input_bytes)?;
                let (ent_out, ent_lc) =
                    entropy_scan_bytes(&output_bytes, fp.entropy_configs, fp.store);
                output_bytes = ent_out;
                merge_entropy_counts(&mut stats, ent_lc);
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(FileReport::from_scan_stats(
                        "<stdin>".to_string(),
                        &stats,
                        "scanner",
                    ));
                }
                maybe_extract_context(&output_bytes, "<stdin>", cli, fp.report_builder);
                if !cli.dry_run {
                    write_or_collect(&output_bytes, "<stdin>", output_path, fp.llm_collector)?;
                }
                Ok(had_matches)
            });
        }

        let reader = BufReader::new(io::stdin().lock());
        fp.process_stdin_streaming(reader, output_path)
    }

    fn process_stdin_streaming<R: io::Read>(
        self,
        reader: BufReader<R>,
        output_path: Option<&Path>,
    ) -> Result<bool, String> {
        let cli = self.cli;
        let fp = self;
        let output_path = if output_path.is_some_and(|p| p == Path::new("-")) {
            None
        } else {
            output_path
        };
        let label = if cli.dry_run {
            "Scanning stdin (dry-run)"
        } else {
            "Scanning stdin"
        };
        let entropy_active = !fp.entropy_configs.is_empty();

        with_progress_scope(fp.progress, label, move |progress| {
            let mut had_matches = false;

            if cli.dry_run {
                let (stats, locs, locs_truncated) = if entropy_active {
                    let mut buf: Vec<u8> = Vec::new();
                    let (mut s, locs, tr) = scan_with_locations(
                        fp.scanner,
                        reader,
                        &mut buf,
                        None,
                        make_scan_callback(progress.clone(), label),
                        cli.max_match_locations,
                    )?;
                    let (_ent_out, ent_lc) = entropy_scan_bytes(&buf, fp.entropy_configs, fp.store);
                    merge_entropy_counts(&mut s, ent_lc);
                    if let Some(acc) = fp.entropy_histogram_acc {
                        accumulate_entropy_histogram(acc, &buf, fp.entropy_configs);
                    }
                    (s, locs, tr)
                } else {
                    let (s, locs, tr) = scan_with_locations(
                        fp.scanner,
                        reader,
                        io::sink(),
                        None,
                        make_scan_callback(progress.clone(), label),
                        cli.max_match_locations,
                    )?;
                    (s, locs, tr)
                };
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                info!(
                    matches = stats.matches_found,
                    replacements = stats.replacements_applied,
                    "dry-run complete"
                );
                return Ok(had_matches);
            }

            let needs_buffer = cli.extract_context || fp.llm_collector.is_some() || entropy_active;

            if let Some(out_path) = output_path {
                if needs_buffer {
                    let mut buf: Vec<u8> = Vec::new();
                    let (mut stats, locs, locs_truncated) = scan_with_locations(
                        fp.scanner,
                        reader,
                        &mut buf,
                        None,
                        make_scan_callback(progress.clone(), label),
                        cli.max_match_locations,
                    )?;
                    if crate::is_interrupted() {
                        return Err("interrupted — partial output discarded".into());
                    }
                    if entropy_active {
                        let (ent_out, ent_lc) =
                            entropy_scan_bytes(&buf, fp.entropy_configs, fp.store);
                        buf = ent_out;
                        merge_entropy_counts(&mut stats, ent_lc);
                    }
                    if stats.matches_found > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = fp.report_builder {
                        rb.record_file(
                            FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                                .with_match_locations(locs, locs_truncated),
                        );
                    }
                    maybe_extract_context(&buf, "<stdin>", cli, fp.report_builder);
                    if let Some(c) = fp.llm_collector {
                        maybe_collect_for_llm(&buf, "<stdin>", Some(c));
                    } else {
                        atomic_write(out_path, &buf)
                            .map_err(|e| format!("failed to write {}: {e}", out_path.display()))?;
                        info!(output = %out_path.display(), "output written");
                    }
                } else {
                    let mut atomic_writer = AtomicFileWriter::new(out_path)
                        .map_err(|e| format!("failed to create output: {e}"))?;

                    let (stats, locs, locs_truncated) = scan_with_locations(
                        fp.scanner,
                        reader,
                        &mut atomic_writer,
                        None,
                        make_scan_callback(progress.clone(), label),
                        cli.max_match_locations,
                    )?;

                    if crate::is_interrupted() {
                        return Err("interrupted — partial output discarded".into());
                    }

                    atomic_writer
                        .finish()
                        .map_err(|e| format!("failed to finalize output: {e}"))?;

                    if stats.matches_found > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = fp.report_builder {
                        rb.record_file(
                            FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                                .with_match_locations(locs, locs_truncated),
                        );
                    }
                }
            } else if needs_buffer {
                let mut buf: Vec<u8> = Vec::new();
                let (mut stats, locs, locs_truncated) = scan_with_locations(
                    fp.scanner,
                    reader,
                    &mut buf,
                    None,
                    make_scan_callback(progress.clone(), label),
                    cli.max_match_locations,
                )?;
                if entropy_active {
                    let (ent_out, ent_lc) = entropy_scan_bytes(&buf, fp.entropy_configs, fp.store);
                    buf = ent_out;
                    merge_entropy_counts(&mut stats, ent_lc);
                }
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context(&buf, "<stdin>", cli, fp.report_builder);
                if let Some(c) = fp.llm_collector {
                    maybe_collect_for_llm(&buf, "<stdin>", Some(c));
                } else {
                    if let Some(p) = progress {
                        p.lock().expect("progress reporter lock").clear_live_line();
                    }
                    let stdout = io::stdout();
                    stdout
                        .lock()
                        .write_all(&buf)
                        .map_err(|e| format!("failed to write to stdout: {e}"))?;
                }
            } else {
                if let Some(ref p) = progress {
                    p.lock().expect("progress reporter lock").clear_live_line();
                }
                let stdout = io::stdout();
                let writer = BufWriter::new(stdout.lock());
                let (stats, locs, locs_truncated) = scan_with_locations(
                    fp.scanner,
                    reader,
                    writer,
                    None,
                    make_scan_callback(progress.clone(), label),
                    cli.max_match_locations,
                )?;
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                            .with_match_locations(locs, locs_truncated),
                    );
                }
            }

            Ok(had_matches)
        })
    }

    /// Process a plain (non-archive) file. Returns `true` if matches were found.
    pub(crate) fn process_plain_file(self, input: &Path, output_path: Option<&Path>) -> Result<bool, String> {
        let cli = self.cli;
        let fp = self;
    let mut sample = [0u8; 512];
    let sample_len = {
        let mut f = fs::File::open(input)
            .map_err(|e| format!("failed to open {}: {e}", input.display()))?;
        io::Read::read(&mut f, &mut sample)
            .map_err(|e| format!("failed to read {}: {e}", input.display()))?
    };
    if !cli.include_binary && looks_binary(&sample[..sample_len]) {
        let file_size = sample_len as u64;
        warn!(
            file = %input.display(),
            bytes = file_size,
            "skipping binary file — use --include-binary to process it"
        );
        return Ok(false);
    }

    let filename = if let Some(ref fmt) = cli.format {
        format_to_ext(fmt)
            .map(|ext| format!("override.{ext}"))
            .unwrap_or_default()
    } else {
        input
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string()
    };

    let structured_ext = matches!(
        filename.rsplit('.').next().unwrap_or(""),
        "json"
            | "jsonl"
            | "ndjson"
            | "yaml"
            | "yml"
            | "xml"
            | "csv"
            | "tsv"
            | "rb"
            | "conf"
            | "cfg"
            | "ini"
            | "env"
            | "properties"
            | "toml"
    ) || {
        filename
            .rsplit('/')
            .next()
            .unwrap_or(&filename)
            .starts_with(".env")
    };

    let output_path = if output_path.is_some_and(|p| p == Path::new("-")) {
        None
    } else {
        output_path
    };

    let mut had_matches = false;

    if structured_ext && !cli.force_text {
        let file_meta =
            fs::metadata(input).map_err(|e| format!("failed to stat {}: {e}", input.display()))?;
        let file_size = file_meta.len();

        let maybe_streaming = fp.profiles
            .iter()
            .find(|p| p.matches_filename(&filename))
            .and_then(|p| {
                fp.registry
                    .get(&p.processor)
                    .filter(|proc| proc.supports_streaming())
                    .map(|proc| (p.clone(), Arc::clone(proc)))
            });

        if let Some((streaming_profile, streaming_proc)) = maybe_streaming {
            let store_snapshot = fp.store.snapshot();
            {
                let mut reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                streaming_proc
                    .process_stream(&mut reader, &mut io::sink(), &streaming_profile, fp.store)
                    .map_err(|e| {
                        format!("structured pass 1 failed for {}: {e}", input.display())
                    })?;
            }
            let per_file_scanner = Arc::new(
                build_format_preserving_scanner(fp.scanner, fp.store, store_snapshot)
                    .map_err(|e| format!("failed to build per-file scanner: {e}"))?,
            );
            let ext = filename.rsplit('.').next().unwrap_or("unknown");
            let method = format!("structured+scan:{ext}");
            let sz = file_size;

            if cli.dry_run {
                let label = format!("Scanning {} (dry-run)", input.display());
                let progress_label = label.clone();
                return with_progress_scope(fp.progress, &label, move |progress| {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                    );
                    let (stats, locs, locs_truncated) = scan_with_locations(
                        &per_file_scanner,
                        reader,
                        io::sink(),
                        Some(sz),
                        make_scan_callback(progress.clone(), &progress_label),
                        cli.max_match_locations,
                    )?;
                    if stats.matches_found > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = fp.report_builder {
                        rb.record_file(
                            FileReport::from_scan_stats(
                                input.display().to_string(),
                                &stats,
                                &method,
                            )
                            .with_match_locations(locs, locs_truncated),
                        );
                    }
                    info!(
                        matches = stats.matches_found,
                        replacements = stats.replacements_applied,
                        "dry-run complete"
                    );
                    Ok(had_matches)
                });
            } else if let Some(out_path) = output_path {
                let label = format!("Scanning {}", input.display());
                let progress_label = label.clone();
                let llm_opt = fp.llm_collector.cloned();
                return with_progress_scope(fp.progress, &label, move |progress| {
                    if llm_opt.is_some() {
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let mut buf: Vec<u8> = Vec::new();
                        let (stats, locs, locs_truncated) = scan_with_locations(
                            &per_file_scanner,
                            reader,
                            &mut buf,
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                            cli.max_match_locations,
                        )?;
                        if crate::is_interrupted() {
                            return Err("interrupted — partial output discarded".into());
                        }
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = fp.report_builder {
                            rb.record_file(
                                FileReport::from_scan_stats(
                                    input.display().to_string(),
                                    &stats,
                                    &method,
                                )
                                .with_match_locations(locs, locs_truncated),
                            );
                        }
                        maybe_extract_context(
                            &buf,
                            &input.display().to_string(),
                            cli,
                            fp.report_builder,
                        );
                        maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                    } else {
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let mut atomic_writer = AtomicFileWriter::new(out_path)
                            .map_err(|e| format!("failed to create output: {e}"))?;
                        let (stats, locs, locs_truncated) = scan_with_locations(
                            &per_file_scanner,
                            reader,
                            &mut atomic_writer,
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                            cli.max_match_locations,
                        )?;
                        if crate::is_interrupted() {
                            return Err("interrupted — partial output discarded".into());
                        }
                        atomic_writer
                            .finish()
                            .map_err(|e| format!("failed to finalize output: {e}"))?;
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = fp.report_builder {
                            rb.record_file(
                                FileReport::from_scan_stats(
                                    input.display().to_string(),
                                    &stats,
                                    &method,
                                )
                                .with_match_locations(locs, locs_truncated),
                            );
                        }
                        maybe_extract_context_reader(
                            out_path,
                            &input.display().to_string(),
                            cli,
                            fp.report_builder,
                        );
                    }
                    Ok(had_matches)
                });
            } else {
                let label = format!("Scanning {}", input.display());
                let progress_label = label.clone();
                let llm_opt = fp.llm_collector.cloned();
                return with_progress_scope(fp.progress, &label, move |progress| {
                    let needs_buffer = (cli.extract_context || llm_opt.is_some())
                        && sz <= MAX_CONTEXT_BUFFER_BYTES;
                    if needs_buffer {
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let mut buf: Vec<u8> = Vec::new();
                        let (stats, locs, locs_truncated) = scan_with_locations(
                            &per_file_scanner,
                            reader,
                            &mut buf,
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                            cli.max_match_locations,
                        )?;
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = fp.report_builder {
                            rb.record_file(
                                FileReport::from_scan_stats(
                                    input.display().to_string(),
                                    &stats,
                                    &method,
                                )
                                .with_match_locations(locs, locs_truncated),
                            );
                        }
                        maybe_extract_context(
                            &buf,
                            &input.display().to_string(),
                            cli,
                            fp.report_builder,
                        );
                        if llm_opt.is_some() {
                            maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                        } else {
                            let stdout = io::stdout();
                            stdout
                                .lock()
                                .write_all(&buf)
                                .map_err(|e| format!("failed to write to stdout: {e}"))?;
                        }
                    } else {
                        if cli.extract_context {
                            warn!(
                                file = %input.display(),
                                size = sz,
                                max = MAX_CONTEXT_BUFFER_BYTES,
                                "--extract-context: file too large to buffer for stdout; \
                                 use -o/--output to write to a file for context extraction"
                            );
                        }
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let stdout = io::stdout();
                        let writer = BufWriter::new(stdout.lock());
                        let (stats, locs, locs_truncated) = scan_with_locations(
                            &per_file_scanner,
                            reader,
                            writer,
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                            cli.max_match_locations,
                        )?;
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = fp.report_builder {
                            rb.record_file(
                                FileReport::from_scan_stats(
                                    input.display().to_string(),
                                    &stats,
                                    &method,
                                )
                                .with_match_locations(locs, locs_truncated),
                            );
                        }
                    }
                    Ok(had_matches)
                });
            }
        }

        if file_size > cli.max_structured_size {
            warn!(
                file = %input.display(),
                size = file_size,
                max = cli.max_structured_size,
                "structured file exceeds size limit, falling back to streaming scanner"
            );
        } else {
            let input_bytes =
                fs::read(input).map_err(|e| format!("failed to read {}: {e}", input.display()))?;

            let store_len_before = fp.store.len();
            let store_snapshot = fp.store.snapshot();

            let label = format!("Processing structured {}", input.display());
            return with_progress_scope(fp.progress, &label, move |_| {
                let structured_result =
                    try_structured_processing(&input_bytes, &filename, fp.registry, fp.store, fp.profiles);

                let (output_bytes, method, _was_structured, fallback_stats) =
                    match structured_result {
                        Some(Ok(_structured_bytes)) => {
                            let ext = filename.rsplit('.').next().unwrap_or("unknown");
                            let per_file_scanner =
                                build_format_preserving_scanner(fp.scanner, fp.store, store_snapshot)
                                    .map_err(|e| {
                                        format!("failed to build per-file scanner: {e}")
                                    })?;
                            let (scanned_bytes, scan_stats) =
                                scanner_fallback(&per_file_scanner, &input_bytes)?;
                            (
                                scanned_bytes,
                                format!("structured+scan:{ext}"),
                                true,
                                Some(scan_stats),
                            )
                        }
                        Some(Err(e)) => {
                            if cli.strict {
                                return Err(format!("structured processing failed: {e}"));
                            }
                            warn!(error = %e, "structured processing failed, falling back to scanner");
                            let (out, stats) = scanner_fallback(fp.scanner, &input_bytes)?;
                            (out, "scanner".into(), false, Some(stats))
                        }
                        None => {
                            let (out, stats) = scanner_fallback(fp.scanner, &input_bytes)?;
                            (out, "scanner".into(), false, Some(stats))
                        }
                    };

                let (output_bytes, fallback_stats) = {
                    let (ent_out, ent_lc) =
                        entropy_scan_bytes(&output_bytes, fp.entropy_configs, fp.store);
                    let stats = fallback_stats.map(|mut s| {
                        merge_entropy_counts(&mut s, ent_lc);
                        s
                    });
                    (ent_out, stats)
                };

                if cli.dry_run || fp.report_builder.is_some() || cli.fail_on_match {
                    let _ = store_len_before;
                    let replacements = fallback_stats
                        .as_ref()
                        .map_or(0, |s| s.replacements_applied);

                    if replacements > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = fp.report_builder {
                        let stats = fallback_stats
                            .map(|mut s| {
                                s.matches_found = replacements;
                                s.replacements_applied = replacements;
                                s.bytes_processed = input_bytes.len() as u64;
                                s.bytes_output = output_bytes.len() as u64;
                                s
                            })
                            .unwrap_or_else(|| ScanStats {
                                matches_found: replacements,
                                replacements_applied: replacements,
                                bytes_processed: input_bytes.len() as u64,
                                bytes_output: output_bytes.len() as u64,
                                ..Default::default()
                            });
                        rb.record_file(FileReport::from_scan_stats(
                            input.display().to_string(),
                            &stats,
                            method,
                        ));
                    }
                    if cli.dry_run {
                        info!(
                            matches = replacements,
                            replacements = replacements,
                            "dry-run complete"
                        );
                        return Ok(had_matches);
                    }
                }
                maybe_extract_context(
                    &output_bytes,
                    &input.display().to_string(),
                    cli,
                    fp.report_builder,
                );
                write_or_collect(
                    &output_bytes,
                    &input.display().to_string(),
                    output_path,
                    fp.llm_collector,
                )?;
                Ok(had_matches)
            });
        }
    }

    let method = "scanner";
    let entropy_active = !fp.entropy_configs.is_empty();

    if cli.dry_run {
        let label = format!("Scanning {} (dry-run)", input.display());
        let progress_label = label.clone();
        let ent_cfgs = Arc::clone(fp.entropy_configs);
        let store_arc = Arc::clone(fp.store);
        with_progress_scope(fp.progress, &label, move |progress| {
            let reader = BufReader::new(
                fs::File::open(input)
                    .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
            );
            let progress_for_scan = progress.clone();
            let sz = file_size(input)?;
            let (stats, locs, locs_truncated) = if entropy_active {
                let mut buf: Vec<u8> = Vec::new();
                let (mut s, locs, tr) = scan_with_locations(
                    fp.scanner,
                    reader,
                    &mut buf,
                    Some(sz),
                    make_scan_callback(progress_for_scan, &progress_label),
                    cli.max_match_locations,
                )?;
                let (_ent_out, ent_lc) = entropy_scan_bytes(&buf, &ent_cfgs, &store_arc);
                merge_entropy_counts(&mut s, ent_lc);
                if let Some(acc) = fp.entropy_histogram_acc {
                    accumulate_entropy_histogram(acc, &buf, &ent_cfgs);
                }
                (s, locs, tr)
            } else {
                scan_with_locations(
                    fp.scanner,
                    reader,
                    io::sink(),
                    Some(sz),
                    make_scan_callback(progress_for_scan, &progress_label),
                    cli.max_match_locations,
                )?
            };
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = fp.report_builder {
                rb.record_file(
                    FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                        .with_match_locations(locs, locs_truncated),
                );
            }
            info!(
                matches = stats.matches_found,
                replacements = stats.replacements_applied,
                "dry-run complete"
            );
            Ok(had_matches)
        })
    } else if let Some(out_path) = output_path {
        let label = format!("Scanning {}", input.display());
        let progress_label = label.clone();
        let llm_opt = fp.llm_collector.cloned();
        let ent_cfgs = Arc::clone(fp.entropy_configs);
        let store_arc = Arc::clone(fp.store);
        with_progress_scope(fp.progress, &label, move |progress| {
            if llm_opt.is_some() || entropy_active {
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut buf: Vec<u8> = Vec::new();
                let progress_for_scan = progress.clone();
                let (mut stats, locs, locs_truncated) = scan_with_locations(
                    fp.scanner,
                    reader,
                    &mut buf,
                    Some(file_size(input)?),
                    make_scan_callback(progress_for_scan, &progress_label),
                    cli.max_match_locations,
                )?;
                if crate::is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                if entropy_active {
                    let (ent_out, ent_lc) = entropy_scan_bytes(&buf, &ent_cfgs, &store_arc);
                    buf = ent_out;
                    merge_entropy_counts(&mut stats, ent_lc);
                }
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context(&buf, &input.display().to_string(), cli, fp.report_builder);
                if llm_opt.is_some() {
                    maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                } else {
                    atomic_write(out_path, &buf)
                        .map_err(|e| format!("failed to write output: {e}"))?;
                }
            } else {
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(out_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;

                let progress_for_scan = progress.clone();
                let (stats, locs, locs_truncated) = scan_with_locations(
                    fp.scanner,
                    reader,
                    &mut atomic_writer,
                    Some(file_size(input)?),
                    make_scan_callback(progress_for_scan, &progress_label),
                    cli.max_match_locations,
                )?;

                if crate::is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }

                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;

                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context_reader(
                    out_path,
                    &input.display().to_string(),
                    cli,
                    fp.report_builder,
                );
            }
            Ok(had_matches)
        })
    } else {
        let label = format!("Scanning {}", input.display());
        let progress_label = label.clone();
        let llm_opt = fp.llm_collector.cloned();
        let ent_cfgs = Arc::clone(fp.entropy_configs);
        let store_arc = Arc::clone(fp.store);
        with_progress_scope(fp.progress, &label, move |progress| {
            let sz = file_size(input)?;
            let needs_buffer = (cli.extract_context || llm_opt.is_some() || entropy_active)
                && sz <= MAX_CONTEXT_BUFFER_BYTES;
            if needs_buffer {
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut buf: Vec<u8> = Vec::new();
                let progress_for_scan = progress.clone();
                let (mut stats, locs, locs_truncated) = scan_with_locations(
                    fp.scanner,
                    reader,
                    &mut buf,
                    Some(sz),
                    make_scan_callback(progress_for_scan, &progress_label),
                    cli.max_match_locations,
                )?;
                if entropy_active {
                    let (ent_out, ent_lc) = entropy_scan_bytes(&buf, &ent_cfgs, &store_arc);
                    buf = ent_out;
                    merge_entropy_counts(&mut stats, ent_lc);
                }
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context(&buf, &input.display().to_string(), cli, fp.report_builder);
                if llm_opt.is_some() {
                    maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                } else {
                    let stdout = io::stdout();
                    stdout
                        .lock()
                        .write_all(&buf)
                        .map_err(|e| format!("failed to write to stdout: {e}"))?;
                }
            } else {
                if cli.extract_context {
                    warn!(
                        file = %input.display(),
                        size = sz,
                        max = MAX_CONTEXT_BUFFER_BYTES,
                        "--extract-context: file too large to buffer for stdout; \
                         use -o/--output to write to a file for context extraction"
                    );
                }
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let stdout = io::stdout();
                let writer = BufWriter::new(stdout.lock());
                let progress_for_scan = progress.clone();
                let (stats, locs, locs_truncated) = scan_with_locations(
                    fp.scanner,
                    reader,
                    writer,
                    Some(sz),
                    make_scan_callback(progress_for_scan, &progress_label),
                    cli.max_match_locations,
                )?;
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
            }
            Ok(had_matches)
        })
    }
}

    /// Process an archive file. Returns `true` if entries were processed.
    pub(crate) fn process_archive(
        self,
        input: &Path,
        output_path: &Path,
        format: ArchiveFormat,
        filter: ArchiveFilter,
        suppress_inner_parallelism: bool,
    ) -> Result<bool, String> {
        let cli = self.cli;
        let fp = self;
        let label = format!("Processing archive {}", input.display());
        let label_inner = label.clone();

        let filter_active = !filter.is_empty();
        with_progress_scope(fp.progress, &label, move |progress| {
            let label = label_inner;
        let context_map: Option<Arc<Mutex<HashMap<String, LogContextResult>>>> =
            if cli.extract_context && fp.report_builder.is_some() {
                Some(Arc::new(Mutex::new(HashMap::new())))
            } else {
                None
            };

            let base_proc = ArchiveProcessor::new(
                Arc::clone(fp.registry),
                Arc::clone(fp.scanner),
                Arc::clone(fp.store),
                fp.profiles.to_vec(),
            )
        .with_max_depth(cli.max_archive_depth)
        .with_force_text(cli.force_text)
        .with_filter(filter);

        let base_proc = if suppress_inner_parallelism {
            base_proc.with_parallel_threshold(usize::MAX)
        } else {
            base_proc
        };

        let base_proc = if let Some(ctx_map) = &context_map {
            let ctx_map = Arc::clone(ctx_map);
            let config = build_log_context_config(cli);
            let cb: EntryCallback = Arc::new(move |name: &str, bytes: &[u8]| {
                let text = String::from_utf8_lossy(bytes);
                let result = extract_context(&text, &config);
                if let Ok(mut map) = ctx_map.lock() {
                    map.insert(name.to_string(), result);
                }
            });
            base_proc.with_entry_callback(cb)
        } else {
            base_proc
        };

        let archive_proc = if let Some(progress) = &progress {
            let label = label.clone();
            let progress = Arc::clone(progress);
            base_proc.with_progress_callback(Arc::new(move |archive_progress: &ArchiveProgress| {
                progress
                    .lock()
                    .expect("progress lock poisoned")
                    .update_archive(&label, archive_progress);
            }))
        } else {
            base_proc
        };

        if cli.dry_run {
            let stats = match format {
                ArchiveFormat::Tar => {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    archive_proc
                        .process_tar(reader, io::sink())
                        .map_err(|e| format!("archive error: {e}"))?
                }
                ArchiveFormat::TarGz => {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    archive_proc
                        .process_tar_gz(reader, io::sink())
                        .map_err(|e| format!("archive error: {e}"))?
                }
                ArchiveFormat::Zip => {
                    let mut reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    let mut null_out = NullSeekWriter { pos: 0, len: 0 };
                    archive_proc
                        .process_zip(&mut reader, &mut null_out)
                        .map_err(|e| format!("archive error: {e}"))?
                }
            };

            if let Some(rb) = fp.report_builder {
                record_archive_stats(rb, &stats);
            }

            info!(
                files = stats.files_processed,
                structured = stats.structured_hits,
                scanner = stats.scanner_fallback,
                "dry-run archive processing complete"
            );

            return Ok(stats.files_processed > 0);
        }

        let stats = match format {
            ArchiveFormat::Tar => {
                let reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open input: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_tar(reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if crate::is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
            ArchiveFormat::TarGz => {
                let reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open input: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_tar_gz(reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if crate::is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
            ArchiveFormat::Zip => {
                let mut reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open archive: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_zip(&mut reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if crate::is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
        };

            if let Some(rb) = fp.report_builder {
                record_archive_stats(rb, &stats);
                if let Some(ctx_map) = context_map {
                    if let Ok(map) = ctx_map.lock() {
                        for (path, result) in map.iter() {
                            rb.set_file_log_context(path, result.clone());
                        }
                    }
                }
            }
            print_archive_stats(output_path, &stats);

            if filter_active && stats.files_processed == 0 && stats.entries_filtered > 0 {
                warn!(
                    archive = %input.display(),
                    filtered = stats.entries_filtered,
                    "no archive entries matched the --only/--exclude filter — output archive is empty"
                );
            }

            Ok(stats.files_processed > 0)
        })
    }
} // impl FileProcessor

#[cfg(test)]
mod tests {
    use super::*;
    use sanitize_engine::{MappingStore, RandomGenerator};
    use std::sync::Arc;

    fn empty_store() -> Arc<MappingStore> {
        Arc::new(MappingStore::new(Arc::new(RandomGenerator::new()), None))
    }

    fn store_with_entry(original: &str) -> Arc<MappingStore> {
        let store = empty_store();
        store.get_or_insert(&sanitize_engine::Category::AuthToken, original).unwrap();
        store
    }

    // ── save_discovered_secrets ──────────────────────────────────────────────

    #[test]
    fn save_discovered_secrets_empty_store_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.yaml");
        let n = save_discovered_secrets(&empty_store(), &path).unwrap();
        assert_eq!(n, 0);
        assert!(!path.exists(), "no file should be created when store is empty");
    }

    #[test]
    fn save_discovered_secrets_writes_new_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.yaml");
        let store = store_with_entry("abc123");

        let n = save_discovered_secrets(&store, &path).unwrap();
        assert_eq!(n, 1);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("abc123"), "written file should contain the literal value");
        assert!(content.contains("literal"), "entry kind should be 'literal'");
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
        assert!(result.is_err(), "malformed YAML should return an error, not silently lose data");
    }
}
