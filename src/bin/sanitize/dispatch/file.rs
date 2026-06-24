//! Plain-file and structured-file dispatch for `FileProcessor`.

use super::*;

/// Resolve the effective filename used for format detection of a *file* input.
///
/// A file whose own name already maps to a structured format keeps that format;
/// `--format` only fills in for inputs that aren't otherwise typeable (e.g. an
/// extensionless file, or a `.txt` that is really JSON). This prevents
/// `--format` — which a piped stdin *requires* — from silently forcing an
/// accompanying `.yaml`/`.csv`/… file to be parsed as the stdin format, which
/// would produce no structured edits and leak that file's escaped values.
fn effective_file_format_name(input: &Path, cli_format: Option<&str>) -> String {
    // The full path (not just the basename) so profile `include` globs with a
    // path component — `group_vars/*.yml`, `.aws/credentials`,
    // `.circleci/config.yml` — match here exactly as they do in the phase
    // partition (which uses `input.to_string_lossy()`). Extension detection
    // (`rsplit('.')`) and `is_structured_filename` work the same on a path, so
    // using the full path is strictly more permissive for matching without
    // changing format detection. (Previously this returned only the basename,
    // which silently dropped every path-anchored profile to the plain scanner.)
    let real = input.to_string_lossy().to_string();
    if is_structured_filename(&real) {
        return real;
    }
    match cli_format {
        Some(fmt) => format_to_ext(fmt)
            .map(|ext| format!("override.{ext}"))
            .unwrap_or(real),
        None => real,
    }
}

/// Label under which in-place structured field redactions are counted in the
/// run summary. They cannot be attributed per-category at this layer (the span
/// `Replacement` carries only byte offsets), so they share one honest bucket;
/// the scanner's own matches keep their per-pattern labels.
const FIELD_EDIT_LABEL: &str = "profile-field";

/// Fold `count` in-place structured field edits into `stats` so they appear in
/// `total_matches` and the run summary. No-op when `count == 0`.
fn record_field_edits(stats: &mut rust_sanitize::scanner::ScanStats, count: usize) {
    if count == 0 {
        return;
    }
    let count = count as u64;
    stats.matches_found += count;
    stats.replacements_applied += count;
    *stats
        .pattern_counts
        .entry(FIELD_EDIT_LABEL.to_string())
        .or_insert(0) += count;
}

impl FileProcessor<'_> {
    /// Process a plain (non-archive) file. Returns `true` if matches were found.
    pub(crate) fn process_plain_file(
        self,
        input: &Path,
        output_path: Option<&Path>,
    ) -> Result<bool, String> {
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
            warn!(
                file = %input.display(),
                bytes = sample_len,
                "skipping binary file — use --include-binary to process it"
            );
            return Ok(false);
        }

        let filename = effective_file_format_name(input, cli.format.as_deref());

        // Structured-eligible if the extension is inherently structured OR a
        // loaded profile explicitly targets this file (e.g. a bundle declaring
        // `extensions: [".log"]` for JSON/JSONL logs). Without the profile check,
        // a profile's custom extension would be silently dropped to the scanner.
        let structured_ext = is_structured_filename(&filename)
            || fp.profiles.iter().any(|p| p.matches_filename(&filename));

        let output_path = if output_path.is_some_and(|p| p == Path::new("-")) {
            None
        } else {
            output_path
        };

        if structured_ext && !cli.force_text {
            let file_size = fs::metadata(input)
                .map_err(|e| format!("failed to stat {}: {e}", input.display()))?
                .len();

            // Within the size cap, use the buffered path, which prefers
            // span-based edit mode (leak-free + format-preserving). This applies
            // even to streaming-capable processors (e.g. JSONL) so normal-size
            // files get exact edits; only oversized files fall back to the
            // bounded-memory streaming path (literal redaction).
            if file_size <= cli.max_structured_size {
                return fp.process_buffered_structured(input, output_path, &filename);
            }

            let maybe_streaming = fp
                .profiles
                .iter()
                .find(|p| p.matches_filename(&filename))
                .and_then(|p| {
                    fp.registry
                        .get(&p.processor)
                        .filter(|proc| proc.supports_streaming())
                        .map(|proc| (p.clone(), Arc::clone(proc)))
                });

            if let Some((streaming_profile, streaming_proc)) = maybe_streaming {
                return fp.process_streaming_structured(
                    input,
                    output_path,
                    streaming_profile,
                    streaming_proc,
                    file_size,
                    &filename,
                );
            }

            warn!(
                file = %input.display(),
                size = file_size,
                max = cli.max_structured_size,
                "structured file exceeds size limit, falling back to streaming scanner"
            );
        }

        fp.scan_plain_scanner(input, output_path)
    }

    /// Discovery pre-pass for a structured plain file: populate the mapping
    /// store with the file's structured field values **without** writing any
    /// output. Running this over every structured input before the output pass
    /// lets the augmented and format-preserving scanners redact those values
    /// across all files, independent of input order.
    ///
    /// Non-structured files, binaries, and files too large for buffered
    /// structured parsing are skipped here — they carry no field literals to
    /// seed, and any base-pattern matches in them are caught during the output
    /// pass (regexes match the same value in every file regardless).
    pub(crate) fn discover_plain_file(self, input: &Path) -> Result<(), String> {
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
            return Ok(());
        }

        let filename = effective_file_format_name(input, cli.format.as_deref());

        // Mirror the output pass: a file is structured-eligible if its extension
        // is structured OR a loaded profile explicitly targets it (custom
        // extensions like `.log`). Keeps discovery and output in agreement.
        let structured = is_structured_filename(&filename)
            || fp.profiles.iter().any(|p| p.matches_filename(&filename));
        if !structured || cli.force_text {
            return Ok(());
        }

        // Streaming processors discover by streaming to a sink.
        let maybe_streaming = fp
            .profiles
            .iter()
            .find(|p| p.matches_filename(&filename))
            .and_then(|p| {
                fp.registry
                    .get(&p.processor)
                    .filter(|proc| proc.supports_streaming())
                    .map(|proc| (p.clone(), Arc::clone(proc)))
            });

        if let Some((profile, proc)) = maybe_streaming {
            let mut reader = BufReader::new(
                fs::File::open(input)
                    .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
            );
            proc.process_stream(&mut reader, &mut io::sink(), &profile, fp.store)
                .map_err(|e| format!("structured discovery failed for {}: {e}", input.display()))?;
            return Ok(());
        }

        let file_size = fs::metadata(input)
            .map_err(|e| format!("failed to stat {}: {e}", input.display()))?
            .len();
        if file_size > cli.max_structured_size {
            return Ok(());
        }

        let input_bytes =
            fs::read(input).map_err(|e| format!("failed to read {}: {e}", input.display()))?;
        // Populate the store as a side effect; the produced bytes/edits are
        // discarded. Prefer edit mode so discovery handles the same inputs the
        // output pass does (multi-document YAML, source-escaped values); fall
        // back to the literal structured pass for processors without span edits.
        let discovery = match try_structured_edits(
            &input_bytes,
            &filename,
            fp.registry,
            fp.store,
            fp.profiles,
        ) {
            // Discovery discards the produced bytes and edit count; only the
            // store side effect and any error matter here.
            Some(Ok((v, _count))) => Some(Ok(v)),
            // Strict mode surfaces the edit-pass error. Otherwise fall back
            // to the literal structured pass so the file's field values
            // still populate the shared store — mirroring the output path
            // (`structured_base_bytes`). Without this, a value the strict
            // span parser rejects but the legacy parser accepts is never
            // discovered, the augmented scanner is built without it, and the
            // same value leaks from *another* file (comment / plain text /
            // unmatched field).
            Some(Err(e)) if cli.strict => Some(Err(e)),
            Some(Err(e)) => {
                warn!(error = %e, file = %input.display(), "structured edit pass failed during discovery, trying literal pass");
                try_structured_processing(
                    &input_bytes,
                    &filename,
                    fp.registry,
                    fp.store,
                    fp.profiles,
                )
            }
            None => try_structured_processing(
                &input_bytes,
                &filename,
                fp.registry,
                fp.store,
                fp.profiles,
            ),
        };
        if let Some(Err(e)) = discovery {
            if cli.strict {
                return Err(format!(
                    "structured discovery failed for {}: {e}",
                    input.display()
                ));
            }
            warn!(error = %e, file = %input.display(), "structured discovery failed; continuing");
        }
        Ok(())
    }

    fn process_streaming_structured(
        self,
        input: &Path,
        output_path: Option<&Path>,
        streaming_profile: FileTypeProfile,
        streaming_proc: Arc<dyn Processor>,
        file_size: u64,
        filename: &str,
    ) -> Result<bool, String> {
        let cli = self.cli;
        let fp = self;
        let mut had_matches = false;

        let store_snapshot = if fp.full_store_pass {
            rust_sanitize::store::StoreSnapshot::start()
        } else {
            fp.store.snapshot()
        };
        {
            let mut reader = BufReader::new(
                fs::File::open(input)
                    .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
            );
            streaming_proc
                .process_stream(&mut reader, &mut io::sink(), &streaming_profile, fp.store)
                .map_err(|e| format!("structured pass 1 failed for {}: {e}", input.display()))?;
        }
        let per_file_scanner = Arc::new(
            build_format_preserving_scanner(fp.scanner, fp.store, store_snapshot)
                .map_err(|e| format!("failed to build per-file scanner: {e}"))?,
        );
        let ext = filename.rsplit('.').next().unwrap_or("unknown");
        let method = format!("structured+scan:{ext}");

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
                    Some(file_size),
                    make_scan_callback(progress.clone(), &progress_label),
                    cli.max_match_locations,
                )?;
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, &method)
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
        }

        if let Some(out_path) = output_path {
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
                        Some(file_size),
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
                        Some(file_size),
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
        }

        // stdout path
        let label = format!("Scanning {}", input.display());
        let progress_label = label.clone();
        let llm_opt = fp.llm_collector.cloned();
        with_progress_scope(fp.progress, &label, move |progress| {
            let needs_buffer =
                (cli.extract_context || llm_opt.is_some()) && file_size <= MAX_CONTEXT_BUFFER_BYTES;
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
                    Some(file_size),
                    make_scan_callback(progress.clone(), &progress_label),
                    cli.max_match_locations,
                )?;
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, &method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context(&buf, &input.display().to_string(), cli, fp.report_builder);
                if llm_opt.is_some() {
                    maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                } else {
                    io::stdout()
                        .lock()
                        .write_all(&buf)
                        .map_err(|e| format!("failed to write to stdout: {e}"))?;
                }
            } else {
                if cli.extract_context {
                    warn!(
                        file = %input.display(),
                        size = file_size,
                        max = MAX_CONTEXT_BUFFER_BYTES,
                        "--extract-context: file too large to buffer for stdout; \
                         use -o/--output to write to a file for context extraction"
                    );
                }
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let writer = BufWriter::new(io::stdout().lock());
                let (stats, locs, locs_truncated) = scan_with_locations(
                    &per_file_scanner,
                    reader,
                    writer,
                    Some(file_size),
                    make_scan_callback(progress.clone(), &progress_label),
                    cli.max_match_locations,
                )?;
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = fp.report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, &method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
            }
            Ok(had_matches)
        })
    }

    fn process_buffered_structured(
        self,
        input: &Path,
        output_path: Option<&Path>,
        filename: &str,
    ) -> Result<bool, String> {
        let cli = self.cli;
        let fp = self;

        let input_bytes =
            fs::read(input).map_err(|e| format!("failed to read {}: {e}", input.display()))?;
        let store_snapshot = if fp.full_store_pass {
            rust_sanitize::store::StoreSnapshot::start()
        } else {
            fp.store.snapshot()
        };

        let label = format!("Processing structured {}", input.display());
        with_progress_scope(fp.progress, &label, move |_| {
            // Prefer span-based edit mode (exact, format-preserving, leak-free);
            // fall back to the literal structured pass, then to the plain scanner.
            let structured_base = structured_base_bytes(&input_bytes, filename, &fp, cli.strict)?;

            let (output_bytes, method, fallback_stats, field_edits) = match structured_base {
                Some((base, edit_count)) => {
                    let ext = filename.rsplit('.').next().unwrap_or("unknown");
                    let per_file_scanner =
                        build_format_preserving_scanner(fp.scanner, fp.store, store_snapshot)
                            .map_err(|e| format!("failed to build per-file scanner: {e}"))?;
                    // Scan the structured-redacted bytes for cross-occurrence
                    // (values in comments / unstructured regions) and base patterns.
                    let (scanned_bytes, scan_stats) = scanner_fallback(&per_file_scanner, &base)?;
                    (
                        scanned_bytes,
                        format!("structured+scan:{ext}"),
                        Some(scan_stats),
                        edit_count,
                    )
                }
                None => {
                    let (out, stats) = scanner_fallback(fp.scanner, &input_bytes)?;
                    (out, "scanner".into(), Some(stats), 0)
                }
            };

            let mut stats = fallback_stats.unwrap_or_default();
            // Field values edited in place are never re-matched by the scanner
            // (the bytes are already redacted), so fold them into the stats here
            // or they would be invisible to the run summary / total.
            record_field_edits(&mut stats, field_edits);
            let output_bytes = apply_entropy_inplace(output_bytes, &mut stats, fp);
            // Normalise bytes_processed/bytes_output to the file's actual sizes.
            stats.bytes_processed = input_bytes.len() as u64;
            stats.bytes_output = output_bytes.len() as u64;

            let label = input.display().to_string();
            finalize_buffered_scan(
                &output_bytes,
                &stats,
                &label,
                method.as_str(),
                output_path,
                cli,
                fp,
            )
        })
    }

    fn scan_plain_scanner(self, input: &Path, output_path: Option<&Path>) -> Result<bool, String> {
        let cli = self.cli;
        let fp = self;
        let mut had_matches = false;
        let method = "scanner";
        let entropy_active = !fp.entropy_configs.is_empty();

        if cli.dry_run {
            let label = format!("Scanning {} (dry-run)", input.display());
            let progress_label = label.clone();
            let ent_cfgs = Arc::clone(fp.entropy_configs);
            let store_arc = Arc::clone(fp.store);
            return with_progress_scope(fp.progress, &label, move |progress| {
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let sz = file_size(input)?;
                let (stats, locs, locs_truncated) = if entropy_active {
                    let mut buf: Vec<u8> = Vec::new();
                    let (mut s, locs, tr) = scan_with_locations(
                        fp.scanner,
                        reader,
                        &mut buf,
                        Some(sz),
                        make_scan_callback(progress.clone(), &progress_label),
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
                        make_scan_callback(progress.clone(), &progress_label),
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
            });
        }

        if let Some(out_path) = output_path {
            let label = format!("Scanning {}", input.display());
            let progress_label = label.clone();
            let llm_opt = fp.llm_collector.cloned();
            return with_progress_scope(fp.progress, &label, move |progress| {
                if llm_opt.is_some() || entropy_active {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                    );
                    let mut buf: Vec<u8> = Vec::new();
                    let (mut stats, locs, locs_truncated) = scan_with_locations(
                        fp.scanner,
                        reader,
                        &mut buf,
                        Some(file_size(input)?),
                        make_scan_callback(progress.clone(), &progress_label),
                        cli.max_match_locations,
                    )?;
                    if crate::is_interrupted() {
                        return Err("interrupted — partial output discarded".into());
                    }
                    buf = apply_entropy_inplace(buf, &mut stats, fp);
                    if stats.matches_found > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = fp.report_builder {
                        rb.record_file(
                            FileReport::from_scan_stats(
                                input.display().to_string(),
                                &stats,
                                method,
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
                    let (stats, locs, locs_truncated) = scan_with_locations(
                        fp.scanner,
                        reader,
                        &mut atomic_writer,
                        Some(file_size(input)?),
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
                                method,
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
        }

        // stdout path
        let label = format!("Scanning {}", input.display());
        let progress_label = label.clone();
        let llm_opt = fp.llm_collector.cloned();
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
                let (mut stats, locs, locs_truncated) = scan_with_locations(
                    fp.scanner,
                    reader,
                    &mut buf,
                    Some(sz),
                    make_scan_callback(progress.clone(), &progress_label),
                    cli.max_match_locations,
                )?;
                buf = apply_entropy_inplace(buf, &mut stats, fp);
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
                    io::stdout()
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
                let writer = BufWriter::new(io::stdout().lock());
                let (stats, locs, locs_truncated) = scan_with_locations(
                    fp.scanner,
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
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
            }
            Ok(had_matches)
        })
    }
}
