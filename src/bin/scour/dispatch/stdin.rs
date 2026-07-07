//! Stdin dispatch for `FileProcessor`.

use super::*;

impl FileProcessor<'_> {
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
                // Prefer span-based edit mode; fall back to the literal pass,
                // then to the plain scanner.
                let structured_base =
                    structured_base_bytes(&input_bytes, &format!("stdin.{ext}"), &fp, cli.strict)?;

                // The structured edit count is ignored here: the stdin path
                // already derives `structured_reps` from store growth below.
                if let Some((base, _field_edits)) = structured_base {
                    {
                        let per_content_scanner =
                            build_format_preserving_scanner(fp.scanner, fp.store, store_snapshot)
                                .map_err(|e| format!("failed to build content scanner: {e}"))?;
                        let (mut output_bytes, scan_stats) =
                            scanner_fallback(&per_content_scanner, &base)?;
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
                            let mut stats = ScanStats::default();
                            stats.matches_found = total_replacements;
                            stats.replacements_applied = total_replacements;
                            stats.bytes_processed = input_bytes.len() as u64;
                            stats.bytes_output = output_bytes.len() as u64;
                            stats.pattern_counts = pattern_counts;
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
                }

                let (mut output_bytes, mut stats) = scanner_fallback(fp.scanner, &input_bytes)?;
                output_bytes = apply_entropy_inplace(output_bytes, &mut stats, fp);
                had_matches = finalize_buffered_scan(
                    &output_bytes,
                    &stats,
                    "<stdin>",
                    "scanner",
                    output_path,
                    cli,
                    fp,
                )?;
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
}
