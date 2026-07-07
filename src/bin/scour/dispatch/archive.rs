//! Archive (zip / tar / tar.gz) dispatch for `FileProcessor`.

use super::*;

impl FileProcessor<'_> {
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
                base_proc.with_progress_callback(Arc::new(
                    move |archive_progress: &ArchiveProgress| {
                        progress
                            .lock()
                            .expect("progress lock poisoned")
                            .update_archive(&label, archive_progress);
                    },
                ))
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
                    other => {
                        return Err(format!("unsupported archive format: {other:?}"));
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
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
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
                other => {
                    return Err(format!("unsupported archive format: {other:?}"));
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
}
