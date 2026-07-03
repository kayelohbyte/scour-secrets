//! Output phase: discovered-secret write-back, report/LLM/findings emission,
//! the redaction summary line, and the entropy histogram.

use super::*;

pub(super) struct OutputPhase {
    pub(super) report_builder: Option<ReportBuilder>,
    pub(super) llm_collector: Option<LlmCollector>,
    pub(super) llm_ref_entries: Vec<LlmPathEntry>,
    pub(super) reference_mode: bool,
    pub(super) auto_report_path: Option<PathBuf>,
    pub(super) report_no_path_auto: Option<PathBuf>,
}

/// What the structured-handoff write-back needs to update the secrets file in
/// its own on-disk form: re-encrypted with the same password when the file was
/// encrypted, and in its own plaintext format (JSON/YAML/TOML) otherwise.
pub(super) struct SecretsWriteback {
    pub(super) password: Option<Zeroizing<String>>,
    pub(super) was_encrypted: bool,
    pub(super) format: Option<SecretsFormat>,
}

pub(super) fn write_run_output(
    cli: &Cli,
    phase: OutputPhase,
    store: &Arc<MappingStore>,
    profiles: &[FileTypeProfile],
    had_matches: bool,
    entropy_histogram_acc: Option<Arc<Mutex<Vec<EntropyBuckets>>>>,
    writeback: SecretsWriteback,
) -> Result<(), (String, i32)> {
    if !cli.no_structured_handoff && !profiles.is_empty() {
        if let Some(save_path) = &cli.secrets_file {
            match save_discovered_secrets(
                store,
                save_path,
                writeback.password.as_ref().map(|p| p.as_str()),
                writeback.was_encrypted,
                writeback.format,
            ) {
                Ok(0) => {}
                Ok(n) => info!(
                    path = %save_path.display(),
                    added = n,
                    "saved discovered literals to secrets file"
                ),
                Err(e) => warn!("could not save discovered secrets: {e}"),
            }
        }
    }

    if let Some(builder) = phase.report_builder {
        let report = builder.finish();

        if let Some(ref template_name) = cli.llm {
            let prompt = if phase.reference_mode {
                format_llm_prompt_reference(template_name, &phase.llm_ref_entries, Some(&report))
                    .map_err(|e| (e, 1))?
            } else {
                let entries = phase
                    .llm_collector
                    .as_ref()
                    .and_then(|c| c.lock().ok())
                    .map(|g| g.clone())
                    .unwrap_or_default();
                format_llm_prompt(template_name, &entries, Some(&report)).map_err(|e| (e, 1))?
            };
            if let Some(ref endpoint) = cli.llm_endpoint {
                let model = cli.llm_model.as_deref().ok_or_else(|| {
                    ("--llm-model is required with --llm-endpoint".to_string(), 1)
                })?;
                let key = cli.llm_key.as_deref().unwrap_or("local");
                crate::llm_client::send_prompt(endpoint, model, key, &prompt)
                    .map_err(|e| (e, 1))?;
            } else {
                let stdout = io::stdout();
                stdout
                    .lock()
                    .write_all(prompt.as_bytes())
                    .map_err(|e| (format!("failed to write LLM prompt: {e}"), 1))?;
            }
        }

        if let Some(report_opt) = &cli.report {
            let content = match cli.report_format {
                ReportFormat::Sarif => report
                    .to_sarif()
                    .map_err(|e| (format!("failed to serialize SARIF report: {e}"), 1))?,
                ReportFormat::Html => report.to_html(),
                ReportFormat::Json => report
                    .to_json_pretty()
                    .map_err(|e| (format!("failed to serialize report: {e}"), 1))?,
            };

            match report_opt {
                Some(path) if path.to_string_lossy() == "-" => {
                    println!("{content}");
                }
                Some(path) => {
                    atomic_write(path, content.as_bytes()).map_err(|e| {
                        (
                            format!("failed to write report to {}: {e}", path.display()),
                            1,
                        )
                    })?;
                    info!(report = %path.display(), format = ?cli.report_format, "report written");
                }
                None => {
                    if let Some(ref path) = phase.report_no_path_auto {
                        atomic_write(path, content.as_bytes()).map_err(|e| {
                            (
                                format!("failed to write report to {}: {e}", path.display()),
                                1,
                            )
                        })?;
                        eprintln!("Report written to {}", path.display());
                    } else {
                        eprintln!("{content}");
                    }
                }
            }
        } else if let Some(ref path) = phase.auto_report_path {
            let content = report
                .to_json_pretty()
                .map_err(|e| (format!("failed to serialize report: {e}"), 1))?;
            atomic_write(path, content.as_bytes()).map_err(|e| {
                (
                    format!("failed to write report to {}: {e}", path.display()),
                    1,
                )
            })?;
            eprintln!("Report written to {}", path.display());
        }

        if let Some(ref findings_path) = cli.findings {
            let mut lines: Vec<String> = Vec::with_capacity(report.files.len() + 1);

            #[derive(serde::Serialize)]
            struct FileFinding<'a> {
                #[serde(rename = "type")]
                kind: &'static str,
                file: &'a str,
                matches: u64,
                clean: bool,
                #[serde(skip_serializing_if = "HashMap::is_empty")]
                patterns: &'a HashMap<String, u64>,
                bytes_processed: u64,
            }
            #[derive(serde::Serialize)]
            struct SummaryFinding {
                #[serde(rename = "type")]
                kind: &'static str,
                files: u64,
                matches: u64,
                clean: bool,
            }

            for f in &report.files {
                let line = serde_json::to_string(&FileFinding {
                    kind: "file",
                    file: &f.path,
                    matches: f.matches,
                    clean: f.matches == 0,
                    patterns: &f.pattern_counts,
                    bytes_processed: f.bytes_processed,
                })
                .map_err(|e| (format!("failed to serialize finding: {e}"), 1))?;
                lines.push(line);
            }
            lines.push(
                serde_json::to_string(&SummaryFinding {
                    kind: "summary",
                    files: report.summary.total_files,
                    matches: report.summary.total_matches,
                    clean: report.summary.total_matches == 0,
                })
                .map_err(|e| (format!("failed to serialize findings summary: {e}"), 1))?,
            );

            let ndjson = lines.join("\n") + "\n";

            if findings_path.to_string_lossy() == "-" {
                io::stdout()
                    .lock()
                    .write_all(ndjson.as_bytes())
                    .map_err(|e| (format!("failed to write findings to stdout: {e}"), 1))?;
            } else {
                atomic_write(findings_path, ndjson.as_bytes()).map_err(|e| {
                    (
                        format!(
                            "failed to write findings to {}: {e}",
                            findings_path.display()
                        ),
                        1,
                    )
                })?;
                info!(findings = %findings_path.display(), files = report.files.len(), "findings written");
            }
        }

        if !cli.quiet {
            let verb = if cli.dry_run { "Matched" } else { "Redacted" };
            if report.summary.total_matches == 0 {
                eprintln!("{verb}: nothing");
            } else {
                let mut parts: Vec<(u64, &str)> = report
                    .summary
                    .pattern_counts
                    .iter()
                    .map(|(k, &v)| (v, k.as_str()))
                    .collect();
                parts.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
                let line = parts
                    .iter()
                    .map(|(count, name)| format!("{count} {name}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                eprintln!("{verb}: {line}");
            }
        }
    }

    if let Some(acc) = entropy_histogram_acc {
        if let Ok(buckets) = acc.lock() {
            if !buckets.is_empty() {
                print_entropy_histogram(&buckets);
            }
        }
    }

    #[cfg(feature = "bench")]
    {
        let mappings = store.len();
        info!(unique_mappings = mappings, "performance summary");
    }

    if cli.fail_on_match && had_matches {
        return Err(("matches found (--fail-on-match)".into(), 2));
    }

    Ok(())
}
