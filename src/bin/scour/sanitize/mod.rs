use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{info, warn};
use zeroize::Zeroizing;

use scour_secrets::secrets::{
    decrypt_secrets, entries_to_patterns, extract_allow_patterns, parse_secrets, SecretEntry,
    SecretsFormat,
};
use scour_secrets::{
    atomic_write, format_llm_prompt, format_llm_prompt_reference, strip_values_from_text,
    ArchiveFilter, ArchiveFormat, ArchiveProcessor, FileTypeProfile, LlmPathEntry, MappingStore,
    ProcessorRegistry, ReportBuilder, ReportMetadata, ScanConfig, ScanPattern, StreamScanner,
};

use crate::apps::{ensure_user_app_copy, load_app_bundle};
use crate::cli_args::{
    Cli, ReportFormat, DEFAULT_MAX_STRUCTURED_FILE_SIZE, DEFAULT_PROGRESS_INTERVAL_MS,
};
use crate::config::{find_project_config, load_project_config, load_settings, SanitizeConfig};
use crate::crypto::resolve_sanitize_password;
use crate::dispatch::{
    abs_label, load_profiles, print_entropy_histogram, save_discovered_secrets, write_output,
    FileProcessor, LlmCollector,
};
use crate::entropy::{entropy_configs_from_entries, EntropyBuckets, EntropyConfig};
use crate::hooks::global_default_secrets_path;
use crate::input::{
    cli_writes_to_stdout, derive_auto_report_path, plan_input_targets, resolve_thread_count,
    validate_args, InputTarget,
};
use crate::progress::{ProgressContext, ProgressPolicy, ProgressReporter, SharedProgressReporter};
use crate::run_header::{print_run_header, CliConfigSnapshot};
use crate::scanner_builder::{
    build_augmented_scanner, build_default_patterns, build_scan_config, build_store,
    builtin_field_name_signals, common_allow_patterns, field_signals_from_entries,
    write_default_secrets,
};
use scour_secrets::{DEFAULT_ARCHIVE_DEPTH, DEFAULT_CONTEXT_LINES, DEFAULT_MAX_MATCHES};

mod config_layer;
mod output;
mod resources;

pub(crate) fn run_sanitize(
    cli: Cli,
    pre_resolved_password: Option<Zeroizing<String>>,
    filter_map: HashMap<PathBuf, ArchiveFilter>,
) -> Result<(), (String, i32)> {
    if let Err(e) = ctrlc::set_handler(move || {
        crate::INTERRUPTED.store(true, std::sync::atomic::Ordering::SeqCst);
    }) {
        eprintln!("warning: failed to install signal handler: {e}");
    }

    let cli_snapshot = CliConfigSnapshot::capture(&cli);
    let mut cli = config_layer::merge_settings(cli);

    validate_args(&cli).map_err(|e| (e, 1))?;

    let progress_mode = cli.effective_progress_mode();
    let mut progress_context = ProgressContext::detect(cli.effective_log_format());
    progress_context.stdout_is_output = cli_writes_to_stdout(&cli);
    let progress_policy = ProgressPolicy::from_mode(progress_mode, progress_context);
    let progress_reporter: Option<SharedProgressReporter> =
        if progress_policy.live_updates || progress_policy.milestone_updates {
            Some(Arc::new(Mutex::new(ProgressReporter::new(
                progress_policy,
                progress_context.json_logs,
                cli.progress_interval_ms,
            ))))
        } else {
            None
        };

    let thread_count = resolve_thread_count(cli.threads);

    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global();

    if cli.secrets_file.is_none() && cli.app.is_empty() {
        let default_path = global_default_secrets_path();
        // Atomically create the default secrets file on first run. Fail closed
        // on write error rather than silently running with zero patterns (an
        // unsanitized passthrough); the atomic write also stops a concurrent
        // first-run from reading a half-written file and doing the same.
        if !default_path.exists() {
            write_default_secrets(&default_path).map_err(|e| (e, 1))?;
        }
        if default_path.exists() {
            cli.secrets_file = Some(default_path);
        }
    }

    if !cli.app.is_empty() && !cli.no_structured_handoff {
        for app_name in &cli.app {
            if let Some(secrets_path) = ensure_user_app_copy(app_name) {
                if cli.app.len() == 1 && cli.secrets_file.is_none() {
                    info!(
                        app = %app_name,
                        path = %secrets_path.display(),
                        "using local app secrets as write-back target"
                    );
                    cli.secrets_file = Some(secrets_path);
                }
            }
        }
    }

    if cli.profile.is_some() && cli.secrets_file.is_none() && !cli.no_structured_handoff {
        return Err((
            "a secrets file is required when using --profile\n\
             \n\
             Without one, discovered values from the profile pass have nowhere to go\n\
             and the scanner pass runs blind — sensitive data in logs that the profile\n\
             would catch from config will be missed.\n\
             \n\
             The file can be empty on the first run; sanitize will populate it with\n\
             discovered literals automatically:\n\
             \n\
             touch secrets.yaml\n\
             scour-secrets --profile my.profile.yaml --secrets-file secrets.yaml [paths...]"
                .into(),
            1,
        ));
    }

    if progress_policy.live_updates
        || progress_policy.milestone_updates
        || progress_context.json_logs
    {
        print_run_header(&cli, &cli_snapshot, progress_context.json_logs);
    }

    info!(
        threads = thread_count,
        deterministic = cli.deterministic,
        chunk_size = cli.chunk_size,
        progress_mode = ?progress_mode,
        live_progress = progress_policy.live_updates,
        milestone_progress = progress_policy.milestone_updates,
        progress_interval_ms = cli.progress_interval_ms,
        "starting sanitization"
    );

    let resources::RunResources {
        scanner,
        store,
        registry,
        profiles,
        entropy_configs,
        entropy_histogram_acc,
        base_patterns,
        scan_config,
        secrets_password,
        secrets_was_encrypted,
        secrets_format,
    } = resources::load_run_resources(&cli, pre_resolved_password)?;

    let report_enabled = cli.report.is_some()
        || cli.llm.is_some()
        || cli.findings.is_some()
        || cli.extract_context
        || !cli.quiet;
    let report_builder = if report_enabled {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| {
                let secs = d.as_secs();
                let (s, m, h) = (secs % 60, (secs / 60) % 60, (secs / 3600) % 24);
                let days = secs / 86400;
                format!("epoch+{days}d {:02}:{:02}:{:02}Z", h, m, s)
            })
            .unwrap_or_else(|_| "unknown".into());

        Some(ReportBuilder::new(ReportMetadata {
            version: env!("CARGO_PKG_VERSION").into(),
            timestamp,
            deterministic: cli.deterministic,
            dry_run: cli.dry_run,
            strict: cli.strict,
            chunk_size: cli.chunk_size,
            threads: cli.threads,
            secrets_file: cli.secrets_file.as_ref().map(|p| p.display().to_string()),
        }))
    } else {
        None
    };

    let input_targets = plan_input_targets(&cli).map_err(|e| (e, 1))?;

    let has_file_targets = input_targets
        .iter()
        .any(|t| matches!(t, InputTarget::File { .. }));
    let reference_mode = cli.llm.is_some() && (cli.output.is_some() || has_file_targets);

    let llm_collector: Option<LlmCollector> = if cli.llm.is_some() && !reference_mode {
        Some(Arc::new(Mutex::new(Vec::new())))
    } else {
        None
    };

    let auto_report_path: Option<PathBuf> = if cli.extract_context && cli.report.is_none() {
        derive_auto_report_path(&input_targets, "json")
    } else {
        None
    };

    let report_no_path_auto: Option<PathBuf> = if matches!(&cli.report, Some(None)) {
        let ext = match cli.report_format {
            ReportFormat::Sarif => "sarif",
            ReportFormat::Html => "html",
            ReportFormat::Json => "json",
        };
        derive_auto_report_path(&input_targets, ext)
    } else {
        None
    };

    if cli.strip_values {
        for target in &input_targets {
            let (content, output_path) = match target {
                InputTarget::Stdin { output } => {
                    let mut buf = Vec::new();
                    io::stdin()
                        .read_to_end(&mut buf)
                        .map_err(|e| (format!("failed to read stdin: {e}"), 1))?;
                    (
                        String::from_utf8_lossy(&buf).into_owned(),
                        output.as_deref(),
                    )
                }
                InputTarget::File { input, output } => {
                    let text = fs::read_to_string(input)
                        .map_err(|e| (format!("failed to read {}: {e}", input.display()), 1))?;
                    (text, Some(output.as_path()))
                }
            };
            let stripped =
                strip_values_from_text(&content, &cli.strip_delimiter, &cli.strip_comment_prefix);
            write_output(output_path, stripped.as_bytes()).map_err(|e| (e, 1))?;
        }
        return Ok(());
    }

    let (stdin_targets, file_targets): (Vec<_>, Vec<_>) = input_targets
        .into_iter()
        .partition(|t| matches!(t, InputTarget::Stdin { .. }));

    let llm_ref_entries: Vec<LlmPathEntry> = if reference_mode {
        stdin_targets
            .iter()
            .filter_map(|t| {
                if let InputTarget::Stdin { output: Some(out) } = t {
                    Some(("<stdin>".to_string(), abs_label(out)))
                } else {
                    None
                }
            })
            .chain(file_targets.iter().filter_map(|t| {
                if let InputTarget::File { input, output } = t {
                    Some((abs_label(input), abs_label(output)))
                } else {
                    None
                }
            }))
            .map(|(label, abs_out)| (label, PathBuf::from(abs_out)))
            .collect()
    } else {
        vec![]
    };

    // Base FileProcessor — all per-run context in one place.
    // Swap .scanner to switch between the base and augmented scanner.
    let base_fp = FileProcessor {
        cli: &cli,
        scanner: &scanner,
        registry: &registry,
        store: &store,
        profiles: &profiles,
        report_builder: report_builder.as_ref(),
        progress: progress_reporter.as_ref(),
        llm_collector: llm_collector.as_ref(),
        entropy_configs: &entropy_configs,
        entropy_histogram_acc: entropy_histogram_acc.as_ref(),
        full_store_pass: false,
    };

    let mut had_matches = false;

    if profiles.is_empty() {
        for target in &stdin_targets {
            let InputTarget::Stdin { ref output } = target else {
                unreachable!()
            };
            had_matches |= base_fp
                .process_stdin(output.as_deref())
                .map_err(|e| (e, 1))?;
        }
    }

    let (phase1_targets, phase2_targets): (Vec<_>, Vec<_>) = if profiles.is_empty() {
        (vec![], file_targets)
    } else {
        file_targets.into_iter().partition(|t| {
            let InputTarget::File { ref input, .. } = t else {
                return false;
            };
            let name = input.to_string_lossy();
            ArchiveFormat::from_path(&name).is_none()
                && profiles.iter().any(|p| p.matches_filename(&name))
        })
    };

    // Phase 1a — discovery only, sequential in command-line order. Populates
    // the store with structured field values so the augmented scanner and each
    // structured file's format-preserving scanner can redact them across *all*
    // files, regardless of which file a value first appeared in. Sequential
    // order preserves deterministic first-writer-wins replacement values.
    for target in &phase1_targets {
        if crate::is_interrupted() {
            break;
        }
        let InputTarget::File { ref input, .. } = target else {
            unreachable!()
        };
        base_fp.discover_plain_file(input).map_err(|e| (e, 1))?;
    }

    if !profiles.is_empty() {
        let discovery = ArchiveProcessor::new(
            Arc::clone(&registry),
            Arc::clone(&scanner),
            Arc::clone(&store),
            profiles.to_vec(),
        );
        for target in &phase2_targets {
            if crate::is_interrupted() {
                break;
            }
            let InputTarget::File { ref input, .. } = target else {
                continue;
            };
            let input_str = input.to_string_lossy();
            let Some(fmt) = ArchiveFormat::from_path(&input_str) else {
                continue;
            };
            let file = fs::File::open(input).map_err(|e| {
                (
                    format!(
                        "failed to open {} for profile discovery: {e}",
                        input.display()
                    ),
                    1,
                )
            })?;
            match fmt {
                ArchiveFormat::Tar => discovery.discover_profiles_tar(file),
                ArchiveFormat::TarGz => discovery.discover_profiles_tar_gz(file),
                ArchiveFormat::Zip => discovery.discover_profiles_zip(file),
            }
            .map_err(|e| {
                (
                    format!("profile discovery failed for {}: {e}", input.display()),
                    1,
                )
            })?;
        }
    }

    // Process stdin BEFORE building the final augmented scanner and the
    // structured-file output pass, so stdin's discovered field values land in
    // the shared store and are redacted in those files too. (Previously stdin
    // was processed last, so a value first seen in a stdin field leaked from the
    // structured files, which were already written.) stdin is discovered with
    // the same store as files/archives and sees their values; because the
    // streaming-stdin path uses the scanner directly, give it a provisional
    // augmented scanner built from the store so far. The final augmented scanner
    // (below) then also folds in stdin's own contributions.
    if !profiles.is_empty() && !stdin_targets.is_empty() {
        let stdin_scanner = build_augmented_scanner(&base_patterns, &store, scan_config.clone())?;
        let stdin_fp = FileProcessor {
            scanner: &stdin_scanner,
            ..base_fp
        };
        for target in stdin_targets {
            let InputTarget::Stdin { output } = target else {
                unreachable!()
            };
            had_matches |= stdin_fp
                .process_stdin(output.as_deref())
                .map_err(|e| (e, 1))?;
        }
    }

    // Augmented scanner over the now-complete store (files + archives + stdin).
    let augmented_scanner = build_augmented_scanner(&base_patterns, &store, scan_config)?;
    let aug_fp = FileProcessor {
        scanner: &augmented_scanner,
        ..base_fp
    };

    // Phase 1b — output pass for structured files. Uses the base scanner (so
    // `for_structured_pass` can strip structure-corrupting patterns) with
    // `full_store_pass`, building each file's format-preserving scanner from the
    // now fully-populated store (including stdin's values). Sequential, in
    // command-line order, to keep first-writer-wins deterministic for any
    // base-pattern/entropy values these files contribute.
    let full_fp = FileProcessor {
        full_store_pass: true,
        ..base_fp
    };
    for target in phase1_targets {
        if crate::is_interrupted() {
            break;
        }
        let InputTarget::File { input, output } = target else {
            unreachable!()
        };
        had_matches |= full_fp
            .process_plain_file(&input, Some(output.as_path()))
            .map_err(|e| (e, 1))?;
    }

    let file_results: Vec<Result<bool, (String, i32)>> = if phase2_targets.len() > 1 {
        phase2_targets
            .into_par_iter()
            .map(|target| {
                if crate::is_interrupted() {
                    return Ok(false);
                }
                let InputTarget::File { input, output } = target else {
                    unreachable!()
                };
                let input_str = input.to_string_lossy();
                if let Some(fmt) = ArchiveFormat::from_path(&input_str) {
                    let filter = filter_map.get(&input).cloned().unwrap_or_default();
                    aug_fp
                        .process_archive(&input, &output, fmt, filter, true)
                        .map_err(|e| (e, 1))
                } else {
                    aug_fp
                        .process_plain_file(&input, Some(output.as_path()))
                        .map_err(|e| (e, 1))
                }
            })
            .collect()
    } else {
        phase2_targets
            .into_iter()
            .map(|target| {
                let InputTarget::File { input, output } = target else {
                    unreachable!()
                };
                let input_str = input.to_string_lossy();
                if let Some(fmt) = ArchiveFormat::from_path(&input_str) {
                    let filter = filter_map.get(&input).cloned().unwrap_or_default();
                    aug_fp
                        .process_archive(&input, &output, fmt, filter, false)
                        .map_err(|e| (e, 1))
                } else {
                    aug_fp
                        .process_plain_file(&input, Some(output.as_path()))
                        .map_err(|e| (e, 1))
                }
            })
            .collect()
    };

    for result in file_results {
        had_matches |= result?;
    }

    if crate::is_interrupted() {
        return Err(("interrupted by signal".into(), 130));
    }

    output::write_run_output(
        &cli,
        output::OutputPhase {
            report_builder,
            llm_collector,
            llm_ref_entries,
            reference_mode,
            auto_report_path,
            report_no_path_auto,
        },
        &store,
        &profiles,
        had_matches,
        entropy_histogram_acc,
        output::SecretsWriteback {
            password: secrets_password,
            was_encrypted: secrets_was_encrypted,
            format: secrets_format,
        },
    )
}
