use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{info, warn};
use zeroize::Zeroizing;

use rust_sanitize::secrets::{
    decrypt_secrets, entries_to_patterns, extract_allow_patterns, parse_secrets, SecretEntry,
    SecretsFormat,
};
use rust_sanitize::{
    atomic_write, format_llm_prompt, format_llm_prompt_reference, strip_values_from_text,
    ArchiveFilter, ArchiveFormat, ArchiveProcessor, FileTypeProfile, LlmPathEntry, MappingStore,
    ProcessorRegistry, ReportBuilder, ReportMetadata, ScanConfig, ScanPattern, StreamScanner,
};

use crate::apps::{ensure_user_app_copy, load_app_bundle};
use crate::cli_args::{Cli, ReportFormat};
use crate::config::{
    find_project_config, load_project_config, load_settings, ProjectConfig, Settings,
};
use crate::crypto::resolve_sanitize_password;
use crate::dispatch::{
    abs_label, load_profiles, print_entropy_histogram, save_discovered_secrets, write_output,
    FileProcessor, LlmCollector,
};
use crate::entropy::{entropy_configs_from_entries, EntropyBuckets, EntropyConfig};
use crate::scanner_builder::balanced_secret_entries;
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
};

/// Apply a `bool` setting from a config layer: skip if the flag is already set by a higher-priority source.
///
/// Requires that every covered field defaults to `false` in `Cli` (i.e. the flag is off by default).
/// A field that defaults to `true` would be permanently skipped, silently ignoring config.
macro_rules! apply_bool_flag {
    ($cli:expr, $src:expr, $field:ident) => {
        if !$cli.$field {
            if let Some(v) = $src.$field {
                $cli.$field = v;
            }
        }
    };
}

/// Apply an `Option<T>` setting from a config layer: skip if already set.
macro_rules! apply_opt_field {
    ($cli:expr, $src:expr, $field:ident) => {
        if $cli.$field.is_none() {
            $cli.$field = $src.$field;
        }
    };
}

fn apply_settings_layer(cli: &mut Cli, s: Settings) {
    if cli.app.is_empty() && !s.app.is_empty() {
        cli.app = s.app;
    }
    if cli.allow.is_empty() && !s.allow.is_empty() {
        cli.allow = s.allow;
    }
    apply_bool_flag!(cli, s, fail_on_match);
    apply_bool_flag!(cli, s, strict);
    apply_bool_flag!(cli, s, no_structured_handoff);
    apply_bool_flag!(cli, s, no_field_signal);
    apply_opt_field!(cli, s, threads);
    apply_opt_field!(cli, s, log_format);
    apply_opt_field!(cli, s, log_level);
    apply_bool_flag!(cli, s, no_progress);
}

fn apply_project_config_layer(cli: &mut Cli, pc: ProjectConfig, config_dir: &std::path::Path) {
    for bundle in &pc.app {
        if !cli.app.contains(bundle) {
            cli.app.push(bundle.clone());
        }
    }
    for val in &pc.allow {
        if !cli.allow.contains(val) {
            cli.allow.push(val.clone());
        }
    }
    if cli.secrets_file.is_none() {
        if let Some(rel) = pc.secrets_file {
            cli.secrets_file = Some(config_dir.join(rel));
        }
    }
    apply_bool_flag!(cli, pc, encrypted_secrets);
    if cli.profile.is_none() {
        if let Some(rel) = pc.profile {
            cli.profile = Some(config_dir.join(rel));
        }
    }
    apply_bool_flag!(cli, pc, fail_on_match);
    apply_bool_flag!(cli, pc, strict);
    apply_bool_flag!(cli, pc, no_structured_handoff);
    apply_bool_flag!(cli, pc, no_field_signal);
}

fn merge_settings(mut cli: Cli) -> Cli {
    apply_settings_layer(&mut cli, load_settings());
    if let Some(project_config_path) = find_project_config() {
        let (pc, config_dir) = load_project_config(&project_config_path);
        apply_project_config_layer(&mut cli, pc, &config_dir);
    }
    cli
}

struct LoadedSecrets {
    patterns: Vec<ScanPattern>,
    allow_patterns: Vec<String>,
    entropy_configs: Vec<EntropyConfig>,
    raw_bytes: Zeroizing<Vec<u8>>,
    /// Decrypted plaintext for encrypted secrets files; `None` for plaintext files.
    /// Stored here so `apply_field_name_signals` can reuse it without a second
    /// PBKDF2+AES-GCM round.
    plaintext_bytes: Option<Zeroizing<Vec<u8>>>,
}

fn load_secrets_data(
    cli: &Cli,
    password: Option<&str>,
) -> Result<Option<LoadedSecrets>, (String, i32)> {
    let secrets_path = match cli.secrets_file.as_ref() {
        Some(p) => p,
        None => return Ok(None),
    };

    let raw_bytes = if secrets_path.exists() {
        Zeroizing::new(fs::read(secrets_path).map_err(|e| {
            (
                format!(
                    "failed to read secrets file {}: {e}",
                    secrets_path.display()
                ),
                1,
            )
        })?)
    } else if cli.deterministic {
        return Ok(None);
    } else {
        return Err((
            format!("secrets file not found: {}", secrets_path.display()),
            1,
        ));
    };

    let secrets_format = SecretsFormat::from_extension(secrets_path.to_string_lossy().as_ref());
    let (((patterns, warnings), allow_patterns), was_encrypted) =
        rust_sanitize::secrets::load_secrets_auto(
            &raw_bytes,
            password,
            secrets_format,
            !cli.encrypted_secrets,
        )
        .map_err(|e| (format!("failed to load secrets: {e}"), 1))?;

    if was_encrypted {
        info!(secrets_file = %secrets_path.display(), "loaded encrypted secrets");
    } else {
        info!(secrets_file = %secrets_path.display(), "loaded plaintext secrets (unencrypted)");
    }

    if !warnings.is_empty() {
        for (idx, err) in &warnings {
            warn!(entry = idx, error = %err, "secret entry warning");
        }
        if cli.strict {
            return Err((
                format!(
                    "{} secret entries had errors (use without --strict to continue)",
                    warnings.len()
                ),
                1,
            ));
        }
    }

    let plaintext_bytes: Option<Zeroizing<Vec<u8>>> = if was_encrypted {
        password.and_then(|pw| decrypt_secrets(&raw_bytes, pw).ok())
    } else {
        None
    };
    let bytes_for_entropy: &[u8] = plaintext_bytes
        .as_deref()
        .map_or(raw_bytes.as_slice(), |v| v);
    let entropy_configs = if let Ok(ent_entries) = parse_secrets(bytes_for_entropy, None) {
        entropy_configs_from_entries(&ent_entries)
    } else {
        vec![]
    };

    Ok(Some(LoadedSecrets {
        patterns,
        allow_patterns,
        entropy_configs,
        raw_bytes,
        plaintext_bytes,
    }))
}

fn apply_field_name_signals(
    cli: &Cli,
    profiles: &mut [FileTypeProfile],
    loaded_secrets: Option<&LoadedSecrets>,
) {
    if cli.no_field_signal || profiles.is_empty() {
        return;
    }

    let mut active_signals = builtin_field_name_signals();

    if let Some(ls) = loaded_secrets {
        let bytes = ls
            .plaintext_bytes
            .as_deref()
            .map_or(ls.raw_bytes.as_slice(), |v| v);
        if let Ok(entries) = parse_secrets(bytes, None) {
            let user_signals = field_signals_from_entries(&entries);
            if !user_signals.is_empty() {
                info!(
                    count = user_signals.len(),
                    "loaded user-defined field-name signals"
                );
            }
            active_signals.extend(user_signals);
        }
    }

    let signal_count = active_signals.len();
    for profile in profiles.iter_mut() {
        profile.field_name_signals = active_signals.clone();
    }
    info!(
        signals = signal_count,
        "field-name signals active (disable with --no-field-signal)"
    );
}

struct RunResources {
    scanner: Arc<StreamScanner>,
    store: Arc<MappingStore>,
    registry: Arc<ProcessorRegistry>,
    profiles: Vec<rust_sanitize::FileTypeProfile>,
    entropy_configs: Arc<Vec<EntropyConfig>>,
    entropy_histogram_acc: Option<Arc<Mutex<Vec<EntropyBuckets>>>>,
    base_patterns: Vec<ScanPattern>,
    scan_config: ScanConfig,
}

fn load_run_resources(
    cli: &Cli,
    pre_resolved_password: Option<Zeroizing<String>>,
) -> Result<RunResources, (String, i32)> {
    let effective_password: Option<Zeroizing<String>> =
        if cli.encrypted_secrets || cli.deterministic {
            if let Some(pw) = pre_resolved_password {
                Some(pw)
            } else {
                Some(resolve_sanitize_password(cli).map_err(|e| (e, 1))?)
            }
        } else {
            None
        };

    let scan_config = build_scan_config(cli.chunk_size).map_err(|e| (e, 1))?;
    let registry = Arc::new(ProcessorRegistry::with_builtins());

    let file_profiles = if let Some(ref profile_path) = cli.profile {
        load_profiles(profile_path).map_err(|e| (e, 1))?
    } else {
        vec![]
    };

    let mut base_patterns: Vec<ScanPattern> = vec![];
    let mut all_allow_patterns: Vec<String> = cli.allow.clone();
    let mut entropy_configs: Vec<EntropyConfig> = vec![];

    for app_name in &cli.app {
        if let Ok(bundle) = load_app_bundle(app_name) {
            all_allow_patterns.extend(extract_allow_patterns(&bundle.secrets));
        }
    }

    let loaded_secrets = load_secrets_data(cli, effective_password.as_ref().map(|s| s.as_str()))?;
    if let Some(ref ls) = loaded_secrets {
        base_patterns.extend(ls.patterns.iter().cloned());
        all_allow_patterns.extend(ls.allow_patterns.iter().cloned());
        entropy_configs.extend(ls.entropy_configs.iter().cloned());
    }

    if !cli.quick.is_empty() {
        let quick_entries: Vec<SecretEntry> = cli.quick.iter().map(|p| {
            let (kind, pattern) = if let Some(rx) = p.strip_prefix("regex:") {
                ("regex", rx)
            } else {
                ("literal", p.as_str())
            };
            SecretEntry {
                pattern: pattern.to_string(),
                kind: kind.to_string(),
                category: "auth_token".to_string(),
                label: Some(format!("quick:{p}")),
                values: vec![],
                min_length: None,
                max_length: None,
                threshold: None,
                charset: None,
            }
        }).collect();
        let (patterns, errors) = entries_to_patterns(&quick_entries);
        if !errors.is_empty() {
            let msgs: Vec<String> = errors
                .iter()
                .map(|(i, e)| format!("position {i}: {e}"))
                .collect();
            return Err((format!("invalid --quick pattern(s): {}", msgs.join("; ")), 1));
        }
        base_patterns.extend(patterns);
    }

    if let Some(threshold) = cli.entropy_threshold {
        if !entropy_configs
            .iter()
            .any(|c| c.label == "high_entropy_token")
        {
            entropy_configs.push(EntropyConfig {
                threshold,
                ..Default::default()
            });
        }
    }
    let entropy_configs = Arc::new(entropy_configs);

    let entropy_histogram_acc: Option<Arc<Mutex<Vec<EntropyBuckets>>>> =
        if cli.dry_run && !entropy_configs.is_empty() {
            Some(Arc::new(Mutex::new(Vec::new())))
        } else {
            None
        };

    let nothing_specified =
        cli.secrets_file.is_none() && cli.app.is_empty() && cli.profile.is_none();
    let load_defaults = nothing_specified || (!cli.app.is_empty() && cli.secrets_file.is_none());
    if load_defaults {
        all_allow_patterns.extend(common_allow_patterns());
    }

    let allowlist: Option<Arc<rust_sanitize::allowlist::AllowlistMatcher>> =
        if all_allow_patterns.is_empty() {
            None
        } else {
            let al_result =
                rust_sanitize::allowlist::AllowlistMatcher::new(all_allow_patterns);
            for w in &al_result.warnings {
                warn!(warning = %w, "allowlist pattern warning");
            }
            let matcher = Arc::new(al_result.matcher);
            info!(patterns = matcher.pattern_count(), "allowlist loaded");
            Some(matcher)
        };
    let store = build_store(
        cli.deterministic,
        effective_password.as_ref().map(|s| s.as_str()),
        cli.max_mappings,
        allowlist,
    )
    .map_err(|e| (e, 1))?;

    if load_defaults {
        let default_patterns = build_default_patterns();
        info!(
            patterns = default_patterns.len(),
            "loaded built-in balanced patterns (auto, via --app)"
        );
        base_patterns.extend(default_patterns);
    }

    let mut app_profiles = vec![];
    for app_name in &cli.app {
        let bundle = load_app_bundle(app_name).map_err(|e| (e, 1))?;
        let (app_patterns, app_errors) = entries_to_patterns(&bundle.secrets);
        if !app_errors.is_empty() {
            for (i, e) in &app_errors {
                warn!(app = %app_name, entry = i, error = %e, "app bundle pattern warning");
            }
        }
        info!(
            app = %app_name,
            patterns = app_patterns.len(),
            profiles = bundle.profiles.len(),
            "loaded app bundle"
        );
        base_patterns.extend(app_patterns);
        app_profiles.extend(bundle.profiles);
    }

    if base_patterns.is_empty() && app_profiles.is_empty() {
        warn!("no secrets file or --app provided; pass --secrets-file, --app, or --profile explicitly, or run without flags to auto-create the default secrets file");
    }

    let scanner = StreamScanner::new(
        base_patterns.clone(),
        Arc::clone(&store),
        scan_config.clone(),
    )
    .map_err(|e| (format!("failed to create scanner: {e}"), 1))?;

    if !base_patterns.is_empty() {
        info!(patterns = scanner.pattern_count(), "scanner ready");
    }
    let scanner = Arc::new(scanner);

    let mut profiles = {
        let mut merged = app_profiles;
        merged.extend(file_profiles);
        merged
    };

    apply_field_name_signals(cli, &mut profiles, loaded_secrets.as_ref());

    if !profiles.is_empty() {
        info!(count = profiles.len(), "loaded field-path profiles");
        for p in &profiles {
            if registry.get(&p.processor).is_none() {
                eprintln!(
                    "Warning: profile processor '{}' is not registered. \
                     Known processors: {}",
                    p.processor,
                    registry.names().join(", ")
                );
            }
        }
    }

    Ok(RunResources {
        scanner,
        store,
        registry,
        profiles,
        entropy_configs,
        entropy_histogram_acc,
        base_patterns,
        scan_config,
    })
}

struct OutputPhase {
    report_builder: Option<ReportBuilder>,
    llm_collector: Option<LlmCollector>,
    llm_ref_entries: Vec<LlmPathEntry>,
    reference_mode: bool,
    auto_report_path: Option<PathBuf>,
    report_no_path_auto: Option<PathBuf>,
}

fn write_run_output(
    cli: &Cli,
    phase: OutputPhase,
    store: &Arc<MappingStore>,
    profiles: &[FileTypeProfile],
    had_matches: bool,
    entropy_histogram_acc: Option<Arc<Mutex<Vec<EntropyBuckets>>>>,
) -> Result<(), (String, i32)> {
    if !cli.no_structured_handoff && !profiles.is_empty() {
        if let Some(save_path) = &cli.secrets_file {
            match save_discovered_secrets(store, save_path) {
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
    let mut cli = merge_settings(cli);

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
        if !default_path.exists() {
            if let Some(parent) = default_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let allow_entry = SecretEntry {
                kind: "allow".into(),
                pattern: String::new(),
                category: String::new(),
                label: None,
                values: common_allow_patterns(),
                min_length: None,
                max_length: None,
                threshold: None,
                charset: None,
            };
            let mut entries = balanced_secret_entries();
            entries.push(allow_entry);
            if let Ok(yaml) = serde_yaml_ng::to_string(&entries) {
                let header = "# Global sanitize secrets — balanced detection patterns + allowlist.\n# Auto-loaded on every plain run. Edit freely; deleted values take effect immediately.\n\n";
                let _ = fs::write(&default_path, format!("{header}{yaml}"));
            }
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
             sanitize --profile my.profile.yaml --secrets-file secrets.yaml [paths...]"
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

    let RunResources {
        scanner,
        store,
        registry,
        profiles,
        entropy_configs,
        entropy_histogram_acc,
        base_patterns,
        scan_config,
    } = load_run_resources(&cli, pre_resolved_password)?;

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

    for target in phase1_targets {
        if crate::is_interrupted() {
            break;
        }
        let InputTarget::File { input, output } = target else {
            unreachable!()
        };
        had_matches |= base_fp
            .process_plain_file(&input, Some(output.as_path()))
            .map_err(|e| (e, 1))?;
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

    let augmented_scanner = build_augmented_scanner(&base_patterns, &store, scan_config)?;
    let aug_fp = FileProcessor {
        scanner: &augmented_scanner,
        ..base_fp
    };

    if !profiles.is_empty() {
        for target in stdin_targets {
            let InputTarget::Stdin { output } = target else {
                unreachable!()
            };
            had_matches |= aug_fp
                .process_stdin(output.as_deref())
                .map_err(|e| (e, 1))?;
        }
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

    write_run_output(
        &cli,
        OutputPhase {
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
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::path::Path;

    fn default_cli() -> Cli {
        Cli::try_parse_from(["sanitize", "file.txt"]).unwrap()
    }

    // ── apply_settings_layer ─────────────────────────────────────────────────

    #[test]
    fn settings_layer_applies_when_cli_is_default() {
        let mut cli = default_cli();
        let s = Settings {
            threads: Some(8),
            fail_on_match: Some(true),
            log_level: Some("debug".into()),
            ..Default::default()
        };
        apply_settings_layer(&mut cli, s);
        assert_eq!(cli.threads, Some(8));
        assert!(cli.fail_on_match);
        assert_eq!(cli.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn settings_layer_does_not_override_cli_flags() {
        let mut cli = Cli::try_parse_from(["sanitize", "file.txt", "--fail-on-match"]).unwrap();
        assert!(cli.fail_on_match);
        apply_settings_layer(
            &mut cli,
            Settings {
                fail_on_match: Some(false),
                ..Default::default()
            },
        );
        // CLI flag wins — still true.
        assert!(cli.fail_on_match);
    }

    #[test]
    fn settings_layer_does_not_override_explicit_threads() {
        let mut cli = Cli::try_parse_from(["sanitize", "file.txt", "--threads", "2"]).unwrap();
        apply_settings_layer(
            &mut cli,
            Settings {
                threads: Some(16),
                ..Default::default()
            },
        );
        assert_eq!(cli.threads, Some(2));
    }

    #[test]
    fn settings_layer_fills_app_when_cli_empty() {
        let mut cli = default_cli();
        apply_settings_layer(
            &mut cli,
            Settings {
                app: vec!["gitlab".into()],
                ..Default::default()
            },
        );
        assert_eq!(cli.app, vec!["gitlab"]);
    }

    #[test]
    fn settings_layer_does_not_replace_cli_app() {
        let mut cli = Cli::try_parse_from(["sanitize", "file.txt", "--app", "kubernetes"]).unwrap();
        apply_settings_layer(
            &mut cli,
            Settings {
                app: vec!["gitlab".into()],
                ..Default::default()
            },
        );
        assert_eq!(cli.app, vec!["kubernetes"]);
    }

    // ── apply_project_config_layer ───────────────────────────────────────────

    #[test]
    fn project_layer_adds_app_bundles_additively() {
        let mut cli = Cli::try_parse_from(["sanitize", "file.txt", "--app", "kubernetes"]).unwrap();
        let pc = ProjectConfig {
            app: vec!["gitlab".into()],
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("."));
        assert!(cli.app.contains(&"kubernetes".to_string()));
        assert!(cli.app.contains(&"gitlab".to_string()));
    }

    #[test]
    fn project_layer_deduplicates_app_bundles() {
        let mut cli = Cli::try_parse_from(["sanitize", "file.txt", "--app", "gitlab"]).unwrap();
        let pc = ProjectConfig {
            app: vec!["gitlab".into()],
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("."));
        assert_eq!(cli.app.iter().filter(|a| *a == "gitlab").count(), 1);
    }

    #[test]
    fn project_layer_resolves_secrets_file_relative_to_config_dir() {
        let mut cli = default_cli();
        let pc = ProjectConfig {
            secrets_file: Some(PathBuf::from("secrets.yaml")),
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("/repo"));
        assert_eq!(cli.secrets_file, Some(PathBuf::from("/repo/secrets.yaml")));
    }

    #[test]
    fn project_layer_does_not_override_cli_secrets_file() {
        let mut cli =
            Cli::try_parse_from(["sanitize", "file.txt", "-s", "/explicit/secrets.yaml"]).unwrap();
        let pc = ProjectConfig {
            secrets_file: Some(PathBuf::from("project_secrets.yaml")),
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("/repo"));
        assert_eq!(
            cli.secrets_file,
            Some(PathBuf::from("/explicit/secrets.yaml"))
        );
    }

    #[test]
    fn project_layer_resolves_profile_relative_to_config_dir() {
        let mut cli = default_cli();
        let pc = ProjectConfig {
            profile: Some(PathBuf::from("my.profile.yaml")),
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("/repo"));
        assert_eq!(cli.profile, Some(PathBuf::from("/repo/my.profile.yaml")));
    }

    #[test]
    fn project_layer_adds_allow_additively() {
        let mut cli =
            Cli::try_parse_from(["sanitize", "file.txt", "--allow", "localhost"]).unwrap();
        let pc = ProjectConfig {
            allow: vec!["*.internal".into()],
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("."));
        assert!(cli.allow.contains(&"localhost".to_string()));
        assert!(cli.allow.contains(&"*.internal".to_string()));
    }
}
