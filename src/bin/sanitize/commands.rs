use std::collections::HashMap;
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

use rust_sanitize::secrets::{
    entries_to_patterns, parse_secrets, serialize_secrets, SecretsFormat,
};
use rust_sanitize::{
    atomic_write, DEFAULT_ARCHIVE_DEPTH, DEFAULT_CONTEXT_LINES, DEFAULT_MAX_MATCHES,
};

use crate::apps::load_app_bundle;
use crate::cli_args::{
    AllowTestArgs, Cli, ScanArgs, TemplateArgs, TestPatternArgs, DEFAULT_MAX_STRUCTURED_FILE_SIZE,
    DEFAULT_PROGRESS_INTERVAL_MS,
};
use crate::crypto::{prompt_confirm_password, prompt_password, read_password_file};
use crate::guided::{
    build_guided_entries, build_guided_profiles, parse_template_preset, prompt_cloud_providers,
    prompt_domains, prompt_formats, prompt_line, prompt_yes_no, template_body_aws,
    template_body_database, template_body_generic, template_body_k8s, template_body_web,
    GuidedOptions, GuidedPreset, TemplatePreset, PROFILE_HEADER, TEMPLATE_HEADER,
};
use crate::progress::ProgressMode;
use crate::sanitize::run_sanitize;

pub(crate) fn run_scan(args: &ScanArgs) -> Result<(), (String, i32)> {
    let pre_resolved_password: Option<Zeroizing<String>> =
        if args.encrypted_secrets && !args.password {
            if let Some(ref pf) = args.password_file {
                Some(read_password_file(pf).map_err(|e| (e, 1))?)
            } else if let Ok(pw) = std::env::var("SANITIZE_PASSWORD") {
                std::env::remove_var("SANITIZE_PASSWORD");
                eprintln!("info: using password from SANITIZE_PASSWORD environment variable");
                Some(Zeroizing::new(pw))
            } else {
                None
            }
        } else if args.encrypted_secrets && args.password {
            Some(prompt_password("secrets file").map_err(|e| (e, 1))?)
        } else {
            None
        };

    let cli = Cli {
        command: None,
        input: args.input.clone(),
        output: None,
        secrets_file: args.secrets_file.clone(),
        profile: args.profile.clone(),
        password: args.password,
        password_file: args.password_file.clone(),
        encrypted_secrets: args.encrypted_secrets,
        format: None,
        dry_run: true,
        fail_on_match: true,
        report: args.report.clone(),
        report_format: args.report_format.clone(),
        strict: false,
        deterministic: false,
        no_structured_handoff: true,
        no_field_signal: false,
        include_binary: false,
        hidden: args.hidden,
        exclude_path: args.exclude_path.clone(),
        include_path: args.include_path.clone(),
        force_text: false,
        threads: args.threads,
        chunk_size: 1_048_576,
        max_mappings: 10_000_000,
        max_structured_size: DEFAULT_MAX_STRUCTURED_FILE_SIZE,
        max_archive_depth: DEFAULT_ARCHIVE_DEPTH,
        log_format: args.log_format.clone(),
        log_level: args.log_level.clone(),
        progress: if args.findings || args.no_progress {
            Some(ProgressMode::Off)
        } else {
            None
        },
        no_progress: false,
        quiet: false,
        progress_interval_ms: DEFAULT_PROGRESS_INTERVAL_MS,
        extract_context: false,
        context_lines: DEFAULT_CONTEXT_LINES,
        context_keywords: Vec::new(),
        context_keywords_replace: false,
        max_context_matches: DEFAULT_MAX_MATCHES,
        context_case_sensitive: false,
        max_match_locations: 0,
        strip_values: false,
        strip_delimiter: "=".to_string(),
        strip_comment_prefix: "#".to_string(),
        llm: None,
        app: args.app.clone(),
        allow: args.allow.clone(),
        findings: if args.findings {
            Some(PathBuf::from("-"))
        } else {
            None
        },
        entropy_threshold: args.entropy_threshold,
    };

    run_sanitize(cli, pre_resolved_password, HashMap::new())
}

pub(crate) fn run_test_pattern(args: &TestPatternArgs) -> Result<(), (String, i32)> {
    let mut entries: Vec<rust_sanitize::secrets::SecretEntry> = Vec::new();

    for p in &args.patterns {
        entries.push(rust_sanitize::secrets::SecretEntry {
            pattern: p.clone(),
            kind: "regex".to_string(),
            category: "auth_token".to_string(),
            label: None,
            values: vec![],
            min_length: None,
            max_length: None,
            threshold: None,
            charset: None,
        });
    }

    if let Some(ref path) = args.secrets_file {
        let bytes =
            fs::read(path).map_err(|e| (format!("failed to read {}: {e}", path.display()), 1))?;
        let format = SecretsFormat::from_extension(path.to_string_lossy().as_ref());
        let mut file_entries = parse_secrets(&bytes, format)
            .map_err(|e| (format!("failed to parse {}: {e}", path.display()), 1))?;
        file_entries.retain(|e| e.kind != "allow");
        entries.extend(file_entries);
    }

    for app_name in &args.app {
        let bundle = load_app_bundle(app_name).map_err(|e| (e, 1))?;
        let mut bundle_entries = bundle.secrets;
        bundle_entries.retain(|e| e.kind != "allow");
        entries.extend(bundle_entries);
    }

    if entries.is_empty() {
        return Err((
            "no patterns to test — provide --pattern, --secrets-file, or --app".into(),
            1,
        ));
    }

    struct CompiledPattern {
        label: String,
        category: String,
        regex: regex::Regex,
    }

    let mut compiled: Vec<CompiledPattern> = Vec::new();
    let mut compile_errors: Vec<String> = Vec::new();

    for entry in &entries {
        if entry.pattern.is_empty() {
            continue;
        }
        let label = entry
            .label
            .clone()
            .unwrap_or_else(|| entry.pattern.chars().take(40).collect());
        let (regex_str, _is_literal) = if entry.kind == "literal" {
            (regex::escape(&entry.pattern), true)
        } else {
            (entry.pattern.clone(), false)
        };
        match regex::Regex::new(&regex_str) {
            Ok(re) => compiled.push(CompiledPattern {
                label,
                category: entry.category.clone(),
                regex: re,
            }),
            Err(e) => compile_errors.push(format!("  pattern '{}': {e}", entry.pattern)),
        }
    }

    if !compile_errors.is_empty() {
        for e in &compile_errors {
            eprintln!("warning: pattern failed to compile — {e}");
        }
    }
    if compiled.is_empty() {
        return Err(("all patterns failed to compile".into(), 1));
    }

    let values: Vec<String> = if args.values.is_empty() {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| (format!("failed to read stdin: {e}"), 1))?;
        buf.lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect()
    } else {
        args.values.clone()
    };

    if values.is_empty() {
        return Err((
            "no values to test — provide values as arguments or via stdin".into(),
            1,
        ));
    }

    struct MatchHit {
        label: String,
        category: String,
        matched_text: String,
        start: usize,
        end: usize,
        partial: bool,
    }

    struct ValueResult {
        value: String,
        hits: Vec<MatchHit>,
    }

    let results: Vec<ValueResult> = values
        .iter()
        .map(|value| {
            let mut hits = Vec::new();
            for cp in &compiled {
                if let Some(m) = cp.regex.captures(value) {
                    let (span, partial) = if let Some(g1) = m.get(1) {
                        (g1, true)
                    } else {
                        (
                            m.get(0)
                                .expect("group 0 is always Some on a successful captures call"),
                            false,
                        )
                    };
                    hits.push(MatchHit {
                        label: cp.label.clone(),
                        category: cp.category.clone(),
                        matched_text: span.as_str().to_string(),
                        start: span.start(),
                        end: span.end(),
                        partial,
                    });
                }
            }
            ValueResult {
                value: value.clone(),
                hits,
            }
        })
        .collect();

    let total_matched = results.iter().filter(|r| !r.hits.is_empty()).count();

    if args.json {
        #[derive(serde::Serialize)]
        struct JsonHit<'a> {
            label: &'a str,
            category: &'a str,
            matched_text: &'a str,
            start: usize,
            end: usize,
            partial: bool,
        }
        #[derive(serde::Serialize)]
        struct JsonResult<'a> {
            value: &'a str,
            matched: bool,
            hits: Vec<JsonHit<'a>>,
        }
        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            patterns_loaded: usize,
            results: Vec<JsonResult<'a>>,
            summary: JsonSummary,
        }
        #[derive(serde::Serialize)]
        struct JsonSummary {
            total: usize,
            matched: usize,
            unmatched: usize,
        }
        let out = JsonOutput {
            patterns_loaded: compiled.len(),
            results: results
                .iter()
                .map(|r| JsonResult {
                    value: &r.value,
                    matched: !r.hits.is_empty(),
                    hits: r
                        .hits
                        .iter()
                        .map(|h| JsonHit {
                            label: &h.label,
                            category: &h.category,
                            matched_text: &h.matched_text,
                            start: h.start,
                            end: h.end,
                            partial: h.partial,
                        })
                        .collect(),
                })
                .collect(),
            summary: JsonSummary {
                total: results.len(),
                matched: total_matched,
                unmatched: results.len() - total_matched,
            },
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
        );
    } else {
        println!(
            "Testing {} pattern(s) against {} value(s)\n",
            compiled.len(),
            values.len()
        );
        for r in &results {
            if r.hits.is_empty() {
                println!("✗  {}", r.value);
                println!("   (no match)\n");
            } else {
                println!("✓  {}", r.value);
                for h in &r.hits {
                    let span_note = if h.partial {
                        format!(
                            "bytes {}..{} (partial — prefix/suffix preserved)",
                            h.start, h.end
                        )
                    } else {
                        format!("bytes {}..{} (full match)", h.start, h.end)
                    };
                    println!(
                        "   {:<30}  [{}]  {:?}  {}",
                        h.label, h.category, h.matched_text, span_note
                    );
                }
                println!();
            }
        }
        println!("{}/{} values matched", total_matched, results.len());
    }

    if total_matched < results.len() {
        Err(("some values did not match any pattern".into(), 1))
    } else {
        Ok(())
    }
}

pub(crate) fn run_allow_test(args: &AllowTestArgs) -> Result<(), (String, i32)> {
    use rust_sanitize::allowlist::AllowlistMatcher;

    let (matcher, warnings) = AllowlistMatcher::new(args.allow.clone());
    for w in &warnings {
        eprintln!("warning: {w}");
    }

    let values: Vec<String> = if args.values.is_empty() {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| (format!("failed to read stdin: {e}"), 1))?;
        buf.lines()
            .map(|l| l.to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        args.values.clone()
    };

    if values.is_empty() {
        return Err((
            "no values to test — provide values as arguments or via stdin".into(),
            1,
        ));
    }

    #[derive(serde::Serialize)]
    struct MatchResult<'a> {
        value: &'a str,
        allowed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pattern: Option<&'a str>,
    }

    let results: Vec<MatchResult> = values
        .iter()
        .map(|v| {
            let pattern = matcher.match_pattern(v);
            MatchResult {
                value: v,
                allowed: pattern.is_some(),
                pattern,
            }
        })
        .collect();

    if args.json {
        let allowed = results.iter().filter(|r| r.allowed).count();
        #[derive(serde::Serialize)]
        struct Output<'a> {
            results: Vec<MatchResult<'a>>,
            summary: Summary,
        }
        #[derive(serde::Serialize)]
        struct Summary {
            total: usize,
            allowed: usize,
            blocked: usize,
        }
        let out = Output {
            summary: Summary {
                total: results.len(),
                allowed,
                blocked: results.len() - allowed,
            },
            results,
        };
        match serde_json::to_string_pretty(&out) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("allow-test: failed to serialize JSON output: {e}"),
        }
    } else {
        for r in &results {
            if r.allowed {
                println!("✓  {:<40}  → {}", r.value, r.pattern.unwrap_or(""));
            } else {
                println!("✗  {:<40}  (no match)", r.value);
            }
        }
        let allowed = results.iter().filter(|r| r.allowed).count();
        println!("\n{}/{} values allowed", allowed, results.len());
    }

    Ok(())
}

pub(crate) fn run_template(args: &TemplateArgs) -> Result<(), (String, i32)> {
    let preset = parse_template_preset(&args.preset).map_err(|e| (e, 1))?;

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("secrets.template.{}.yaml", args.preset)));

    if output_path.exists() && !args.overwrite {
        return Err((
            format!(
                "{} already exists — use --overwrite to replace it",
                output_path.display()
            ),
            1,
        ));
    }

    let body = match preset {
        TemplatePreset::Generic => template_body_generic(),
        TemplatePreset::Web => template_body_web(),
        TemplatePreset::K8s => template_body_k8s(),
        TemplatePreset::Database => template_body_database(),
        TemplatePreset::Aws => template_body_aws(),
    };

    let mut content = String::with_capacity(TEMPLATE_HEADER.len() + body.len());
    content.push_str(TEMPLATE_HEADER);
    content.push('\n');
    content.push_str(body);

    atomic_write(&output_path, content.as_bytes())
        .map_err(|e| (format!("failed to write {}: {e}", output_path.display()), 1))?;

    eprintln!("Template written to {}", output_path.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!(
        "  1. Edit {} to add your own patterns and remove irrelevant ones.",
        output_path.display()
    );
    eprintln!(
        "  2. Encrypt:  sanitize encrypt {} {}.enc",
        output_path.display(),
        output_path.display()
    );
    eprintln!(
        "  3. Sanitize: sanitize <input> -s {}.enc -o <output>",
        output_path.display()
    );
    eprintln!();
    eprintln!("WARNING: always review sanitized output before sending to an LLM.");

    Ok(())
}

pub(crate) fn normalize_guided_output_path(path: PathBuf) -> PathBuf {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        Some(ext) if ext == "yaml" || ext == "yml" => path,
        _ => path.with_extension("yaml"),
    }
}

pub(crate) fn run_guided() -> Result<(), (String, i32)> {
    use rust_sanitize::secrets::encrypt_secrets;

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err((
            "guided mode requires an interactive terminal (TTY)".into(),
            1,
        ));
    }

    eprintln!("Guided setup: logs-focused secrets template");
    eprintln!("This wizard creates a starter file you can extend later.\n");

    eprintln!("Workspace type (affects which patterns are included):");
    eprintln!("  1) Generic     — tokens, emails, IPs, hostnames, UUIDs");
    eprintln!("  2) Web app     — JWTs, session cookies, emails, URLs");
    eprintln!("  3) Kubernetes  — service accounts, tokens, namespaces");
    eprintln!("  4) Database    — passwords, connection strings, usernames");
    eprintln!("  5) AWS         — access keys, ARNs, account IDs");
    let preset = loop {
        let answer = prompt_line("Select [1-5] (default: 1): ").map_err(|e| (e, 1))?;
        match answer.as_str() {
            "" | "1" => break GuidedPreset::Balanced,
            "2" => break GuidedPreset::WebApp,
            "3" => break GuidedPreset::Kubernetes,
            "4" => break GuidedPreset::Database,
            "5" => break GuidedPreset::Aggressive,
            _ => eprintln!("Please enter a number from 1 to 5."),
        }
    };

    eprintln!("\nReplacement strictness:");
    eprintln!("  1) Balanced    — replace clearly sensitive values only");
    eprintln!("  2) Aggressive  — replace high-entropy tokens too (recommended for LLMs)");
    let aggressive = loop {
        let answer = prompt_line("Select [1/2] (default: 2): ").map_err(|e| (e, 1))?;
        match answer.as_str() {
            "" | "2" => break true,
            "1" => break false,
            _ => eprintln!("Please enter 1 or 2."),
        }
    };

    let domains = prompt_domains().map_err(|e| (e, 1))?;
    let providers = prompt_cloud_providers().map_err(|e| (e, 1))?;
    eprintln!();
    let formats = prompt_formats().map_err(|e| (e, 1))?;
    let exclude_noise_ids = prompt_yes_no(
        "\nExclude noisy IDs (trace_id/span_id-like high-entropy values)?",
        true,
    )
    .map_err(|e| (e, 1))?;

    let out_raw = prompt_line("\nOutput secrets file path (YAML; default: secrets.guided.yaml): ")
        .map_err(|e| (e, 1))?;
    let requested_output_path = if out_raw.trim().is_empty() {
        PathBuf::from("secrets.guided.yaml")
    } else {
        PathBuf::from(out_raw)
    };
    let output_path = normalize_guided_output_path(requested_output_path.clone());
    if output_path != requested_output_path {
        eprintln!(
            "Guided mode writes YAML templates; using {}",
            output_path.display()
        );
    }

    let options = GuidedOptions {
        preset: if aggressive {
            match preset {
                GuidedPreset::Balanced => GuidedPreset::Aggressive,
                other => other,
            }
        } else {
            preset
        },
        domains,
        providers,
        exclude_noise_ids,
        formats,
    };
    let entries = build_guided_entries(&options);

    let (_patterns, compile_warnings) = entries_to_patterns(&entries);
    if !compile_warnings.is_empty() {
        return Err((
            format!(
                "generated template had {} invalid pattern(s)",
                compile_warnings.len()
            ),
            1,
        ));
    }

    let plain = serialize_secrets(&entries, SecretsFormat::Yaml)
        .map_err(|e| (format!("failed to serialize template: {e}"), 1))?;

    if output_path.exists()
        && !prompt_yes_no(
            &format!("{} already exists. Overwrite?", output_path.display()),
            false,
        )
        .map_err(|e| (e, 1))?
    {
        return Err(("aborted by user".into(), 1));
    }

    atomic_write(&output_path, &plain)
        .map_err(|e| (format!("failed to write {}: {e}", output_path.display()), 1))?;

    eprintln!(
        "Generated {} entries at {}",
        entries.len(),
        output_path.display()
    );

    let profile_path: Option<PathBuf> = if options.formats.is_empty() {
        None
    } else {
        let profiles = build_guided_profiles(&options);
        let profile_yaml = serde_yaml_ng::to_string(&profiles)
            .map_err(|e| (format!("failed to serialize profile: {e}"), 1))?;

        let default_profile_name = output_path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|stem| format!("{stem}.profile.yaml"))
            .unwrap_or_else(|| "profile.guided.yaml".to_string());

        let prof_raw = prompt_line(&format!(
            "Output profile file path (default: {default_profile_name}): "
        ))
        .map_err(|e| (e, 1))?;
        let prof_path = if prof_raw.trim().is_empty() {
            PathBuf::from(&default_profile_name)
        } else {
            PathBuf::from(prof_raw)
        };

        if prof_path.exists()
            && !prompt_yes_no(
                &format!("{} already exists. Overwrite?", prof_path.display()),
                false,
            )
            .map_err(|e| (e, 1))?
        {
            return Err(("aborted by user".into(), 1));
        }

        let mut content = String::with_capacity(PROFILE_HEADER.len() + 1 + profile_yaml.len());
        content.push_str(PROFILE_HEADER);
        content.push('\n');
        content.push_str(&profile_yaml);

        atomic_write(&prof_path, content.as_bytes())
            .map_err(|e| (format!("failed to write {}: {e}", prof_path.display()), 1))?;

        eprintln!(
            "Generated {} profile rule(s) at {} (safe to commit — no secrets inside)",
            profiles.len(),
            prof_path.display()
        );
        Some(prof_path)
    };

    let encrypt =
        prompt_yes_no("Encrypt the generated secrets file now?", true).map_err(|e| (e, 1))?;
    let mut secrets_for_run = output_path.clone();
    let mut run_password: Option<Zeroizing<String>> = None;
    let mut run_unencrypted = true;

    if encrypt {
        let pw = prompt_confirm_password().map_err(|e| (e, 1))?;
        let encrypted = encrypt_secrets(&plain, &pw)
            .map_err(|e| (format!("failed to encrypt guided secrets file: {e}"), 1))?;
        let encrypted_path = PathBuf::from(format!("{}.enc", output_path.display()));
        atomic_write(&encrypted_path, &encrypted).map_err(|e| {
            (
                format!("failed to write {}: {e}", encrypted_path.display()),
                1,
            )
        })?;
        eprintln!("Encrypted template written to {}", encrypted_path.display());
        if let Err(e) = fs::remove_file(&output_path) {
            eprintln!(
                "Warning: could not remove plaintext file {}: {e}",
                output_path.display()
            );
        } else {
            eprintln!("Plaintext file {} removed.", output_path.display());
        }
        secrets_for_run = encrypted_path;
        run_password = Some(pw);
        run_unencrypted = false;
    }

    let run_now =
        prompt_yes_no("Run sanitize now with this secrets file?", true).map_err(|e| (e, 1))?;
    if !run_now {
        let profile_flag = profile_path
            .as_ref()
            .map(|p| format!(" --profile {}", p.display()))
            .unwrap_or_default();
        eprintln!(
            "Next: sanitize <input> -s {}{}",
            secrets_for_run.display(),
            profile_flag
        );
        return Ok(());
    }

    let input_raw = prompt_line("Input file path (or '-' for stdin): ").map_err(|e| (e, 1))?;
    let input = if input_raw.trim().is_empty() {
        return Err(("input file path is required to run sanitize now".into(), 1));
    } else {
        PathBuf::from(input_raw)
    };

    let out_raw =
        prompt_line("Output path (optional; blank = stdout/default): ").map_err(|e| (e, 1))?;
    let output = if out_raw.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(out_raw))
    };

    let dry_run = prompt_yes_no("Dry-run first?", true).map_err(|e| (e, 1))?;
    let deterministic =
        prompt_yes_no("Use deterministic replacements?", true).map_err(|e| (e, 1))?;

    let mut deterministic_password: Option<Zeroizing<String>> = run_password.clone();
    if deterministic && deterministic_password.is_none() {
        deterministic_password = Some(prompt_password("deterministic seed").map_err(|e| (e, 1))?);
    }

    let cli = Cli {
        input: vec![input],
        output,
        secrets_file: Some(secrets_for_run),
        profile: profile_path,
        encrypted_secrets: !run_unencrypted,
        dry_run,
        deterministic,
        ..Cli::default()
    };

    run_sanitize(cli, deterministic_password.or(run_password), HashMap::new())
}
