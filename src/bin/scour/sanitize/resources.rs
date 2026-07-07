//! Per-run resource loading: secrets, patterns, allowlist, scanner, registry,
//! profiles, and entropy configuration assembled from the resolved `Cli`.

use super::*;

struct LoadedSecrets {
    patterns: Vec<ScanPattern>,
    allow_patterns: Vec<String>,
    entropy_configs: Vec<EntropyConfig>,
    raw_bytes: Zeroizing<Vec<u8>>,
    /// Decrypted plaintext for encrypted secrets files; `None` for plaintext files.
    /// Stored here so `apply_field_name_signals` can reuse it without a second
    /// Argon2id+AES-GCM round.
    plaintext_bytes: Option<Zeroizing<Vec<u8>>>,
    /// Whether the file on disk was AES-256-GCM encrypted. The structured
    /// handoff must re-encrypt on write-back when this is set.
    was_encrypted: bool,
    /// Extension-derived plaintext format, used so the handoff write-back
    /// preserves the file's own format instead of assuming YAML.
    format: Option<SecretsFormat>,
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
    let loaded = scour_secrets::secrets::load_secrets_auto(
        &raw_bytes,
        password,
        secrets_format,
        !cli.encrypted_secrets,
    )
    .map_err(|e| (format!("failed to load secrets: {e}"), 1))?;
    let (patterns, warnings, allow_patterns, was_encrypted) = (
        loaded.patterns,
        loaded.warnings,
        loaded.allow_patterns,
        loaded.was_encrypted,
    );

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
        was_encrypted,
        format: secrets_format,
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

pub(super) struct RunResources {
    pub(super) scanner: Arc<StreamScanner>,
    pub(super) store: Arc<MappingStore>,
    pub(super) registry: Arc<ProcessorRegistry>,
    pub(super) profiles: Vec<scour_secrets::FileTypeProfile>,
    pub(super) entropy_configs: Arc<Vec<EntropyConfig>>,
    pub(super) entropy_histogram_acc: Option<Arc<Mutex<Vec<EntropyBuckets>>>>,
    pub(super) base_patterns: Vec<ScanPattern>,
    pub(super) scan_config: ScanConfig,
    /// Password retained for the structured-handoff write-back: an encrypted
    /// secrets file is re-encrypted with the same password after discovered
    /// literals are merged. `None` for plaintext runs. Zeroized on drop.
    pub(super) secrets_password: Option<Zeroizing<String>>,
    /// Whether the loaded secrets file was encrypted on disk.
    pub(super) secrets_was_encrypted: bool,
    /// Extension-derived secrets file format for format-preserving write-back.
    pub(super) secrets_format: Option<SecretsFormat>,
}

pub(super) fn load_run_resources(
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
        let quick_entries: Vec<SecretEntry> = cli
            .quick
            .iter()
            .map(|p| {
                let (kind, pattern) = if let Some(rx) = p.strip_prefix("regex:") {
                    ("regex", rx)
                } else {
                    ("literal", p.as_str())
                };
                SecretEntry::new(pattern, kind, "auth_token").with_label(format!("quick:{p}"))
            })
            .collect();
        let (patterns, errors) = entries_to_patterns(&quick_entries);
        if !errors.is_empty() {
            let msgs: Vec<String> = errors
                .iter()
                .map(|(i, e)| format!("position {i}: {e}"))
                .collect();
            return Err((
                format!("invalid --quick pattern(s): {}", msgs.join("; ")),
                1,
            ));
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
    // The built-in baseline (generic PII + common tokens) is a floor that app
    // bundles layer on top of: load it for plain runs and for ANY `--app` run.
    // We key off `cli.app` rather than `secrets_file.is_none()` because the app
    // write-back sets secrets_file to the seeded app copy before we get here,
    // which previously suppressed the baseline under `--app`. `--no-baseline`
    // opts out for app-only precision.
    let load_defaults = !cli.no_baseline && (nothing_specified || !cli.app.is_empty());
    if load_defaults {
        all_allow_patterns.extend(common_allow_patterns());
    }

    let allowlist: Option<Arc<scour_secrets::allowlist::AllowlistMatcher>> =
        if all_allow_patterns.is_empty() {
            None
        } else {
            let al_result = scour_secrets::allowlist::AllowlistMatcher::new(all_allow_patterns);
            for w in &al_result.warnings {
                warn!(warning = %w, "allowlist pattern warning");
            }
            let matcher = Arc::new(al_result.matcher);
            info!(patterns = matcher.pattern_count(), "allowlist loaded");
            Some(matcher)
        };
    let length_policy = if cli.randomize_length {
        scour_secrets::LengthPolicy::Randomized
    } else {
        scour_secrets::LengthPolicy::Preserve
    };
    let store = build_store(
        cli.deterministic,
        effective_password.as_ref().map(|s| s.as_str()),
        cli.seed_salt_file.as_deref(),
        cli.max_mappings,
        allowlist,
        length_policy,
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

    let (secrets_was_encrypted, secrets_format) = loaded_secrets
        .as_ref()
        .map_or((false, None), |ls| (ls.was_encrypted, ls.format));

    Ok(RunResources {
        scanner,
        store,
        registry,
        profiles,
        entropy_configs,
        entropy_histogram_acc,
        base_patterns,
        scan_config,
        secrets_password: effective_password,
        secrets_was_encrypted,
        secrets_format,
    })
}
