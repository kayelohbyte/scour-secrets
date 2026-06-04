use std::sync::Arc;
use tracing::{info, warn};
use zeroize::Zeroizing;

use rust_sanitize::secrets::{entries_to_patterns, parse_category, SecretEntry};
use rust_sanitize::{
    FieldNameSignal, HmacGenerator, MappingStore, RandomGenerator, ReplacementGenerator,
    ScanConfig, ScanPattern, StreamScanner, DEFAULT_FIELD_SIGNAL_THRESHOLD,
};

use crate::guided::{build_guided_entries, GuidedOptions, GuidedPreset};

/// Build an `Arc<MappingStore>` with the chosen generator mode.
pub(crate) fn build_store(
    deterministic: bool,
    password: Option<&str>,
    max_mappings: usize,
    allowlist: Option<Arc<rust_sanitize::allowlist::AllowlistMatcher>>,
) -> std::result::Result<Arc<MappingStore>, String> {
    let generator: Arc<dyn ReplacementGenerator> = if deterministic {
        match password {
            Some(k) => {
                use hmac::Hmac;
                use sha2::Sha256;
                let mut buf = Zeroizing::new([0u8; 32]);
                let salt = b"rust-sanitize:deterministic-seed:v1";
                pbkdf2::pbkdf2::<Hmac<Sha256>>(k.as_bytes(), salt, 600_000, buf.as_mut())
                    .expect("PBKDF2 output length is valid");
                Arc::new(HmacGenerator::new(*buf))
            }
            None => {
                return Err(
                    "--deterministic requires --password (or SANITIZE_PASSWORD). \
                     A deterministic seed cannot be derived without a key."
                        .into(),
                );
            }
        }
    } else {
        Arc::new(RandomGenerator::new())
    };
    let capacity = if max_mappings == 0 {
        None
    } else {
        Some(max_mappings)
    };
    Ok(Arc::new(match allowlist {
        Some(al) => MappingStore::new_with_allowlist(generator, capacity, al),
        None => MappingStore::new(generator, capacity),
    }))
}

/// Common values that are safe to allow through for any built-in preset.
pub(crate) fn common_allow_patterns() -> Vec<String> {
    vec![
        "127.0.0.1".into(),
        "0.0.0.0".into(),
        "255.255.255.255".into(),
        "255.255.255.0".into(),
        "255.255.0.0".into(),
        "255.0.0.0".into(),
        "::1".into(),
        "localhost".into(),
        "localhost.localdomain".into(),
        "http://localhost*".into(),
        "https://localhost*".into(),
        "http://127.0.0.1*".into(),
        "https://127.0.0.1*".into(),
        "example.com".into(),
        "example.org".into(),
        "example.net".into(),
        "http://example.com*".into(),
        "https://example.com*".into(),
        "https://example.org*".into(),
        "https://example.net*".into(),
        "00000000-0000-0000-0000-000000000000".into(),
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".into(),
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
        "12345678-1234-1234-1234-123456789abc".into(),
        "changeme".into(),
        "example".into(),
        "sample".into(),
        "placeholder".into(),
        "${*}".into(),
        "{{*}}".into(),
    ]
}

/// Compile the built-in balanced detection patterns used by `--default`.
pub(crate) fn build_default_patterns() -> Vec<ScanPattern> {
    let opts = GuidedOptions {
        preset: GuidedPreset::Balanced,
        domains: vec![],
        providers: vec![],
        exclude_noise_ids: false,
        formats: vec![],
    };
    let entries = build_guided_entries(&opts);
    let (patterns, errors) = entries_to_patterns(&entries);
    if !errors.is_empty() {
        for (i, e) in &errors {
            warn!(entry = i, error = %e, "built-in default pattern failed to compile");
        }
    }
    patterns
}

/// Build the two built-in field-name signal groups.
pub(crate) fn builtin_field_name_signals() -> Vec<FieldNameSignal> {
    let specs: &[(&str, &str, f64)] = &[
        (
            r"password|passwd|secret|private_key|api_secret|client_secret",
            "field-signal:strong",
            3.0,
        ),
        (
            r"api_key|access_key|auth_token|token|signing_key|encryption_key|credential|cert",
            "field-signal:medium",
            3.5,
        ),
    ];
    specs
        .iter()
        .filter_map(|(pattern, label, threshold)| {
            match FieldNameSignal::new(
                *pattern,
                parse_category("custom:credential"),
                Some((*label).to_string()),
                *threshold,
            ) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    warn!(error = %e, "built-in field-name signal failed to compile");
                    None
                }
            }
        })
        .collect()
}

/// Extract `kind: field-name` entries from a parsed secrets list and compile
/// them into [`FieldNameSignal`]s.
pub(crate) fn field_signals_from_entries(entries: &[SecretEntry]) -> Vec<FieldNameSignal> {
    entries
        .iter()
        .filter(|e| e.kind == "field-name" && !e.pattern.is_empty())
        .filter_map(|e| {
            let category = parse_category(&e.category);
            let threshold = e.threshold.unwrap_or(DEFAULT_FIELD_SIGNAL_THRESHOLD);
            match FieldNameSignal::new(&e.pattern, category, e.label.clone(), threshold) {
                Ok(sig) => Some(sig),
                Err(err) => {
                    warn!(pattern = %e.pattern, error = %err, "field-name signal skipped");
                    None
                }
            }
        })
        .collect()
}

/// Build an augmented scanner after the profile pass (Phase 1).
pub(crate) fn build_augmented_scanner(
    base_patterns: &[ScanPattern],
    store: &Arc<MappingStore>,
    scan_config: ScanConfig,
) -> std::result::Result<Arc<StreamScanner>, (String, i32)> {
    let mut patterns = base_patterns.to_vec();

    let mut discovered = 0usize;
    for (category, original, _replacement) in store.iter() {
        let s = original.as_str();
        if s.is_empty() {
            continue;
        }
        match ScanPattern::from_literal(s, category, format!("profile-discovered:{s}")) {
            Ok(pat) => {
                patterns.push(pat);
                discovered += 1;
            }
            Err(e) => {
                warn!(value = s, error = %e, "could not compile discovered literal pattern");
            }
        }
    }

    if discovered > 0 {
        info!(
            count = discovered,
            "augmented scanner with profile-discovered literals"
        );
    }

    let scanner = StreamScanner::new(patterns, Arc::clone(store), scan_config)
        .map_err(|e| (format!("failed to create augmented scanner: {e}"), 1))?;
    Ok(Arc::new(scanner))
}

/// Build a `ScanConfig`, validating `chunk_size`.
pub(crate) fn build_scan_config(chunk_size: usize) -> Result<ScanConfig, String> {
    if chunk_size == 0 {
        return Err("--chunk-size must be greater than 0".into());
    }
    let overlap = (chunk_size / 4).clamp(1, 4096);
    if overlap >= chunk_size {
        return Err(format!(
            "--chunk-size ({chunk_size}) is too small; must be > {overlap} bytes"
        ));
    }
    let cfg = ScanConfig::new(chunk_size, overlap);
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}
