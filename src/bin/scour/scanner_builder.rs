use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};
use zeroize::Zeroizing;

use scour_secrets::secrets::{entries_to_patterns, parse_category, SecretEntry};
use scour_secrets::{
    atomic_write, FieldNameSignal, HmacGenerator, LengthPolicy, MappingStore, RandomGenerator,
    ReplacementGenerator, ScanConfig, ScanPattern, StreamScanner, DEFAULT_FIELD_SIGNAL_THRESHOLD,
};

/// Environment variable supplying the deterministic seed salt directly.
///
/// To reproduce deterministic output created before per-install salts existed
/// (pre-0.14.2), set this to the legacy constant
/// `scour-secrets:deterministic-seed:v1`.
const SEED_SALT_ENV: &str = "SCOUR_SECRETS_SEED_SALT";

/// Resolve the deterministic seed salt.
///
/// Priority:
/// 1. `--seed-salt-file <PATH>` — file contents used verbatim.
/// 2. `SCOUR_SECRETS_SEED_SALT` env var — string bytes used verbatim.
/// 3. Persisted per-install salt at `<config_dir>/seed-salt`.
/// 4. Freshly generated 32 random bytes, persisted (mode 0600) for reuse.
///
/// Any length is accepted: the resolved salt is SHA-256-normalized to 32 bytes
/// before Argon2id key derivation (Argon2 requires a salt of at least 8 bytes).
fn resolve_seed_salt(
    seed_salt_file: Option<&Path>,
) -> std::result::Result<Zeroizing<Vec<u8>>, String> {
    if let Some(path) = seed_salt_file {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read seed-salt file {}: {e}", path.display()))?;
        if bytes.is_empty() {
            return Err(format!("seed-salt file {} is empty", path.display()));
        }
        return Ok(Zeroizing::new(bytes));
    }

    if let Ok(env) = std::env::var(SEED_SALT_ENV) {
        if !env.is_empty() {
            return Ok(Zeroizing::new(env.into_bytes()));
        }
    }

    let path = crate::hooks::sanitize_config_dir().join("seed-salt");
    resolve_or_create_salt_at(&path)
}

/// Read the persisted salt at `path`, or atomically create and persist a fresh
/// one if it does not yet exist.
///
/// Creation is safe under concurrent first-run processes: a fresh 32-byte salt
/// is written to a unique temp file, then `hard_link`ed into place. `hard_link`
/// fails atomically if the destination already exists, so exactly one process
/// wins; every other process reads the **winner's** salt (the winner finishes
/// writing the temp before linking, so the destination is never observed
/// half-written). This avoids the check-then-write race where each process would
/// otherwise persist — and return — its own salt, producing inconsistent
/// deterministic output across concurrent first runs.
fn resolve_or_create_salt_at(path: &Path) -> std::result::Result<Zeroizing<Vec<u8>>, String> {
    use rand::Rng;

    // Fast path: already persisted (from this or an earlier run).
    if let Some(existing) = read_existing_salt(path)? {
        return Ok(existing);
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create config dir {}: {e}", dir.display()))?;
    }

    // Generate a candidate and write it fully to a unique temp file (0600).
    let mut salt = Zeroizing::new(vec![0u8; 32]);
    rand::rng().fill(salt.as_mut_slice());
    let tmp = path.with_file_name(format!(
        "seed-salt.tmp.{}.{:016x}",
        std::process::id(),
        rand::rng().random::<u64>()
    ));
    write_new_private(&tmp, &salt)
        .map_err(|e| format!("cannot write temp seed-salt {}: {e}", tmp.display()))?;

    // Atomically claim the destination. hard_link errors if it already exists.
    let result = match std::fs::hard_link(&tmp, path) {
        Ok(()) => {
            info!(path = %path.display(), "created a new per-install deterministic seed salt");
            eprintln!(
                "info: created a new per-install deterministic seed salt at {}.\n\
                 info: copy this file (or set {SEED_SALT_ENV}) to reproduce identical output on other machines.",
                path.display()
            );
            Ok(salt)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process won the race — adopt its salt for consistency.
            match read_existing_salt(path)? {
                Some(winner) => Ok(winner),
                None => Err(format!(
                    "seed-salt file {} exists but is empty; delete it to regenerate",
                    path.display()
                )),
            }
        }
        Err(e) => Err(format!(
            "cannot create seed-salt file {}: {e}",
            path.display()
        )),
    };

    let _ = std::fs::remove_file(&tmp);
    result
}

/// Read an existing salt file. Returns `Ok(None)` when the file is absent,
/// `Err` when it exists but is empty (corrupt — the user must remove it).
fn read_existing_salt(path: &Path) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, String> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.is_empty() => Err(format!(
            "seed-salt file {} is empty; delete it to regenerate",
            path.display()
        )),
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "cannot read seed-salt file {}: {e}",
            path.display()
        )),
    }
}

/// Create `path` exclusively (fails if it exists), write `data` with owner-only
/// permissions, and flush to disk. Used for the seed-salt temp file.
fn write_new_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Build an `Arc<MappingStore>` with the chosen generator mode.
pub(crate) fn build_store(
    deterministic: bool,
    password: Option<&str>,
    seed_salt_file: Option<&Path>,
    max_mappings: usize,
    allowlist: Option<Arc<scour_secrets::allowlist::AllowlistMatcher>>,
    length_policy: LengthPolicy,
) -> std::result::Result<Arc<MappingStore>, String> {
    let generator: Arc<dyn ReplacementGenerator> = if deterministic {
        match password {
            Some(k) => {
                use sha2::{Digest, Sha256};
                let salt = resolve_seed_salt(seed_salt_file)?;
                // The seed salt is arbitrary user input (file / env / persisted)
                // and may be shorter than Argon2's 8-byte minimum, so normalize
                // it to a fixed 32-byte salt with SHA-256 before key derivation.
                let mut salt32 = Zeroizing::new([0u8; 32]);
                salt32.copy_from_slice(&Sha256::digest(&*salt));
                let key = scour_secrets::secrets::derive_key_argon2(k.as_bytes(), &*salt32)
                    .map_err(|e| format!("failed to derive deterministic seed: {e}"))?;
                Arc::new(HmacGenerator::new(*key).with_length_policy(length_policy))
            }
            None => {
                return Err(
                    "--deterministic requires --password (or SCOUR_SECRETS_PASSWORD). \
                     A deterministic seed cannot be derived without a key."
                        .into(),
                );
            }
        }
    } else {
        Arc::new(RandomGenerator::new().with_length_policy(length_policy))
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

/// Render the default global secrets file (balanced patterns + allowlist) and
/// write it to `path` atomically.
///
/// Uses [`atomic_write`] (random-suffix temp + rename) so that concurrent
/// first-runs each render the byte-identical default file and rename it into
/// place — a parallel run never observes a half-written or empty file and falls
/// through to running with zero patterns (an unsanitized passthrough). The
/// content is deterministic, so whichever process wins the rename, every reader
/// sees a complete, valid file.
pub(crate) fn write_default_secrets(path: &Path) -> std::result::Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create config dir {}: {e}", parent.display()))?;
    }
    let mut entries = balanced_secret_entries();
    entries.push(SecretEntry::new("", "allow", "").with_values(common_allow_patterns()));
    let yaml = serde_yaml_ng::to_string(&entries)
        .map_err(|e| format!("cannot serialize default secrets: {e}"))?;
    let header = "# Global sanitize secrets — balanced detection patterns + allowlist.\n# Auto-loaded on every plain run. Edit freely; deleted values take effect immediately.\n\n";
    atomic_write(path, format!("{header}{yaml}").as_bytes()).map_err(|e| {
        format!(
            "cannot write default secrets file {}: {e}\nPass --secrets-file or --app explicitly.",
            path.display()
        )
    })
}

/// Build the canonical balanced set of `SecretEntry` values.
///
/// Used both to compile the in-memory scanner and to write the starter
/// `~/.config/scour/secrets.yaml` on first run.
pub(crate) fn balanced_secret_entries() -> Vec<SecretEntry> {
    fn e(pattern: &str, category: &str, label: &str) -> SecretEntry {
        SecretEntry::new(pattern, "regex", category).with_label(label)
    }
    vec![
        e(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "email",
            "email",
        ),
        e(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ipv4", "ipv4"),
        e(
            r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b",
            "ipv6",
            "ipv6_full",
        ),
        e(
            r"\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{0,4}\b|\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b",
            "ipv6",
            "ipv6_compressed",
        ),
        e(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
            "uuid",
            "uuid",
        ),
        e(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            "jwt",
            "jwt",
        ),
        // `credential_url` must precede the generic `url` detector: both match a
        // `https://user:pass@host` span to the same end, and on that tie the
        // earlier pattern wins — so the precise (capture-group) rule has to come
        // first, or every credential-bearing https URL is redacted whole.
        //
        // Capture group 1 is the `user:pass` credential only, so the scheme,
        // host, port, path, and query (`@db.host:5432/orders?sslmode=require`)
        // are preserved for troubleshooting — only the credential is redacted.
        // The username is optional (`{0,128}`) to catch the password-only form
        // `redis://:secret@host`, common for Redis and otherwise missed.
        e(
            r#"[a-z][a-z0-9+.-]+://([^:@\s]{0,128}:[^@\s]{1,128})@[^\s"'<>]+"#,
            "url",
            "credential_url",
        ),
        e(r#"https?://[^\s"'<>;]+"#, "url", "url"),
        e(
            r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----",
            "auth_token",
            "private_key_header",
        ),
        // Capture group 1 is the value only, so the `key=` keyword and any
        // trailing structured context (`,ssl=True`, `&sslmode=require`) are
        // preserved for troubleshooting — only the secret itself is redacted.
        e(
            r#"(?i)(?:api_key|api_secret|access_token|client_secret|private_key|secret_key|auth_key|signing_key|jwt_secret|jwt_key)[\s:="']+([A-Za-z0-9._~+/=-]{16,})"#,
            "auth_token",
            "secret_kv",
        ),
        // Value class excludes the structured separators `, ; &` so a
        // connection-string `password=secret,ssl=True` redacts only `secret`
        // and keeps `,ssl=True`. Capture group 1 keeps the `password=` keyword.
        e(
            r#"(?i)(?:password|passwd|pwd)[\s:="']+([^\s"',;&]{6,})"#,
            "custom:password",
            "password_kv",
        ),
        // Capture only the username segment so the `/home/` prefix and the rest
        // of the path are preserved (`/home/alice/x` → `/home/‹token›/x`). No
        // `.` in the charset: POSIX usernames never contain one, and excluding
        // it stops the match from swallowing file paths like `/home/foo.html`.
        e(
            r"/(?:home|Users)/([A-Za-z0-9_-]+)",
            "file_path",
            "user_home_path",
        ),
        e(r"\bsha256:[a-f0-9]{64}\b", "container_id", "image_digest"),
        e(
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            "mac_address",
            "mac_address",
        ),
        e(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
            "auth_token",
            "github_token",
        ),
        e(
            r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
            "auth_token",
            "github_pat_fine_grained",
        ),
        e(r"\bAIza[A-Za-z0-9_-]{35}\b", "auth_token", "gcp_api_key"),
        // Full set of AWS unique-ID prefixes (access keys, STS, roles, users,
        // groups, etc.) so bundles don't each re-implement an AWS key rule.
        e(
            r"\b(?:ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b",
            "auth_token",
            "aws_access_key_id",
        ),
        e(
            r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b",
            "auth_token",
            "openai_api_key",
        ),
        e(
            r"\bsk-ant-[A-Za-z0-9_-]{93,}\b",
            "auth_token",
            "anthropic_api_key",
        ),
        e(
            r"\bxox[bpars]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b",
            "auth_token",
            "slack_token",
        ),
        e(r"\bnpm_[A-Za-z0-9]{36}\b", "auth_token", "npm_token"),
        e(r"\bhf_[A-Za-z0-9]{34}\b", "auth_token", "huggingface_token"),
        e(
            r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b",
            "auth_token",
            "stripe_key",
        ),
        e(r"\bglpat-[A-Za-z0-9_-]{20}\b", "auth_token", "gitlab_token"),
        e(
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
            "auth_token",
            "sendgrid_api_key",
        ),
        e(r"\bAC[a-f0-9]{32}\b", "auth_token", "twilio_account_sid"),
    ]
}

/// Compile the built-in balanced detection patterns.
pub(crate) fn build_default_patterns() -> Vec<ScanPattern> {
    let (patterns, errors) = entries_to_patterns(&balanced_secret_entries());
    if !errors.is_empty() {
        for (i, err) in &errors {
            warn!(entry = i, error = %err, "built-in default pattern failed to compile");
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
        // Label by category, never the value — labels surface in the report,
        // `--findings`, and the console summary, which must contain no secrets.
        let label = format!("profile-discovered:{category}");
        match ScanPattern::from_literal(s, category, label) {
            Ok(pat) => {
                patterns.push(pat);
                discovered += 1;
            }
            Err(e) => {
                warn!(error = %e, "could not compile discovered literal pattern");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn seed_salt_file_used_verbatim() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"scour-secrets:deterministic-seed:v1").unwrap();
        f.flush().unwrap();
        let salt = resolve_seed_salt(Some(f.path())).unwrap();
        assert_eq!(&salt[..], b"scour-secrets:deterministic-seed:v1");
    }

    #[test]
    fn seed_salt_file_empty_is_error() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = resolve_seed_salt(Some(f.path())).unwrap_err();
        assert!(err.contains("empty"), "expected empty error, got: {err}");
    }

    #[test]
    fn deterministic_requires_password() {
        match build_store(true, None, None, 0, None, LengthPolicy::Preserve) {
            Ok(_) => panic!("expected an error without a password"),
            Err(err) => assert!(err.contains("--password"), "got: {err}"),
        }
    }

    #[test]
    fn default_secrets_write_is_atomic_under_concurrency() {
        // Concurrent first-runs writing the default secrets file must never
        // leave a half-written/empty file that a parallel run would load as zero
        // patterns (an unsanitized passthrough). Every writer must succeed and
        // the final file must always parse to the full balanced entry set.
        use scour_secrets::secrets::parse_secrets;
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("nested").join("secrets.yaml"));
        let n = 16;
        let barrier = Arc::new(Barrier::new(n));
        let expected = balanced_secret_entries().len() + 1; // + allow entry

        let handles: Vec<_> = (0..n)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    write_default_secrets(&path)
                })
            })
            .collect();

        for h in handles {
            h.join()
                .unwrap()
                .expect("every concurrent write must succeed");
        }

        // The persisted file is always complete and parses to the full set.
        let bytes = std::fs::read(&*path).unwrap();
        let entries = parse_secrets(&bytes, None).expect("default secrets file must parse");
        assert_eq!(entries.len(), expected, "incomplete default secrets file");

        // No temp files left behind in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn salt_creation_is_consistent_under_concurrent_first_runs() {
        // Reproduces the first-run race: many processes/threads resolving a
        // fresh salt path at once must all converge on a single persisted salt,
        // or concurrent deterministic runs would produce inconsistent output.
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("sub").join("seed-salt"));
        let n = 16;
        let barrier = Arc::new(Barrier::new(n));

        let handles: Vec<_> = (0..n)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait(); // maximize contention on first creation
                    resolve_or_create_salt_at(&path).unwrap().to_vec()
                })
            })
            .collect();

        let salts: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Every thread must have seen the same salt.
        assert!(
            salts.windows(2).all(|w| w[0] == w[1]),
            "concurrent first-run resolved differing salts: {salts:?}"
        );
        // And it must equal what is persisted on disk.
        let persisted = std::fs::read(&*path).unwrap();
        assert_eq!(persisted.len(), 32, "persisted salt must be 32 bytes");
        assert_eq!(
            salts[0], persisted,
            "returned salt must match persisted file"
        );
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn length_policy_applies_to_both_generator_modes() {
        use scour_secrets::category::Category;

        // Use an explicit seed-salt file for the deterministic arm so the test
        // never touches the per-install config dir.
        let mut salt = tempfile::NamedTempFile::new().unwrap();
        salt.write_all(b"unit-test-salt").unwrap();
        salt.flush().unwrap();

        // A 6-digit phone value: under Randomized it becomes a band-length digit
        // run (>= 8 digits), so its length must differ from the input regardless
        // of which generator mode build_store selected.
        let stores = [
            build_store(false, None, None, 0, None, LengthPolicy::Randomized).unwrap(),
            build_store(
                true,
                Some("pw"),
                Some(salt.path()),
                0,
                None,
                LengthPolicy::Randomized,
            )
            .unwrap(),
        ];
        for store in stores {
            let out = store.get_or_insert(&Category::Phone, "123456").unwrap();
            assert!(out.chars().all(|c| c.is_ascii_digit()), "got: {out}");
            assert!(out.len() >= 8, "randomized digit run must be >= 8: {out}");
        }

        // Sanity: under Preserve the same value keeps its length.
        let store = build_store(false, None, None, 0, None, LengthPolicy::Preserve).unwrap();
        let out = store.get_or_insert(&Category::Phone, "123456").unwrap();
        assert_eq!(out.len(), 6, "preserve must keep length: {out}");
    }
}
