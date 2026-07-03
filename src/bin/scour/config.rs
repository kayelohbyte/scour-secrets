use crate::cli_args::{InitArgs, InstallHookArgs};
use crate::hooks::{
    global_default_secrets_path, global_settings_path, run_install_hook, sanitize_config_dir,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Unified scan configuration loaded from any of the three config files:
///
/// - `~/.config/scour-secrets/settings.yaml`      — global per-user defaults
/// - `<project>/.scour-secrets.yaml`              — per-project defaults (cwd-walk)
/// - `<namespace-dir>/settings.yaml`         — per-namespace defaults (MCP only)
///
/// All fields are optional. An explicit CLI flag always wins over any layer.
/// Lists (`app`, `allow`, `exclude_path`, `include_path`, `context_keywords`)
/// are merged additively across all layers rather than replaced.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct SanitizeConfig {
    // --- Additive lists -------------------------------------------------
    /// App bundles to load. Merged across all layers; CLI `--app` appends further.
    #[serde(default)]
    pub(crate) app: Vec<String>,
    /// Allow-list patterns (exact, glob, or `regex:<pat>`). Merged across layers.
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    /// Path glob patterns to exclude. Merged across layers.
    #[serde(default)]
    pub(crate) exclude_path: Vec<String>,
    /// Path glob patterns to include (directory walks only). Merged across layers.
    #[serde(default)]
    pub(crate) include_path: Vec<String>,
    /// Extra context-extraction keywords. Merged with built-in defaults.
    #[serde(default)]
    pub(crate) context_keywords: Vec<String>,

    // --- Source files (project / namespace only) -------------------------
    /// Path to a secrets file, relative to the config file location.
    pub(crate) secrets_file: Option<PathBuf>,
    /// Treat the secrets file as AES-GCM encrypted.
    pub(crate) encrypted_secrets: Option<bool>,
    /// Path to a field-level profile YAML, relative to the config file location.
    pub(crate) profile: Option<PathBuf>,

    // --- Bool scan-behavior flags ----------------------------------------
    /// Exit with code 2 when any match is found (`--fail-on-match`).
    pub(crate) fail_on_match: Option<bool>,
    /// Abort on the first processing error (`--strict`).
    pub(crate) strict: Option<bool>,
    /// Suppress structured-to-scanner value handoff (`--no-structured-handoff`).
    pub(crate) no_structured_handoff: Option<bool>,
    /// Disable the field-name signal heuristic (`--no-field-signal`).
    pub(crate) no_field_signal: Option<bool>,
    /// Bypass all structured processors, streaming scanner only (`--force-text`).
    pub(crate) force_text: Option<bool>,
    /// Process binary entries inside archives (`--include-binary`).
    pub(crate) include_binary: Option<bool>,
    /// Walk hidden files and directories (`--hidden`).
    pub(crate) hidden: Option<bool>,
    /// Replace context_keywords entirely instead of merging (`--context-keywords-replace`).
    pub(crate) context_keywords_replace: Option<bool>,
    /// Case-sensitive keyword matching for context extraction (`--context-case-sensitive`).
    pub(crate) context_case_sensitive: Option<bool>,
    /// Extract keyword-matched log context after sanitization (`--extract-context`).
    pub(crate) extract_context: Option<bool>,

    // --- Option<T> parameters (None = CLI default applies) ---------------
    /// Worker thread count; `null` = auto-detect (`--threads`).
    pub(crate) threads: Option<usize>,
    /// Shannon entropy threshold for high-entropy token detection (`--entropy-threshold`).
    pub(crate) entropy_threshold: Option<f64>,
    /// Log output format: `"human"` or `"json"` (`--log-format`).
    pub(crate) log_format: Option<String>,
    /// Log level: off, error, warn, info, debug, trace (`--log-level`).
    pub(crate) log_level: Option<String>,

    // --- Numeric fields with concrete CLI defaults -----------------------
    /// Streaming chunk size in bytes; default 1 MiB (`--chunk-size`).
    pub(crate) chunk_size: Option<usize>,
    /// Max unique mapping cache entries; default 10 M (`--max-mappings`).
    pub(crate) max_mappings: Option<usize>,
    /// Max structured file size in bytes; default 256 MiB (`--max-structured-size`).
    pub(crate) max_structured_size: Option<u64>,
    /// Max recursive archive nesting depth; default 5 (`--max-archive-depth`).
    pub(crate) max_archive_depth: Option<u32>,
    /// Context lines captured before/after each keyword hit; default 10 (`--context-lines`).
    pub(crate) context_lines: Option<usize>,
    /// Max keyword matches returned per file; default 50 (`--max-context-matches`).
    pub(crate) max_context_matches: Option<usize>,
    /// Max match locations stored per run; default 500 (`--max-match-locations`).
    pub(crate) max_match_locations: Option<usize>,
    /// Progress reporting interval in ms; default 200 (`--progress-interval-ms`).
    pub(crate) progress_interval_ms: Option<u64>,

    // --- Display flags ---------------------------------------------------
    /// Suppress all progress output (`--no-progress`).
    pub(crate) no_progress: Option<bool>,
    /// Suppress non-error output (`--quiet`).
    pub(crate) quiet: Option<bool>,
}

// ---------------------------------------------------------------------------
// Global settings (~/.config/scour/settings.yaml)
// ---------------------------------------------------------------------------

/// Load `~/.config/scour-secrets/settings.yaml`. Silently returns defaults when
/// absent or unreadable. Set `SCOUR_SECRETS_NO_SETTINGS=1` to skip entirely.
pub(crate) fn load_settings() -> SanitizeConfig {
    if std::env::var("SCOUR_SECRETS_NO_SETTINGS").as_deref() == Ok("1") {
        return SanitizeConfig::default();
    }
    let path = global_settings_path();
    load_yaml_config(&path, "settings")
}

// ---------------------------------------------------------------------------
// Project config (.scour-secrets.yaml)
// ---------------------------------------------------------------------------

/// Search for `.scour-secrets.yaml` starting from `dir` and walking upward.
/// Returns the path of the first file found, or `None`.
pub(crate) fn find_project_config_from(dir: &Path) -> Option<PathBuf> {
    let mut current = dir.to_path_buf();
    loop {
        let candidate = current.join(".scour-secrets.yaml");
        if candidate.is_file() {
            return Some(candidate);
        }
        match current.parent() {
            Some(p) => current = p.to_path_buf(),
            None => return None,
        }
    }
}

/// Locate the project config to load.
///
/// Resolution order:
/// 1. `SCOUR_SECRETS_NO_CONFIG=1` → skip (returns `None`).
/// 2. `SCOUR_SECRETS_CONFIG=<path>` → use that file if it exists.
/// 3. Walk up from CWD looking for `.scour-secrets.yaml`.
pub(crate) fn find_project_config() -> Option<PathBuf> {
    if std::env::var("SCOUR_SECRETS_NO_CONFIG").as_deref() == Ok("1") {
        return None;
    }
    if let Ok(explicit) = std::env::var("SCOUR_SECRETS_CONFIG") {
        let p = PathBuf::from(&explicit);
        if p.is_file() {
            return Some(p);
        }
        eprintln!("warning: SCOUR_SECRETS_CONFIG={explicit} does not exist — ignoring");
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    find_project_config_from(&cwd)
}

/// Parse a `.scour-secrets.yaml` file. Returns `(config, config_dir)` so relative
/// paths inside the file can be resolved against the file's location.
/// Silently returns defaults on read or parse error.
pub(crate) fn load_project_config(path: &Path) -> (SanitizeConfig, PathBuf) {
    let config_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    (load_yaml_config(path, "project config"), config_dir)
}

// ---------------------------------------------------------------------------
// Shared YAML loader
// ---------------------------------------------------------------------------

fn load_yaml_config(path: &Path, label: &str) -> SanitizeConfig {
    if !path.exists() {
        return SanitizeConfig::default();
    }
    match fs::read_to_string(path) {
        Ok(text) => serde_yaml_ng::from_str(&text).unwrap_or_else(|e| {
            eprintln!(
                "warning: could not parse {} {}: {e} — ignoring",
                label,
                path.display()
            );
            SanitizeConfig::default()
        }),
        Err(e) => {
            eprintln!(
                "warning: could not read {} {}: {e} — ignoring",
                label,
                path.display()
            );
            SanitizeConfig::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Template written to `settings.yaml` by `scour-secrets init-hook`.
pub(crate) const SETTINGS_TEMPLATE: &str = "\
# sanitize settings  (~/.config/scour/settings.yaml)
# Values here become defaults for every run. Explicit CLI flags always win.
# All fields are optional — uncomment and edit to activate.

# ── Pattern loading ──────────────────────────────────────────────────────────

# App bundles to load on every run (--app). Additive with --app on the CLI.
# app:
#   - gitlab
#   - kubernetes

# Values that pass through unchanged; supports * glob and regex:<pat> (--allow).
# allow:
#   - localhost
#   - \"*.internal\"

# ── Path filtering ───────────────────────────────────────────────────────────

# Glob patterns to skip when walking directories (--exclude-path).
# exclude_path:
#   - \"*.test.yaml\"
#   - \"fixtures/**\"

# Glob patterns to restrict directory walks to (--include-path).
# include_path:
#   - \"**/*.log\"
#   - \"**/*.conf\"

# ── Scan behavior ────────────────────────────────────────────────────────────

# Exit with code 2 when any match is found (--fail-on-match).
# fail_on_match: false

# Abort on the first processing error (--strict).
# strict: false

# Suppress the structured-to-scanner value handoff (--no-structured-handoff).
# no_structured_handoff: false

# Disable the field-name signal heuristic (--no-field-signal).
# no_field_signal: false

# Bypass all structured processors; streaming scanner only (--force-text).
# force_text: false

# Process binary entries inside archives (--include-binary).
# include_binary: false

# Walk hidden files and directories (--hidden).
# hidden: false

# Shannon entropy threshold for high-entropy token detection (--entropy-threshold).
# entropy_threshold: 4.5

# ── Performance ──────────────────────────────────────────────────────────────

# Worker thread count; omit for auto-detect (--threads).
# threads: 4

# Streaming chunk size in bytes (--chunk-size). Default: 1048576 (1 MiB).
# chunk_size: 1048576

# Max unique mapping cache entries (--max-mappings). Default: 10000000.
# max_mappings: 10000000

# Max structured file size in bytes (--max-structured-size). Default: 268435456.
# max_structured_size: 268435456

# Max recursive archive nesting depth (--max-archive-depth). Default: 5.
# max_archive_depth: 5

# ── Context extraction ───────────────────────────────────────────────────────

# Enable keyword-matched log context extraction (--extract-context).
# extract_context: false

# Context lines captured before/after each hit (--context-lines). Default: 10.
# context_lines: 10

# Extra keywords to flag in addition to built-in defaults (--context-keywords).
# context_keywords:
#   - timeout
#   - oomkilled

# Replace built-in keyword list entirely (--context-keywords-replace).
# context_keywords_replace: false

# Case-sensitive keyword matching (--context-case-sensitive).
# context_case_sensitive: false

# Max keyword matches returned per file (--max-context-matches). Default: 50.
# max_context_matches: 50

# ── Display ──────────────────────────────────────────────────────────────────

# Log output format: \"human\" (default) or \"json\" for SIEM ingestion (--log-format).
# log_format: human

# Log level: off, error, warn (default), info, debug, trace (--log-level).
# log_level: warn

# Suppress progress output (--no-progress).
# no_progress: false

# Suppress non-error output entirely (--quiet).
# quiet: false
";

// ---------------------------------------------------------------------------
// show-config
// ---------------------------------------------------------------------------

pub(crate) fn run_show_config() -> Result<(), (String, i32)> {
    let secrets_path = global_default_secrets_path();
    let settings_path = global_settings_path();
    let no_settings = std::env::var("SCOUR_SECRETS_NO_SETTINGS").as_deref() == Ok("1");
    let no_config = std::env::var("SCOUR_SECRETS_NO_CONFIG").as_deref() == Ok("1");

    println!("Config directory: {}", sanitize_config_dir().display());
    println!();

    // ── secrets file ──────────────────────────────────────────────────────────
    print!("Secrets:  {}", secrets_path.display());
    if secrets_path.exists() {
        println!(" (found — auto-loaded when --secrets-file is not given)");
    } else {
        println!(" (not found — will be created automatically on the next plain run)");
    }

    // ── settings file ─────────────────────────────────────────────────────────
    println!();
    print!("Settings: {}", settings_path.display());
    if no_settings {
        println!(" (skipped — SCOUR_SECRETS_NO_SETTINGS=1)");
    } else if !settings_path.exists() {
        println!(" (not found — run 'sanitize init-hook' to create it)");
    } else {
        println!();
        let s = load_settings();
        show_config_fields(&s, None);
    }

    // ── project config (.scour-secrets.yaml) ──────────────────────────────────────
    println!();
    if no_config {
        println!("Project config: (skipped — SCOUR_SECRETS_NO_CONFIG=1)");
        return Ok(());
    }
    match find_project_config() {
        None => {
            println!(
                "Project config: (none — no .scour-secrets.yaml found in this directory or its parents)"
            );
        }
        Some(ref path) => {
            println!("Project config: {}", path.display());
            let (pc, config_dir) = load_project_config(path);
            show_config_fields(&pc, Some(&config_dir));
        }
    }

    Ok(())
}

fn show_config_fields(cfg: &SanitizeConfig, config_dir: Option<&Path>) {
    fn list(label: &str, v: &[String]) {
        if v.is_empty() {
            println!("  {label:<26} (not set)");
        } else {
            println!("  {label:<26} {}", v.join(", "));
        }
    }
    fn opt<T: std::fmt::Display>(label: &str, v: Option<T>) {
        match v {
            Some(ref val) => println!("  {label:<26} {val}"),
            None => println!("  {label:<26} (not set)"),
        }
    }
    fn path_field(label: &str, v: Option<&Path>, base: Option<&Path>) {
        match v {
            Some(p) => {
                let resolved = if p.is_absolute() {
                    p.to_path_buf()
                } else if let Some(b) = base {
                    b.join(p)
                } else {
                    p.to_path_buf()
                };
                println!("  {label:<26} {}", resolved.display());
            }
            None => println!("  {label:<26} (not set)"),
        }
    }

    list("app:", &cfg.app);
    list("allow:", &cfg.allow);
    list("exclude_path:", &cfg.exclude_path);
    list("include_path:", &cfg.include_path);
    if config_dir.is_some() {
        path_field("secrets_file:", cfg.secrets_file.as_deref(), config_dir);
        opt("encrypted_secrets:", cfg.encrypted_secrets);
        path_field("profile:", cfg.profile.as_deref(), config_dir);
    }
    opt("fail_on_match:", cfg.fail_on_match);
    opt("strict:", cfg.strict);
    opt("no_structured_handoff:", cfg.no_structured_handoff);
    opt("no_field_signal:", cfg.no_field_signal);
    opt("force_text:", cfg.force_text);
    opt("include_binary:", cfg.include_binary);
    opt("hidden:", cfg.hidden);
    opt("entropy_threshold:", cfg.entropy_threshold);
    opt("threads:", cfg.threads);
    opt("chunk_size:", cfg.chunk_size);
    opt("max_archive_depth:", cfg.max_archive_depth);
    opt("extract_context:", cfg.extract_context);
    opt("context_lines:", cfg.context_lines);
    list("context_keywords:", &cfg.context_keywords);
    opt("context_keywords_replace:", cfg.context_keywords_replace);
    opt("max_context_matches:", cfg.max_context_matches);
    opt(
        "log_format:",
        cfg.log_format.as_deref().map(|s| s.to_string()),
    );
    opt(
        "log_level:",
        cfg.log_level.as_deref().map(|s| s.to_string()),
    );
    opt("no_progress:", cfg.no_progress);
    opt("quiet:", cfg.quiet);
}

// ---------------------------------------------------------------------------
// init-hook
// ---------------------------------------------------------------------------

pub(crate) fn run_init(args: &InitArgs) -> Result<(), (String, i32)> {
    let settings_path = global_settings_path();

    let hook_args = InstallHookArgs {
        hook: args.hook,
        mode: args.mode,
        global: args.global,
        force: args.force,
        remove: false,
        app: None,
        secrets_file: None,
        dry_run: args.dry_run,
    };

    if args.dry_run {
        println!("Would create (dry-run):");
        if settings_path.exists() && !args.force {
            println!(
                "  {} (already exists — use --force to overwrite)",
                settings_path.display()
            );
        } else {
            println!("  {} — persistent flag defaults", settings_path.display());
        }
        println!();
        run_install_hook(&hook_args)?;
        return Ok(());
    }

    if settings_path.exists() && !args.force {
        println!("Settings file already exists: {}", settings_path.display());
        println!("  Use --force to overwrite, or edit it directly.");
    } else {
        if let Some(parent) = settings_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| (format!("failed to create {}: {e}", parent.display()), 1))?;
        }
        fs::write(&settings_path, SETTINGS_TEMPLATE).map_err(|e| {
            (
                format!("failed to write {}: {e}", settings_path.display()),
                1,
            )
        })?;
        println!("Created: {}", settings_path.display());
        println!("  Uncomment fields to set persistent flag defaults.");
    }

    println!();
    run_install_hook(&hook_args)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    // ── find_project_config_from ─────────────────────────────────────────────

    #[test]
    fn find_project_config_from_finds_in_same_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".scour-secrets.yaml");
        fs::write(&config, "").unwrap();
        assert_eq!(find_project_config_from(dir.path()), Some(config));
    }

    #[test]
    fn find_project_config_from_finds_in_parent() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".scour-secrets.yaml");
        fs::write(&config, "").unwrap();
        let child = dir.path().join("subdir/nested");
        fs::create_dir_all(&child).unwrap();
        assert_eq!(find_project_config_from(&child), Some(config));
    }

    #[test]
    fn find_project_config_from_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("a/b/c");
        fs::create_dir_all(&child).unwrap();
        let result = find_project_config_from(&child);
        if let Some(ref found) = result {
            assert!(
                !found.starts_with(dir.path()),
                "should not find config inside temp dir"
            );
        }
    }

    // ── load_project_config ──────────────────────────────────────────────────

    #[test]
    fn load_project_config_parses_all_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".scour-secrets.yaml");
        fs::write(
            &path,
            r#"
app: [gitlab, kubernetes]
allow: [localhost, "*.internal"]
exclude_path: ["*.test.yaml"]
include_path: ["**/*.log"]
secrets_file: secrets.yaml
encrypted_secrets: true
profile: profile.yaml
fail_on_match: true
strict: true
no_structured_handoff: true
no_field_signal: true
force_text: true
include_binary: true
hidden: true
entropy_threshold: 4.5
threads: 8
chunk_size: 2097152
max_archive_depth: 3
context_lines: 5
context_keywords: [timeout, oomkilled]
log_format: json
log_level: debug
no_progress: true
quiet: true
"#,
        )
        .unwrap();
        let (cfg, cfg_dir) = load_project_config(&path);
        assert_eq!(cfg.app, vec!["gitlab", "kubernetes"]);
        assert_eq!(cfg.allow, vec!["localhost", "*.internal"]);
        assert_eq!(cfg.exclude_path, vec!["*.test.yaml"]);
        assert_eq!(cfg.include_path, vec!["**/*.log"]);
        assert_eq!(cfg.secrets_file, Some(PathBuf::from("secrets.yaml")));
        assert_eq!(cfg.encrypted_secrets, Some(true));
        assert_eq!(cfg.profile, Some(PathBuf::from("profile.yaml")));
        assert_eq!(cfg.fail_on_match, Some(true));
        assert_eq!(cfg.strict, Some(true));
        assert_eq!(cfg.no_structured_handoff, Some(true));
        assert_eq!(cfg.no_field_signal, Some(true));
        assert_eq!(cfg.force_text, Some(true));
        assert_eq!(cfg.include_binary, Some(true));
        assert_eq!(cfg.hidden, Some(true));
        assert_eq!(cfg.entropy_threshold, Some(4.5));
        assert_eq!(cfg.threads, Some(8));
        assert_eq!(cfg.chunk_size, Some(2_097_152));
        assert_eq!(cfg.max_archive_depth, Some(3));
        assert_eq!(cfg.context_lines, Some(5));
        assert_eq!(cfg.context_keywords, vec!["timeout", "oomkilled"]);
        assert_eq!(cfg.log_format.as_deref(), Some("json"));
        assert_eq!(cfg.log_level.as_deref(), Some("debug"));
        assert_eq!(cfg.no_progress, Some(true));
        assert_eq!(cfg.quiet, Some(true));
        assert_eq!(cfg_dir, dir.path());
    }

    #[test]
    fn load_project_config_partial_file_fills_rest_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".scour-secrets.yaml");
        fs::write(&path, "app:\n  - gitlab\nfail_on_match: true\n").unwrap();
        let (cfg, _) = load_project_config(&path);
        assert_eq!(cfg.app, vec!["gitlab"]);
        assert_eq!(cfg.fail_on_match, Some(true));
        assert!(cfg.strict.is_none());
        assert!(cfg.secrets_file.is_none());
    }

    #[test]
    fn load_project_config_returns_default_on_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".scour-secrets.yaml");
        fs::write(&path, "this: is: not: valid: ][[[").unwrap();
        let (cfg, _) = load_project_config(&path);
        assert!(cfg.app.is_empty());
        assert!(cfg.fail_on_match.is_none());
    }

    #[test]
    fn load_project_config_resolves_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".scour-secrets.yaml");
        fs::write(&path, "secrets_file: secrets.yaml\n").unwrap();
        let (cfg, cfg_dir) = load_project_config(&path);
        assert_eq!(cfg.secrets_file, Some(PathBuf::from("secrets.yaml")));
        assert_eq!(cfg_dir, dir.path());
    }

    // ── load_settings ────────────────────────────────────────────────────────

    #[test]
    fn load_settings_skips_when_env_var_set() {
        let _guard = env_lock();
        std::env::set_var("SCOUR_SECRETS_NO_SETTINGS", "1");
        let s = load_settings();
        std::env::remove_var("SCOUR_SECRETS_NO_SETTINGS");
        assert!(s.app.is_empty());
        assert!(s.allow.is_empty());
    }

    #[test]
    fn load_settings_returns_default_when_file_missing() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var("SCOUR_SECRETS_NO_SETTINGS");
        #[cfg(windows)]
        std::env::set_var("APPDATA", dir.path());
        #[cfg(not(windows))]
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        let s = load_settings();
        #[cfg(windows)]
        std::env::remove_var("APPDATA");
        #[cfg(not(windows))]
        std::env::remove_var("XDG_CONFIG_HOME");
        assert!(s.app.is_empty());
    }

    #[test]
    fn load_settings_parses_all_fields() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("scour-secrets");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("settings.yaml"),
            "app:\n  - gitlab\nallow:\n  - localhost\nfail_on_match: true\nthreads: 4\nno_progress: true\nforce_text: true\nentropy_threshold: 3.5\n",
        )
        .unwrap();
        std::env::remove_var("SCOUR_SECRETS_NO_SETTINGS");
        #[cfg(windows)]
        std::env::set_var("APPDATA", dir.path());
        #[cfg(not(windows))]
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        let s = load_settings();
        #[cfg(windows)]
        std::env::remove_var("APPDATA");
        #[cfg(not(windows))]
        std::env::remove_var("XDG_CONFIG_HOME");
        assert_eq!(s.app, vec!["gitlab"]);
        assert_eq!(s.allow, vec!["localhost"]);
        assert_eq!(s.fail_on_match, Some(true));
        assert_eq!(s.threads, Some(4));
        assert_eq!(s.no_progress, Some(true));
        assert_eq!(s.force_text, Some(true));
        assert_eq!(s.entropy_threshold, Some(3.5));
    }

    #[test]
    fn load_settings_returns_default_on_malformed_yaml() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("scour-secrets");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("settings.yaml"),
            "this: is: not: valid: ][[[",
        )
        .unwrap();
        std::env::remove_var("SCOUR_SECRETS_NO_SETTINGS");
        #[cfg(windows)]
        std::env::set_var("APPDATA", dir.path());
        #[cfg(not(windows))]
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        let s = load_settings();
        #[cfg(windows)]
        std::env::remove_var("APPDATA");
        #[cfg(not(windows))]
        std::env::remove_var("XDG_CONFIG_HOME");
        assert!(s.app.is_empty());
    }

    // ── find_project_config ──────────────────────────────────────────────────

    #[test]
    fn find_project_config_returns_none_when_disabled() {
        let _guard = env_lock();
        std::env::set_var("SCOUR_SECRETS_NO_CONFIG", "1");
        let result = find_project_config();
        std::env::remove_var("SCOUR_SECRETS_NO_CONFIG");
        assert!(result.is_none());
    }

    #[test]
    fn find_project_config_uses_explicit_env_var() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.yaml");
        fs::write(&path, "").unwrap();
        std::env::remove_var("SCOUR_SECRETS_NO_CONFIG");
        std::env::set_var("SCOUR_SECRETS_CONFIG", path.to_str().unwrap());
        let result = find_project_config();
        std::env::remove_var("SCOUR_SECRETS_CONFIG");
        assert_eq!(result, Some(path));
    }

    #[test]
    fn find_project_config_returns_none_for_nonexistent_explicit_path() {
        let _guard = env_lock();
        std::env::remove_var("SCOUR_SECRETS_NO_CONFIG");
        std::env::set_var("SCOUR_SECRETS_CONFIG", "/nonexistent/path/custom.yaml");
        let result = find_project_config();
        std::env::remove_var("SCOUR_SECRETS_CONFIG");
        assert!(result.is_none());
    }
}
