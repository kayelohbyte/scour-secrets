use crate::cli_args::{InitArgs, InstallHookArgs};
use crate::hooks::{
    global_default_secrets_path, global_settings_path, run_install_hook, sanitize_config_dir,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Per-user default flag values loaded from `~/.config/sanitize/settings.yaml`.
/// Each field mirrors a CLI flag. A `None` / empty value means "not set" and
/// the CLI default applies. An explicit CLI flag always wins over this file.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct Settings {
    /// --app: app bundles to load on every run.
    #[serde(default)]
    pub(crate) app: Vec<String>,
    /// --allow: values to pass through unchanged (exact strings or * globs).
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    /// --fail-on-match: exit 2 when any match is found.
    #[serde(default)]
    pub(crate) fail_on_match: Option<bool>,
    /// --strict: abort on the first error instead of skipping.
    #[serde(default)]
    pub(crate) strict: Option<bool>,
    /// --no-structured-handoff: suppress the structured-to-scanner value handoff.
    #[serde(default)]
    pub(crate) no_structured_handoff: Option<bool>,
    /// --no-field-signal: disable the field-name heuristic.
    #[serde(default)]
    pub(crate) no_field_signal: Option<bool>,
    /// --threads: worker thread count (null = auto-detect).
    #[serde(default)]
    pub(crate) threads: Option<usize>,
    /// --log-format: "human" or "json".
    #[serde(default)]
    pub(crate) log_format: Option<String>,
    /// --log-level: "off", "error", "warn", "info", "debug", or "trace".
    #[serde(default)]
    pub(crate) log_level: Option<String>,
    /// --no-progress: disable progress output.
    #[serde(default)]
    pub(crate) no_progress: Option<bool>,
}

/// Load `~/.config/sanitize/settings.yaml` if it exists. Silently returns
/// defaults when the file is absent or unreadable.
/// Set `SANITIZE_NO_SETTINGS=1` to skip loading entirely (useful in CI).
pub(crate) fn load_settings() -> Settings {
    if std::env::var("SANITIZE_NO_SETTINGS").as_deref() == Ok("1") {
        return Settings::default();
    }
    let path = global_settings_path();
    if !path.exists() {
        return Settings::default();
    }
    match fs::read_to_string(&path) {
        Ok(text) => serde_yaml_ng::from_str(&text).unwrap_or_else(|e| {
            eprintln!(
                "warning: could not parse {}: {e} — ignoring settings",
                path.display()
            );
            Settings::default()
        }),
        Err(e) => {
            eprintln!(
                "warning: could not read {}: {e} — ignoring settings",
                path.display()
            );
            Settings::default()
        }
    }
}

// ── Project-level config (.sanitize.toml) ─────────────────────────────────────

/// Per-directory config loaded from a `.sanitize.toml` file found by walking
/// up from the current working directory.  Applied after `settings.yaml` but
/// before CLI flags, so project config overrides global defaults while CLI
/// flags still win over everything.
///
/// Override the search entirely with `SANITIZE_CONFIG=/path/to/file.toml`.
/// Set `SANITIZE_NO_CONFIG=1` to skip project config loading.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct ProjectConfig {
    /// App bundles to load — additive with, not replacing, CLI `--app`.
    #[serde(default)]
    pub(crate) app: Vec<String>,
    /// Allow-list values — additive with CLI `--allow`.
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    /// Path to a secrets file (relative to the `.sanitize.toml` location).
    pub(crate) secrets_file: Option<PathBuf>,
    /// Whether the secrets file is AES-GCM encrypted.
    pub(crate) encrypted_secrets: Option<bool>,
    /// Path to a profile YAML file (relative to the `.sanitize.toml` location).
    pub(crate) profile: Option<PathBuf>,
    /// Exit 2 when any match is found.
    pub(crate) fail_on_match: Option<bool>,
    /// Abort on the first error instead of skipping.
    pub(crate) strict: Option<bool>,
    /// Suppress auto-save of discovered literal values.
    pub(crate) no_structured_handoff: Option<bool>,
    /// Disable the field-name signal heuristic.
    pub(crate) no_field_signal: Option<bool>,
    /// Path-level exclude patterns (glob). Matched relative to the
    /// `.sanitize.toml` location; patterns without `/` also match the basename.
    #[serde(default)]
    pub(crate) exclude: Vec<String>,
}

/// Search for `.sanitize.toml` starting from `dir` and walking upward.
/// Returns the path of the first file found, or `None`.
pub(crate) fn find_project_config_from(dir: &Path) -> Option<PathBuf> {
    let mut current = dir.to_path_buf();
    loop {
        let candidate = current.join(".sanitize.toml");
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
/// 1. `SANITIZE_NO_CONFIG=1` → skip entirely (returns `None`).
/// 2. `SANITIZE_CONFIG=<path>` → use that file if it exists.
/// 3. Walk up from CWD looking for `.sanitize.toml`.
pub(crate) fn find_project_config() -> Option<PathBuf> {
    if std::env::var("SANITIZE_NO_CONFIG").as_deref() == Ok("1") {
        return None;
    }
    if let Ok(explicit) = std::env::var("SANITIZE_CONFIG") {
        let p = PathBuf::from(&explicit);
        if p.is_file() {
            return Some(p);
        }
        eprintln!("warning: SANITIZE_CONFIG={explicit} does not exist — ignoring");
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    find_project_config_from(&cwd)
}

/// Parse a `.sanitize.toml` file.  Returns `(config, config_dir)` so that
/// relative paths inside the file can be resolved against the file's location.
/// Silently returns defaults on read or parse error.
pub(crate) fn load_project_config(path: &Path) -> (ProjectConfig, PathBuf) {
    let config_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();

    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "warning: could not read {}: {e} — ignoring project config",
                path.display()
            );
            return (ProjectConfig::default(), config_dir);
        }
    };
    let cfg: ProjectConfig = match toml::from_str(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "warning: could not parse {}: {e} — ignoring project config",
                path.display()
            );
            return (ProjectConfig::default(), config_dir);
        }
    };
    (cfg, config_dir)
}

/// Template written to `settings.yaml` by `sanitize init-hook`.
const SETTINGS_TEMPLATE: &str = "\
# sanitize settings
# Values here apply when the corresponding flag is not passed on the command
# line. All fields are optional — uncomment and edit to activate.

# Load these app bundles on every run (--app).
# app:
#   - gitlab
#   - kubernetes

# Values that pass through unchanged, supports * glob patterns (--allow).
# allow:
#   - localhost
#   - \"*.internal\"

# Exit with code 2 when any secrets are found (--fail-on-match).
# fail_on_match: false

# Abort on the first error instead of skipping and continuing (--strict).
# strict: false

# Suppress the structured-to-scanner value handoff (--no-structured-handoff).
# no_structured_handoff: false

# Disable the field-name signal heuristic (--no-field-signal).
# When active, key names matching sensitive keywords (password, secret, token, …)
# are flagged by their value's Shannon entropy even without an explicit FieldRule.
# Default thresholds: 3.0 bits/char for strong keywords, 3.5 for ambiguous ones.
# Override per-signal with kind: field-name entries in your secrets file.
# no_field_signal: false

# Worker thread count — omit for auto-detect (--threads).
# threads: 4

# Log format: \"human\" (default) or \"json\" for SIEM ingestion (--log-format).
# log_format: human

# Log level: off, error, warn (default), info, debug, trace (--log-level).
# Override with SANITIZE_LOG env var.
# log_level: warn

# Disable progress output (--no-progress).
# no_progress: false
";

pub(crate) fn run_show_config() -> Result<(), (String, i32)> {
    let secrets_path = global_default_secrets_path();
    let settings_path = global_settings_path();
    let no_settings = std::env::var("SANITIZE_NO_SETTINGS").as_deref() == Ok("1");
    let no_config = std::env::var("SANITIZE_NO_CONFIG").as_deref() == Ok("1");

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
        println!(" (skipped — SANITIZE_NO_SETTINGS=1)");
    } else if !settings_path.exists() {
        println!(" (not found — run 'sanitize init-hook' to create it)");
    } else {
        println!();

        let settings = load_settings();

        fn show<T: std::fmt::Display>(label: &str, val: Option<T>, default: &str, source: &str) {
            match val {
                Some(v) => println!("  {label:<22} {v}  ({source})"),
                None => println!("  {label:<22} {default}  (default)"),
            }
        }
        fn show_vec(label: &str, v: &[String], default: &str, source: &str) {
            if v.is_empty() {
                println!("  {label:<22} {default}  (default)");
            } else {
                println!("  {label:<22} {}  ({source})", v.join(", "));
            }
        }

        show_vec("app:", &settings.app, "(none)", "from settings");
        show_vec("allow:", &settings.allow, "(none)", "from settings");
        show(
            "fail_on_match:",
            settings.fail_on_match,
            "false",
            "from settings",
        );
        show("strict:", settings.strict, "false", "from settings");
        show(
            "no_structured_handoff:",
            settings.no_structured_handoff,
            "false",
            "from settings",
        );
        show("threads:", settings.threads, "(auto)", "from settings");
        show(
            "log_format:",
            settings.log_format.as_deref().map(|s| s.to_string()),
            "human",
            "from settings",
        );
        show(
            "log_level:",
            settings.log_level.as_deref().map(|s| s.to_string()),
            "warn",
            "from settings",
        );
        show(
            "no_progress:",
            settings.no_progress,
            "false",
            "from settings",
        );
    }

    // ── project config (.sanitize.toml) ──────────────────────────────────────
    println!();
    if no_config {
        println!("Project config: (skipped — SANITIZE_NO_CONFIG=1)");
        return Ok(());
    }
    match find_project_config() {
        None => {
            println!(
                "Project config: (none — no .sanitize.toml found in this directory or its parents)"
            );
        }
        Some(ref path) => {
            println!("Project config: {}", path.display());
            let (pc, config_dir) = load_project_config(path);

            fn show_opt_path(label: &str, val: Option<&Path>, base: &Path) {
                match val {
                    Some(p) => {
                        let resolved = if p.is_absolute() {
                            p.to_path_buf()
                        } else {
                            base.join(p)
                        };
                        println!("  {label:<22} {}", resolved.display());
                    }
                    None => println!("  {label:<22} (not set)"),
                }
            }

            if pc.app.is_empty() {
                println!("  {:<22} (not set)", "app:");
            } else {
                println!("  {:<22} {}", "app:", pc.app.join(", "));
            }
            if pc.allow.is_empty() {
                println!("  {:<22} (not set)", "allow:");
            } else {
                println!("  {:<22} {}", "allow:", pc.allow.join(", "));
            }
            if pc.exclude.is_empty() {
                println!("  {:<22} (none)", "exclude:");
            } else {
                println!("  {:<22}", "exclude:");
                for pat in &pc.exclude {
                    println!("    - {pat}");
                }
            }
            show_opt_path("secrets_file:", pc.secrets_file.as_deref(), &config_dir);
            match pc.encrypted_secrets {
                Some(v) => println!("  {:<22} {v}", "encrypted_secrets:"),
                None => println!("  {:<22} (not set)", "encrypted_secrets:"),
            }
            show_opt_path("profile:", pc.profile.as_deref(), &config_dir);
            match pc.fail_on_match {
                Some(v) => println!("  {:<22} {v}", "fail_on_match:"),
                None => println!("  {:<22} (not set)", "fail_on_match:"),
            }
            match pc.strict {
                Some(v) => println!("  {:<22} {v}", "strict:"),
                None => println!("  {:<22} (not set)", "strict:"),
            }
            match pc.no_structured_handoff {
                Some(v) => println!("  {:<22} {v}", "no_structured_handoff:"),
                None => println!("  {:<22} (not set)", "no_structured_handoff:"),
            }
        }
    }

    Ok(())
}

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

    // ── settings.yaml ─────────────────────────────────────────────────────────
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── find_project_config_from ─────────────────────────────────────────────

    #[test]
    fn find_project_config_from_finds_in_same_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".sanitize.toml");
        fs::write(&config, "").unwrap();
        assert_eq!(find_project_config_from(dir.path()), Some(config));
    }

    #[test]
    fn find_project_config_from_finds_in_parent() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".sanitize.toml");
        fs::write(&config, "").unwrap();
        let child = dir.path().join("subdir/nested");
        fs::create_dir_all(&child).unwrap();
        assert_eq!(find_project_config_from(&child), Some(config));
    }

    #[test]
    fn find_project_config_from_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        // No .sanitize.toml anywhere in this subtree (which is in /tmp).
        // Walk will stop at filesystem root; as long as no .sanitize.toml
        // happens to exist in /tmp or above this returns None.
        let child = dir.path().join("a/b/c");
        fs::create_dir_all(&child).unwrap();
        // Verify there is no config in the temp dir itself either.
        let result = find_project_config_from(&child);
        // It may find one higher up on developer machines, so only assert
        // it doesn't find one *inside* our temp dir.
        if let Some(ref found) = result {
            assert!(!found.starts_with(dir.path()), "should not find config inside temp dir");
        }
    }

    // ── load_project_config ──────────────────────────────────────────────────

    #[test]
    fn load_project_config_parses_valid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".sanitize.toml");
        fs::write(&path, r#"
            app = ["gitlab"]
            allow = ["localhost"]
            fail_on_match = true
        "#).unwrap();
        let (cfg, cfg_dir) = load_project_config(&path);
        assert_eq!(cfg.app, vec!["gitlab"]);
        assert_eq!(cfg.allow, vec!["localhost"]);
        assert_eq!(cfg.fail_on_match, Some(true));
        assert_eq!(cfg_dir, dir.path());
    }

    #[test]
    fn load_project_config_returns_default_on_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".sanitize.toml");
        fs::write(&path, "this is not valid toml ][[[").unwrap();
        let (cfg, _) = load_project_config(&path);
        assert!(cfg.app.is_empty());
        assert!(cfg.allow.is_empty());
        assert_eq!(cfg.fail_on_match, None);
    }

    #[test]
    fn load_project_config_resolves_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".sanitize.toml");
        fs::write(&path, r#"secrets_file = "secrets.yaml""#).unwrap();
        let (cfg, cfg_dir) = load_project_config(&path);
        assert_eq!(cfg.secrets_file, Some(PathBuf::from("secrets.yaml")));
        assert_eq!(cfg_dir, dir.path());
    }
}
