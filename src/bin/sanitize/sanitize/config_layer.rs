//! Configuration layering: merge settings and project-config files into the
//! parsed `Cli`, respecting precedence (explicit CLI > project config > global
//! settings > compile-time defaults).

use super::*;

/// Apply a `bool` setting from a config layer: skip if the flag is already set by a higher-priority source.
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

/// Apply a concrete (non-Option) CLI field: only applied when the field still holds its compile-time
/// default, which is the proxy for "not explicitly set on the command line".
macro_rules! apply_concrete_field {
    ($cli:expr, $src:expr, $field:ident, $default:expr) => {
        if $cli.$field == $default {
            if let Some(v) = $src.$field {
                $cli.$field = v;
            }
        }
    };
}

/// Merge one list additively into another, skipping values already present.
fn merge_list(target: &mut Vec<String>, source: Vec<String>) {
    for v in source {
        if !target.contains(&v) {
            target.push(v);
        }
    }
}

fn apply_settings_layer(cli: &mut Cli, s: SanitizeConfig) {
    // Additive lists
    merge_list(&mut cli.app, s.app);
    merge_list(&mut cli.allow, s.allow);
    merge_list(&mut cli.exclude_path, s.exclude_path);
    merge_list(&mut cli.include_path, s.include_path);
    merge_list(&mut cli.context_keywords, s.context_keywords);
    // Bool flags
    apply_bool_flag!(cli, s, fail_on_match);
    apply_bool_flag!(cli, s, strict);
    apply_bool_flag!(cli, s, no_structured_handoff);
    apply_bool_flag!(cli, s, no_field_signal);
    apply_bool_flag!(cli, s, force_text);
    apply_bool_flag!(cli, s, include_binary);
    apply_bool_flag!(cli, s, hidden);
    apply_bool_flag!(cli, s, context_keywords_replace);
    apply_bool_flag!(cli, s, context_case_sensitive);
    apply_bool_flag!(cli, s, extract_context);
    apply_bool_flag!(cli, s, no_progress);
    apply_bool_flag!(cli, s, quiet);
    // Option<T> fields
    apply_opt_field!(cli, s, threads);
    apply_opt_field!(cli, s, entropy_threshold);
    apply_opt_field!(cli, s, log_format);
    apply_opt_field!(cli, s, log_level);
    // Concrete fields: only applied when the CLI still holds the compile-time default.
    apply_concrete_field!(cli, s, chunk_size, 1_048_576_usize);
    apply_concrete_field!(cli, s, max_mappings, 10_000_000_usize);
    apply_concrete_field!(
        cli,
        s,
        max_structured_size,
        DEFAULT_MAX_STRUCTURED_FILE_SIZE
    );
    apply_concrete_field!(cli, s, max_archive_depth, DEFAULT_ARCHIVE_DEPTH);
    apply_concrete_field!(cli, s, context_lines, DEFAULT_CONTEXT_LINES);
    apply_concrete_field!(cli, s, max_context_matches, DEFAULT_MAX_MATCHES);
    apply_concrete_field!(cli, s, max_match_locations, 500_usize);
    apply_concrete_field!(cli, s, progress_interval_ms, DEFAULT_PROGRESS_INTERVAL_MS);
}

fn apply_project_config_layer(cli: &mut Cli, pc: SanitizeConfig, config_dir: &std::path::Path) {
    // Additive lists (same semantics as settings layer)
    merge_list(&mut cli.app, pc.app);
    merge_list(&mut cli.allow, pc.allow);
    merge_list(&mut cli.exclude_path, pc.exclude_path);
    merge_list(&mut cli.include_path, pc.include_path);
    merge_list(&mut cli.context_keywords, pc.context_keywords);
    // Path-relative source files
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
    // Bool flags
    apply_bool_flag!(cli, pc, fail_on_match);
    apply_bool_flag!(cli, pc, strict);
    apply_bool_flag!(cli, pc, no_structured_handoff);
    apply_bool_flag!(cli, pc, no_field_signal);
    apply_bool_flag!(cli, pc, force_text);
    apply_bool_flag!(cli, pc, include_binary);
    apply_bool_flag!(cli, pc, hidden);
    apply_bool_flag!(cli, pc, context_keywords_replace);
    apply_bool_flag!(cli, pc, context_case_sensitive);
    apply_bool_flag!(cli, pc, extract_context);
    apply_bool_flag!(cli, pc, no_progress);
    apply_bool_flag!(cli, pc, quiet);
    // Option<T> fields
    apply_opt_field!(cli, pc, threads);
    apply_opt_field!(cli, pc, entropy_threshold);
    apply_opt_field!(cli, pc, log_format);
    apply_opt_field!(cli, pc, log_level);
    // Concrete fields
    apply_concrete_field!(cli, pc, chunk_size, 1_048_576_usize);
    apply_concrete_field!(cli, pc, max_mappings, 10_000_000_usize);
    apply_concrete_field!(
        cli,
        pc,
        max_structured_size,
        DEFAULT_MAX_STRUCTURED_FILE_SIZE
    );
    apply_concrete_field!(cli, pc, max_archive_depth, DEFAULT_ARCHIVE_DEPTH);
    apply_concrete_field!(cli, pc, context_lines, DEFAULT_CONTEXT_LINES);
    apply_concrete_field!(cli, pc, max_context_matches, DEFAULT_MAX_MATCHES);
    apply_concrete_field!(cli, pc, max_match_locations, 500_usize);
    apply_concrete_field!(cli, pc, progress_interval_ms, DEFAULT_PROGRESS_INTERVAL_MS);
}

pub(super) fn merge_settings(mut cli: Cli) -> Cli {
    apply_settings_layer(&mut cli, load_settings());
    if let Some(project_config_path) = find_project_config() {
        let (pc, config_dir) = load_project_config(&project_config_path);
        apply_project_config_layer(&mut cli, pc, &config_dir);
    }
    cli
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::path::Path;

    fn default_cli() -> Cli {
        Cli::try_parse_from(["scour-secrets", "file.txt"]).unwrap()
    }

    // ── apply_settings_layer ─────────────────────────────────────────────────

    #[test]
    fn settings_layer_applies_when_cli_is_default() {
        let mut cli = default_cli();
        let s = SanitizeConfig {
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
        let mut cli =
            Cli::try_parse_from(["scour-secrets", "file.txt", "--fail-on-match"]).unwrap();
        assert!(cli.fail_on_match);
        apply_settings_layer(
            &mut cli,
            SanitizeConfig {
                fail_on_match: Some(false),
                ..Default::default()
            },
        );
        assert!(cli.fail_on_match);
    }

    #[test]
    fn settings_layer_does_not_override_explicit_threads() {
        let mut cli = Cli::try_parse_from(["scour-secrets", "file.txt", "--threads", "2"]).unwrap();
        apply_settings_layer(
            &mut cli,
            SanitizeConfig {
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
            SanitizeConfig {
                app: vec!["gitlab".into()],
                ..Default::default()
            },
        );
        assert!(cli.app.contains(&"gitlab".to_string()));
    }

    #[test]
    fn settings_layer_merges_app_additively_with_cli() {
        let mut cli =
            Cli::try_parse_from(["scour-secrets", "file.txt", "--app", "kubernetes"]).unwrap();
        apply_settings_layer(
            &mut cli,
            SanitizeConfig {
                app: vec!["gitlab".into()],
                ..Default::default()
            },
        );
        assert!(cli.app.contains(&"kubernetes".to_string()));
        assert!(cli.app.contains(&"gitlab".to_string()));
    }

    #[test]
    fn settings_layer_applies_new_bool_flags() {
        let mut cli = default_cli();
        apply_settings_layer(
            &mut cli,
            SanitizeConfig {
                force_text: Some(true),
                include_binary: Some(true),
                hidden: Some(true),
                quiet: Some(true),
                ..Default::default()
            },
        );
        assert!(cli.force_text);
        assert!(cli.include_binary);
        assert!(cli.hidden);
        assert!(cli.quiet);
    }

    #[test]
    fn settings_layer_applies_concrete_fields() {
        let mut cli = default_cli();
        apply_settings_layer(
            &mut cli,
            SanitizeConfig {
                chunk_size: Some(2_097_152),
                max_archive_depth: Some(3),
                context_lines: Some(5),
                ..Default::default()
            },
        );
        assert_eq!(cli.chunk_size, 2_097_152);
        assert_eq!(cli.max_archive_depth, 3);
        assert_eq!(cli.context_lines, 5);
    }

    #[test]
    fn settings_layer_does_not_override_explicit_concrete_field() {
        let mut cli =
            Cli::try_parse_from(["scour-secrets", "file.txt", "--max-archive-depth", "2"]).unwrap();
        apply_settings_layer(
            &mut cli,
            SanitizeConfig {
                max_archive_depth: Some(10),
                ..Default::default()
            },
        );
        assert_eq!(cli.max_archive_depth, 2);
    }

    // ── apply_project_config_layer ───────────────────────────────────────────

    #[test]
    fn project_layer_adds_app_bundles_additively() {
        let mut cli =
            Cli::try_parse_from(["scour-secrets", "file.txt", "--app", "kubernetes"]).unwrap();
        let pc = SanitizeConfig {
            app: vec!["gitlab".into()],
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("."));
        assert!(cli.app.contains(&"kubernetes".to_string()));
        assert!(cli.app.contains(&"gitlab".to_string()));
    }

    #[test]
    fn project_layer_deduplicates_app_bundles() {
        let mut cli =
            Cli::try_parse_from(["scour-secrets", "file.txt", "--app", "gitlab"]).unwrap();
        let pc = SanitizeConfig {
            app: vec!["gitlab".into()],
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("."));
        assert_eq!(cli.app.iter().filter(|a| *a == "gitlab").count(), 1);
    }

    #[test]
    fn project_layer_resolves_secrets_file_relative_to_config_dir() {
        let mut cli = default_cli();
        let pc = SanitizeConfig {
            secrets_file: Some(PathBuf::from("secrets.yaml")),
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("/repo"));
        assert_eq!(cli.secrets_file, Some(PathBuf::from("/repo/secrets.yaml")));
    }

    #[test]
    fn project_layer_does_not_override_cli_secrets_file() {
        let mut cli =
            Cli::try_parse_from(["scour-secrets", "file.txt", "-s", "/explicit/secrets.yaml"])
                .unwrap();
        let pc = SanitizeConfig {
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
        let pc = SanitizeConfig {
            profile: Some(PathBuf::from("my.profile.yaml")),
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("/repo"));
        assert_eq!(cli.profile, Some(PathBuf::from("/repo/my.profile.yaml")));
    }

    #[test]
    fn project_layer_adds_allow_additively() {
        let mut cli =
            Cli::try_parse_from(["scour-secrets", "file.txt", "--allow", "localhost"]).unwrap();
        let pc = SanitizeConfig {
            allow: vec!["*.internal".into()],
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("."));
        assert!(cli.allow.contains(&"localhost".to_string()));
        assert!(cli.allow.contains(&"*.internal".to_string()));
    }

    #[test]
    fn project_layer_adds_exclude_path_additively() {
        let mut cli = Cli::try_parse_from([
            "sanitize",
            "file.txt",
            "--exclude-path",
            "tests/fixtures/**",
        ])
        .unwrap();
        let pc = SanitizeConfig {
            exclude_path: vec!["*.generated.yaml".into()],
            ..Default::default()
        };
        apply_project_config_layer(&mut cli, pc, Path::new("."));
        assert!(cli.exclude_path.contains(&"tests/fixtures/**".to_string()));
        assert!(cli.exclude_path.contains(&"*.generated.yaml".to_string()));
    }
}
