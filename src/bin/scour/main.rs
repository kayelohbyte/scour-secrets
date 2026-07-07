//! CLI entry-point for the sanitization engine.
//!
//! # Usage
//!
//! ```text
//! scour-secrets [OPTIONS] [INPUT]...
//! scour-secrets encrypt [OPTIONS] <INPUT> <OUTPUT>
//! scour-secrets decrypt [OPTIONS] <INPUT> <OUTPUT>
//!
//! # Read from stdin (plaintext secrets file — default):
//! cat data.log | scour-secrets -s secrets.yaml
//! grep "error" log.txt | scour-secrets -s secrets.json -o clean.log
//! ```
//!
//! # Subcommands
//!
//! - *(default)* — sanitize a file or archive
//! - `encrypt` — encrypt a plaintext secrets file
//! - `decrypt` — decrypt an encrypted secrets file back to plaintext
//!
//! # Examples
//!
//! ```text
//! # Encrypt a plaintext secrets file:
//! scour-secrets encrypt secrets.json secrets.json.enc --password
//!
//! # Decrypt it back (for editing):
//! scour-secrets decrypt secrets.json.enc secrets.json --password
//!
//! # Sanitize a log file (plaintext secrets — default):
//! scour-secrets data.log -s secrets.yaml
//!
//! # Write output to a file:
//! scour-secrets data.log -s secrets.yaml -o clean.log
//!
//! # Use an encrypted secrets file (requires --encrypted-secrets):
//! scour-secrets data.log -s secrets.enc --encrypted-secrets -p
//!
//! # Read from stdin with encrypted secrets:
//! grep "error" log.txt | scour-secrets -s secrets.enc --encrypted-secrets -P /run/secrets/pw
//!
//! # Deterministic mode with encrypted secrets:
//! scour-secrets data.csv -s s.enc --encrypted-secrets -p -d
//!
//! # Read password from a file (avoids process listing / env exposure):
//! scour-secrets data.log -s s.enc --encrypted-secrets -P /run/secrets/pw
//!
//! # Dry-run:
//! scour-secrets config.yaml -s s.enc --encrypted-secrets -p -n
//!
//! # Fail CI if matches found:
//! scour-secrets config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match
//! ```
//!
//! # One-Way Replacements
//!
//! All replacements are **one-way**. No mapping file is stored and there
//! is no restore mode. Re-running with the `--deterministic` flag and the
//! same secrets will produce identical replacements.

#![forbid(unsafe_code)]

mod apps;
mod cli_args;
mod commands;
mod config;
mod crypto;
mod dispatch;
mod entropy;
mod guided;
mod hooks;
mod input;
mod llm_client;
mod progress;
mod run_header;
mod sanitize;
mod scanner_builder;

use cli_args::{Cli, SubCommand};

use clap::Parser;
use scour_secrets::ArchiveFilter;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag set by the SIGINT/SIGTERM handler.
pub(crate) static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Check whether a graceful shutdown has been requested.
///
/// Uses `Acquire` to pair with the `SeqCst` store in the signal handler,
/// ensuring the write is visible on weakly-ordered architectures (ARM, POWER).
pub(crate) fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Acquire)
}

fn run() -> Result<(), (String, i32)> {
    // Pre-parse --only / --exclude flags that are interleaved with archive
    // paths before handing the cleaned arg list to clap.
    let raw_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let (raw_filter_map, cleaned_args) =
        input::parse_archive_filters(&raw_args).map_err(|e| (e, 1))?;

    // Compile ArchiveFilter objects eagerly so errors are reported before any
    // file I/O starts.
    let filter_map: HashMap<PathBuf, ArchiveFilter> = raw_filter_map
        .into_iter()
        .map(|(path, (only, exclude))| {
            ArchiveFilter::new(only, exclude)
                .map(|f| (path, f))
                .map_err(|e| (e, 1))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;

    let cli = Cli::parse_from(std::iter::once(OsString::from("scour-secrets")).chain(cleaned_args));

    input::init_logging(cli.effective_log_format(), cli.effective_log_level());

    match &cli.command {
        Some(SubCommand::Encrypt(args)) => return crypto::run_encrypt(args),
        Some(SubCommand::Decrypt(args)) => return crypto::run_decrypt(args),
        Some(SubCommand::Apps(args)) => return apps::run_apps(args),
        Some(SubCommand::Template(args)) => return commands::run_template(args),
        Some(SubCommand::AllowTest(args)) => return commands::run_allow_test(args),
        Some(SubCommand::InstallHook(args)) => return hooks::run_install_hook(args),
        Some(SubCommand::InitHook(args)) => return config::run_init(args),
        Some(SubCommand::ShowConfig) => return config::run_show_config(),
        Some(SubCommand::Scan(args)) => return commands::run_scan(args),
        Some(SubCommand::TestPattern(args)) => return commands::run_test_pattern(args),
        None => {}
    }

    sanitize::run_sanitize(cli, None, filter_map)
}

fn main() {
    match run() {
        Ok(()) => {}
        Err((msg, code)) => {
            eprintln!("error: {msg}");
            process::exit(code);
        }
    }
}

/// Single process-wide mutex for tests that mutate environment variables.
/// Shared by config and hooks tests so they cannot race each other.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_MUTEX
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use crate::cli_args::{Cli, HookMode, HookType, InstallHookArgs};
    use crate::hooks::{
        build_hook_flags, build_hook_script, hook_script_pre_commit_scan, remove_hook, sh_quote,
        HOOK_MARKER,
    };
    use crate::input::{
        cli_writes_to_stdout, file_inputs, format_to_ext, has_stdin_input, plan_input_targets,
        validate_args, InputTarget,
    };
    use crate::progress::{ProgressContext, ProgressMode, ProgressPolicy};
    use crate::scanner_builder::build_default_patterns;
    use clap::Parser;

    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_progress_context(
        stderr_is_terminal: bool,
        is_ci: bool,
        term_is_dumb: bool,
        json_logs: bool,
    ) -> ProgressContext {
        ProgressContext {
            stderr_is_terminal,
            stdout_is_terminal: false,
            stdout_is_output: false,
            is_ci,
            term_is_dumb,
            json_logs,
        }
    }

    /// Verify clap derive builds without panicking on debug assertions.
    #[test]
    fn cli_debug_assert_does_not_panic() {
        // clap runs internal validation on first parse attempt.
        // This catches issues like invalid required_unless_present references.
        let _ = Cli::try_parse_from(["scour-secrets", "input.txt"]);
    }

    #[test]
    fn cli_parses_basic_input() {
        let cli = Cli::try_parse_from(["scour-secrets", "input.txt"]).unwrap();
        assert_eq!(cli.input, vec![PathBuf::from("input.txt")]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_input_with_output() {
        let cli = Cli::try_parse_from(["scour-secrets", "input.txt", "-o", "output.txt"]).unwrap();
        assert_eq!(cli.input, vec![PathBuf::from("input.txt")]);
        assert_eq!(cli.output.unwrap(), PathBuf::from("output.txt"));
    }

    #[test]
    fn cli_parses_multiple_inputs() {
        let cli = Cli::try_parse_from(["scour-secrets", "test.txt", "a.json", "b.zip"]).unwrap();
        assert_eq!(
            cli.input,
            vec![
                PathBuf::from("test.txt"),
                PathBuf::from("a.json"),
                PathBuf::from("b.zip")
            ]
        );
    }

    #[test]
    fn cli_parses_output_long_flag() {
        let cli =
            Cli::try_parse_from(["scour-secrets", "input.txt", "--output", "out.txt"]).unwrap();
        assert_eq!(cli.output.unwrap(), PathBuf::from("out.txt"));
    }

    #[test]
    fn cli_parses_secrets_file_flag() {
        let cli = Cli::try_parse_from([
            "scour-secrets",
            "input.txt",
            "--secrets-file",
            "secrets.json",
        ])
        .unwrap();
        assert_eq!(cli.secrets_file.unwrap(), PathBuf::from("secrets.json"));
    }

    #[test]
    fn cli_parses_short_flags() {
        let cli = Cli::try_parse_from([
            "scour-secrets",
            "input.txt",
            "-s",
            "secrets.json",
            "-p",
            "-P",
            "/run/secrets/pw",
            "-o",
            "out.txt",
            "-n",
            "-d",
            "-f",
            "json",
        ])
        .unwrap();
        assert_eq!(cli.secrets_file.unwrap(), PathBuf::from("secrets.json"));
        assert!(cli.password);
        assert_eq!(cli.password_file.unwrap(), PathBuf::from("/run/secrets/pw"));
        assert_eq!(cli.output.unwrap(), PathBuf::from("out.txt"));
        assert!(cli.dry_run);
        assert!(cli.deterministic);
        assert_eq!(cli.format.unwrap(), "json");
    }

    #[test]
    fn cli_parses_dry_run() {
        let cli = Cli::try_parse_from(["scour-secrets", "input.txt", "--dry-run"]).unwrap();
        assert!(cli.dry_run);
    }

    #[test]
    fn cli_parses_progress_mode() {
        let cli = Cli::try_parse_from(["scour-secrets", "input.txt", "--progress", "on"]).unwrap();
        assert_eq!(cli.progress, Some(ProgressMode::On));
        assert_eq!(cli.effective_progress_mode(), ProgressMode::On);
    }

    #[test]
    fn cli_no_progress_maps_to_off() {
        let cli = Cli::try_parse_from(["scour-secrets", "input.txt", "--no-progress"]).unwrap();
        assert!(cli.no_progress);
        assert_eq!(cli.effective_progress_mode(), ProgressMode::Off);
    }

    #[test]
    fn cli_explicit_progress_takes_precedence_over_no_progress() {
        let cli = Cli::try_parse_from([
            "scour-secrets",
            "input.txt",
            "--no-progress",
            "--progress",
            "on",
        ])
        .unwrap();
        assert!(cli.no_progress);
        assert_eq!(cli.progress, Some(ProgressMode::On));
        assert_eq!(cli.effective_progress_mode(), ProgressMode::On);
    }

    #[test]
    fn cli_parses_progress_interval() {
        let cli = Cli::try_parse_from([
            "scour-secrets",
            "input.txt",
            "--progress-interval-ms",
            "500",
        ])
        .unwrap();
        assert_eq!(cli.progress_interval_ms, 500);
    }

    #[test]
    fn validate_args_rejects_zero_progress_interval() {
        let mut cli = Cli::try_parse_from(["scour-secrets", "input.txt"]).unwrap();
        cli.input = vec![std::env::current_dir().unwrap().join("Cargo.toml")];
        cli.progress_interval_ms = 0;
        let err = validate_args(&cli).unwrap_err();
        assert!(err.contains("--progress-interval-ms must be greater than 0"));
    }

    #[test]
    fn progress_policy_auto_disables_live_updates_for_json_logs() {
        let policy = ProgressPolicy::from_mode(
            ProgressMode::Auto,
            make_progress_context(true, false, false, true),
        );
        assert!(!policy.live_updates);
        assert!(!policy.milestone_updates);
    }

    #[test]
    fn progress_policy_auto_disables_live_updates_in_ci() {
        let policy = ProgressPolicy::from_mode(
            ProgressMode::Auto,
            make_progress_context(true, true, false, false),
        );
        // In CI (non-TTY) the spinner is suppressed, but milestone lines are
        // plain eprintln! and remain enabled unless --json-logs is active.
        assert!(!policy.live_updates);
        assert!(policy.milestone_updates);
    }

    #[test]
    fn progress_policy_on_keeps_milestones_when_live_updates_are_unavailable() {
        let policy = ProgressPolicy::from_mode(
            ProgressMode::On,
            make_progress_context(false, false, false, false),
        );
        assert!(!policy.live_updates);
        assert!(policy.milestone_updates);
    }

    #[test]
    fn progress_policy_auto_enables_live_updates_in_interactive_human_mode() {
        let policy = ProgressPolicy::from_mode(
            ProgressMode::Auto,
            make_progress_context(true, false, false, false),
        );
        assert!(policy.live_updates);
        assert!(policy.milestone_updates);
    }

    #[test]
    fn progress_policy_auto_enables_live_when_stdout_is_tty_but_not_output_dest() {
        // Writing to files: stdout is a TTY but output doesn't go there.
        // This is the common `scour-secrets dir/` case — spinner should work.
        let policy = ProgressPolicy::from_mode(
            ProgressMode::Auto,
            ProgressContext {
                stderr_is_terminal: true,
                stdout_is_terminal: true,
                stdout_is_output: false,
                is_ci: false,
                term_is_dumb: false,
                json_logs: false,
            },
        );
        assert!(policy.live_updates);
    }

    #[test]
    fn progress_policy_auto_disables_live_when_writing_to_stdout() {
        // Piping output to stdout: spinner must be suppressed to avoid
        // interleaving with sanitized content.
        let policy = ProgressPolicy::from_mode(
            ProgressMode::Auto,
            ProgressContext {
                stderr_is_terminal: true,
                stdout_is_terminal: true,
                stdout_is_output: true,
                is_ci: false,
                term_is_dumb: false,
                json_logs: false,
            },
        );
        assert!(!policy.live_updates);
    }

    #[test]
    fn cli_writes_to_stdout_stdin_no_output() {
        let cli = Cli::try_parse_from(["scour-secrets"]).unwrap();
        assert!(cli_writes_to_stdout(&cli));
    }

    #[test]
    fn cli_writes_to_stdout_explicit_dash_input() {
        let cli = Cli::try_parse_from(["scour-secrets", "-"]).unwrap();
        assert!(cli_writes_to_stdout(&cli));
    }

    #[test]
    fn cli_writes_to_stdout_explicit_dash_output() {
        let cli = Cli::try_parse_from(["scour-secrets", "file.txt", "-o", "-"]).unwrap();
        assert!(cli_writes_to_stdout(&cli));
    }

    #[test]
    fn cli_writes_to_stdout_file_input_no_output_is_false() {
        let cli = Cli::try_parse_from(["scour-secrets", "file.txt"]).unwrap();
        assert!(!cli_writes_to_stdout(&cli));
    }

    #[test]
    fn cli_writes_to_stdout_dir_input_no_output_is_false() {
        let cli = Cli::try_parse_from(["scour-secrets", "some_dir/"]).unwrap();
        assert!(!cli_writes_to_stdout(&cli));
    }

    #[test]
    fn cli_parses_encrypt_subcommand() {
        let cli = Cli::try_parse_from([
            "scour-secrets",
            "encrypt",
            "secrets.json",
            "secrets.enc",
            "--password",
        ])
        .unwrap();
        assert!(cli.command.is_some());
        assert!(cli.input.is_empty());
    }

    #[test]
    fn cli_parses_decrypt_subcommand() {
        let cli = Cli::try_parse_from([
            "scour-secrets",
            "decrypt",
            "secrets.enc",
            "secrets.json",
            "--password",
        ])
        .unwrap();
        assert!(cli.command.is_some());
        assert!(cli.input.is_empty());
    }

    #[test]
    fn cli_no_input_no_subcommand_is_ok_at_parse_time() {
        // Clap allows it (input is Vec); we validate manually in run().
        let cli = Cli::try_parse_from(["scour-secrets", "--dry-run"]).unwrap();
        assert!(cli.input.is_empty());
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "scour-secrets",
            "input.log",
            "--output",
            "output.log",
            "--secrets-file",
            "s.enc",
            "--password",
            "--dry-run",
            "--fail-on-match",
            "--deterministic",
            "--strict",
            "--include-binary",
            "--encrypted-secrets",
            "--chunk-size",
            "4096",
            "--threads",
            "4",
            "--max-mappings",
            "500",
            "--log-format",
            "json",
            "--format",
            "yaml",
        ])
        .unwrap();
        assert!(cli.dry_run);
        assert!(cli.fail_on_match);
        assert!(cli.deterministic);
        assert!(cli.strict);
        assert!(cli.include_binary);
        assert!(cli.encrypted_secrets);
        assert_eq!(cli.chunk_size, 4096);
        assert_eq!(cli.threads, Some(4));
        assert_eq!(cli.max_mappings, 500);
        assert_eq!(cli.format.unwrap(), "yaml");
        assert_eq!(cli.output.unwrap(), PathBuf::from("output.log"));
    }

    #[test]
    fn cli_stdin_dash_input() {
        let cli = Cli::try_parse_from(["scour-secrets", "-", "-s", "s.json"]).unwrap();
        assert!(has_stdin_input(&cli));
    }

    #[test]
    fn cli_stdin_no_input() {
        let cli = Cli::try_parse_from(["scour-secrets", "-s", "s.json"]).unwrap();
        assert!(has_stdin_input(&cli));
    }

    #[test]
    fn cli_file_input_not_stdin() {
        let cli = Cli::try_parse_from(["scour-secrets", "data.log"]).unwrap();
        assert!(!has_stdin_input(&cli));
    }

    #[test]
    fn cli_file_and_stdin_mix_is_supported() {
        let cli = Cli::try_parse_from(["scour-secrets", "test.txt", "-", "-s", "s.json"]).unwrap();
        assert!(has_stdin_input(&cli));
        assert_eq!(file_inputs(&cli).len(), 1);
    }

    #[test]
    fn format_to_ext_mapping() {
        assert_eq!(format_to_ext("json"), Some("json"));
        assert_eq!(format_to_ext("yaml"), Some("yaml"));
        assert_eq!(format_to_ext("xml"), Some("xml"));
        assert_eq!(format_to_ext("csv"), Some("csv"));
        assert_eq!(format_to_ext("key-value"), Some("conf"));
        assert_eq!(format_to_ext("text"), None);
        assert_eq!(format_to_ext("unknown"), None);
    }

    #[test]
    fn plan_multi_input_outputs_preserve_types() {
        let tmp = tempdir().unwrap();
        let input_dir = tmp.path().join("in");
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&input_dir).unwrap();

        let txt = input_dir.join("test.txt");
        let json = input_dir.join("a.json");
        let zip = input_dir.join("b.zip");
        fs::write(&txt, "x").unwrap();
        fs::write(&json, "{}\n").unwrap();
        fs::write(&zip, "PK\x03\x04").unwrap();

        let cli = Cli::try_parse_from([
            "scour-secrets",
            txt.to_str().unwrap(),
            json.to_str().unwrap(),
            zip.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
        ])
        .unwrap();

        let targets = plan_input_targets(&cli).unwrap();
        let mut outputs = targets
            .into_iter()
            .filter_map(|t| match t {
                InputTarget::File { output, .. } => {
                    Some(output.file_name().unwrap().to_string_lossy().to_string())
                }
                InputTarget::Stdin { .. } => None,
            })
            .collect::<Vec<_>>();
        outputs.sort();

        assert_eq!(
            outputs,
            vec![
                "a-sanitized.json".to_string(),
                "b.sanitized.zip".to_string(),
                "test-sanitized.txt".to_string(),
            ]
        );
    }

    #[test]
    fn plan_multi_input_collision_adds_numeric_suffix() {
        let tmp = tempdir().unwrap();
        let dir1 = tmp.path().join("dir1");
        let dir2 = tmp.path().join("dir2");
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&dir1).unwrap();
        fs::create_dir_all(&dir2).unwrap();

        let f1 = dir1.join("same.txt");
        let f2 = dir2.join("same.txt");
        fs::write(&f1, "x").unwrap();
        fs::write(&f2, "y").unwrap();

        let cli = Cli::try_parse_from([
            "scour-secrets",
            f1.to_str().unwrap(),
            f2.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
        ])
        .unwrap();

        let targets = plan_input_targets(&cli).unwrap();
        let outputs = targets
            .into_iter()
            .filter_map(|t| match t {
                InputTarget::File { output, .. } => {
                    Some(output.file_name().unwrap().to_string_lossy().to_string())
                }
                InputTarget::Stdin { .. } => None,
            })
            .collect::<Vec<_>>();

        assert!(outputs.contains(&"same-sanitized.txt".to_string()));
        assert!(outputs.contains(&"same-sanitized-1.txt".to_string()));
    }

    // -----------------------------------------------------------------------
    // validate_args: additional cases
    // -----------------------------------------------------------------------

    fn real_file_cli() -> Cli {
        let mut cli = Cli::try_parse_from(["scour-secrets", "placeholder"]).unwrap();
        cli.input = vec![std::env::current_dir().unwrap().join("Cargo.toml")];
        cli
    }

    #[test]
    fn validate_args_rejects_invalid_format() {
        let mut cli = real_file_cli();
        cli.format = Some("notaformat".into());
        let err = validate_args(&cli).unwrap_err();
        assert!(err.contains("invalid --format"), "got: {err}");
    }

    #[test]
    fn validate_args_rejects_invalid_log_format() {
        let mut cli = real_file_cli();
        cli.log_format = Some("xml".into());
        let err = validate_args(&cli).unwrap_err();
        assert!(err.contains("invalid --log-format"), "got: {err}");
    }

    #[test]
    fn validate_args_rejects_zero_threads() {
        let mut cli = real_file_cli();
        cli.threads = Some(0);
        let err = validate_args(&cli).unwrap_err();
        assert!(err.contains("--threads must be"), "got: {err}");
    }

    #[test]
    fn validate_args_rejects_password_without_encrypted_secrets() {
        let mut cli = real_file_cli();
        cli.password = true;
        let err = validate_args(&cli).unwrap_err();
        assert!(err.contains("--encrypted-secrets is not set"), "got: {err}");
    }

    #[test]
    fn validate_args_allows_llm_with_output() {
        // --llm + --output is now valid: reference mode writes sanitized files to
        // disk and the prompt lists their paths instead of inlining content.
        let mut cli = real_file_cli();
        cli.llm = Some("troubleshoot".into());
        cli.output = Some(PathBuf::from("/tmp/out.txt"));
        assert!(
            validate_args(&cli).is_ok(),
            "--llm + --output should be allowed for reference mode"
        );
    }

    #[test]
    fn validate_args_rejects_llm_with_dry_run() {
        let mut cli = real_file_cli();
        cli.llm = Some("troubleshoot".into());
        cli.dry_run = true;
        let err = validate_args(&cli).unwrap_err();
        assert!(
            err.contains("--llm and --dry-run cannot be combined"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_args_rejects_llm_with_nonexistent_template_path() {
        let mut cli = real_file_cli();
        cli.llm = Some("/nonexistent/template.txt".into());
        let err = validate_args(&cli).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn validate_args_accepts_known_llm_templates() {
        for name in ["troubleshoot", "review-config", "review-security"] {
            let mut cli = real_file_cli();
            cli.llm = Some(name.into());
            assert!(
                validate_args(&cli).is_ok(),
                "built-in template '{}' should be accepted",
                name
            );
        }
    }

    #[test]
    fn validate_args_rejects_non_http_llm_endpoint() {
        for bad in [
            "file:///etc/passwd",
            "ftp://host/v1",
            "javascript:alert(1)",
            "//host/v1",
        ] {
            let mut cli = real_file_cli();
            cli.llm = Some("troubleshoot".into());
            cli.llm_endpoint = Some(bad.into());
            cli.llm_model = Some("test-model".into());
            let err = validate_args(&cli).unwrap_err();
            assert!(
                err.contains("http://") || err.contains("https://"),
                "expected scheme error for {bad:?}, got: {err}"
            );
        }
    }

    #[test]
    fn validate_args_rejects_llm_endpoint_without_model() {
        let mut cli = real_file_cli();
        cli.llm = Some("troubleshoot".into());
        cli.llm_endpoint = Some("http://localhost:11434/v1".into());
        // llm_model intentionally left None
        let err = validate_args(&cli).unwrap_err();
        assert!(err.contains("llm-model"), "got: {err}");
    }

    #[test]
    fn validate_args_accepts_valid_llm_endpoint() {
        for scheme in ["http://localhost:11434/v1", "https://api.openai.com/v1"] {
            let mut cli = real_file_cli();
            cli.llm = Some("troubleshoot".into());
            cli.llm_endpoint = Some(scheme.into());
            cli.llm_model = Some("phi4-mini".into());
            assert!(
                validate_args(&cli).is_ok(),
                "valid endpoint {scheme:?} should be accepted"
            );
        }
    }

    #[test]
    fn validate_endpoint_scheme_rejects_non_http() {
        for bad in ["file:///etc/passwd", "ftp://host", "javascript:x", "//host"] {
            assert!(
                crate::llm_client::validate_endpoint_scheme(bad).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn validate_endpoint_scheme_accepts_http_and_https() {
        assert!(crate::llm_client::validate_endpoint_scheme("http://localhost:11434/v1").is_ok());
        assert!(crate::llm_client::validate_endpoint_scheme("https://api.openai.com/v1").is_ok());
    }

    #[test]
    fn build_default_patterns_returns_nonempty_set() {
        let patterns = build_default_patterns();
        assert!(
            !patterns.is_empty(),
            "built-in balanced patterns should not be empty"
        );
        // Verify a few known labels are present.
        let labels: Vec<_> = patterns.iter().map(|p| p.label()).collect();
        assert!(labels.contains(&"email"), "expected email pattern");
        assert!(
            labels.contains(&"github_token"),
            "expected github_token pattern"
        );
        assert!(
            labels.contains(&"stripe_key"),
            "expected stripe_key pattern"
        );
    }

    // ── install-hook tests ────────────────────────────────────────────────────

    #[test]
    fn hook_script_pre_commit_scan_contains_marker_and_fail_on_match() {
        let args = InstallHookArgs {
            hook: HookType::PreCommit,
            mode: HookMode::Scan,
            global: false,
            force: false,
            remove: false,
            app: None,
            secrets_file: None,
            dry_run: false,
        };
        let script = build_hook_script(&args);
        assert!(script.contains(HOOK_MARKER), "marker must be present");
        assert!(
            script.contains("--dry-run --fail-on-match"),
            "scan mode must use --dry-run --fail-on-match"
        );
        assert!(
            script.contains("SCOUR_SECRETS_SKIP"),
            "escape hatch must be present"
        );
        assert!(
            script.starts_with("#!/bin/sh"),
            "must start with POSIX shebang"
        );
    }

    #[test]
    fn hook_script_pre_commit_sanitize_uses_output_dot() {
        let args = InstallHookArgs {
            hook: HookType::PreCommit,
            mode: HookMode::Sanitize,
            global: false,
            force: false,
            remove: false,
            app: None,
            secrets_file: None,
            dry_run: false,
        };
        let script = build_hook_script(&args);
        assert!(
            script.contains("--output ."),
            "sanitize mode must write output in place"
        );
        assert!(
            script.contains("git add"),
            "sanitize mode must re-stage files"
        );
        assert!(
            !script.contains("--dry-run"),
            "sanitize mode must not pass --dry-run"
        );
    }

    #[test]
    fn hook_script_pre_push_contains_while_read_loop() {
        let args = InstallHookArgs {
            hook: HookType::PrePush,
            mode: HookMode::Scan,
            global: false,
            force: false,
            remove: false,
            app: Some("gitlab".into()),
            secrets_file: None,
            dry_run: false,
        };
        let script = build_hook_script(&args);
        assert!(
            script.contains("while IFS=' ' read -r"),
            "pre-push must iterate stdin"
        );
        assert!(
            script.contains("--app 'gitlab'"),
            "app bundle must be quoted and forwarded"
        );
    }

    #[test]
    fn hook_flags_shell_quotes_paths_with_spaces() {
        let args = InstallHookArgs {
            hook: HookType::PreCommit,
            mode: HookMode::Scan,
            global: false,
            force: false,
            remove: false,
            app: None,
            secrets_file: Some(PathBuf::from("my secrets/file.yaml")),
            dry_run: false,
        };
        let flags = build_hook_flags(&args);
        assert!(
            flags.contains("-s 'my secrets/file.yaml'"),
            "space in path must be single-quoted: got {flags}"
        );
    }

    #[test]
    fn sh_quote_escapes_embedded_single_quotes() {
        assert_eq!(sh_quote("it's a test"), "'it'\\''s a test'");
        assert_eq!(sh_quote("normal"), "'normal'");
        assert_eq!(sh_quote("a b c"), "'a b c'");
    }

    #[test]
    fn remove_hook_deletes_file_when_entirely_ours() {
        let dir = tempdir().unwrap();
        let hook_path = dir.path().join("pre-commit");
        let script = hook_script_pre_commit_scan("");
        fs::write(&hook_path, &script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        remove_hook(&hook_path, "pre-commit").expect("remove should succeed");
        assert!(
            !hook_path.exists(),
            "file should be deleted when it is entirely our hook"
        );
    }

    #[test]
    fn remove_hook_strips_block_from_composite_hook() {
        let dir = tempdir().unwrap();
        let hook_path = dir.path().join("pre-commit");
        let pre_existing = "#!/bin/sh\n# other team's linter\nnpm run lint\n";
        let our_block = hook_script_pre_commit_scan("");
        fs::write(&hook_path, format!("{pre_existing}{our_block}")).unwrap();
        remove_hook(&hook_path, "pre-commit").expect("remove should succeed");
        assert!(
            hook_path.exists(),
            "file should remain when other content is present"
        );
        let remaining = fs::read_to_string(&hook_path).unwrap();
        assert!(
            remaining.contains("npm run lint"),
            "other hook content must be preserved"
        );
        assert!(!remaining.contains(HOOK_MARKER), "our marker must be gone");
    }

    #[test]
    fn remove_hook_rejects_unrecognised_hook() {
        let dir = tempdir().unwrap();
        let hook_path = dir.path().join("pre-commit");
        fs::write(&hook_path, "#!/bin/sh\necho hello\n").unwrap();
        let result = remove_hook(&hook_path, "pre-commit");
        assert!(
            result.is_err(),
            "should refuse to remove a hook we didn't install"
        );
    }
}
