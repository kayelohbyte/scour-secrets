//! CLI entry-point for the sanitization engine.
//!
//! # Usage
//!
//! ```text
//! sanitize [OPTIONS] [INPUT]...
//! sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
//! sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
//!
//! # Read from stdin (plaintext secrets file — default):
//! cat data.log | sanitize -s secrets.yaml
//! grep "error" log.txt | sanitize -s secrets.json -o clean.log
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
//! sanitize encrypt secrets.json secrets.json.enc --password
//!
//! # Decrypt it back (for editing):
//! sanitize decrypt secrets.json.enc secrets.json --password
//!
//! # Sanitize a log file (plaintext secrets — default):
//! sanitize data.log -s secrets.yaml
//!
//! # Write output to a file:
//! sanitize data.log -s secrets.yaml -o clean.log
//!
//! # Use an encrypted secrets file (requires --encrypted-secrets):
//! sanitize data.log -s secrets.enc --encrypted-secrets -p
//!
//! # Read from stdin with encrypted secrets:
//! grep "error" log.txt | sanitize -s secrets.enc --encrypted-secrets -P /run/secrets/pw
//!
//! # Deterministic mode with encrypted secrets:
//! sanitize data.csv -s s.enc --encrypted-secrets -p -d
//!
//! # Read password from a file (avoids process listing / env exposure):
//! sanitize data.log -s s.enc --encrypted-secrets -P /run/secrets/pw
//!
//! # Dry-run:
//! sanitize config.yaml -s s.enc --encrypted-secrets -p -n
//!
//! # Fail CI if matches found:
//! sanitize config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match
//! ```
//!
//! # One-Way Replacements
//!
//! All replacements are **one-way**. No mapping file is stored and there
//! is no restore mode. Re-running with the `--deterministic` flag and the
//! same secrets will produce identical replacements.

mod apps;
use apps::{
    builtin_app_names, ensure_user_app_copy, load_app_bundle, run_apps, user_apps_dir, BUILTIN_APPS,
};

mod config;
mod guided;
use guided::{
    build_guided_entries, build_guided_profiles, parse_template_preset, prompt_cloud_providers,
    prompt_domains, prompt_formats, prompt_line, prompt_yes_no, template_body_aws,
    template_body_database, template_body_generic, template_body_k8s, template_body_web,
    GuidedOptions, GuidedPreset, TemplatePreset, PROFILE_HEADER, TEMPLATE_HEADER,
};

use config::{find_project_config, load_project_config, load_settings, run_init, run_show_config};

mod hooks;
use hooks::{global_default_secrets_path, run_install_hook};

mod entropy;
use entropy::{
    entropy_configs_from_entries, entropy_histogram_bytes, entropy_scan_bytes, scanner_fallback,
    EntropyBuckets, EntropyConfig, NullSeekWriter, HISTOGRAM_THRESHOLDS,
};

mod progress;
use progress::{
    with_progress_scope, ProgressContext, ProgressMode, ProgressPolicy, ProgressReporter,
    SharedProgressReporter,
};

use clap::{Parser, Subcommand, ValueEnum};
use rayon::prelude::*;
use sanitize_engine::secrets::{
    decrypt_secrets, encrypt_secrets, entries_to_patterns, extract_allow_patterns, parse_category,
    parse_secrets, serialize_secrets, SecretEntry, SecretsFormat,
};
use sanitize_engine::{
    atomic_write, extract_context, extract_context_reader, format_llm_prompt,
    format_llm_prompt_reference, strip_values_from_text, ArchiveFilter, ArchiveFormat,
    ArchiveProcessor, ArchiveProgress, AtomicFileWriter, FieldNameSignal, FileReport,
    FileTypeProfile, HmacGenerator, LlmEntry, LlmPathEntry, LogContextConfig, MappingStore,
    ProcessorRegistry, RandomGenerator, ReplacementGenerator, ReportBuilder, ReportMetadata,
    ScanConfig, ScanPattern, ScanStats, StreamScanner, DEFAULT_ARCHIVE_DEPTH,
    DEFAULT_CONTEXT_LINES, DEFAULT_FIELD_SIGNAL_THRESHOLD, DEFAULT_MAX_MATCHES,
};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufReader, BufWriter, Cursor, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Maximum size (in bytes) for a structured file to be fully loaded into
/// memory for format-aware processing (F-03 fix). Files exceeding this
/// limit fall back to the streaming scanner which operates in bounded
/// memory. Configurable via `--max-structured-size`.
const DEFAULT_MAX_STRUCTURED_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

/// Maximum output size buffered in memory when `--extract-context` is used
/// and the sanitized output is directed to stdout (not a file). Outputs
/// larger than this skip context extraction and emit a warning. Users with
/// large log files should use `-o`/`--output` so the two-pass file path is
/// taken instead.
const MAX_CONTEXT_BUFFER_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

/// Shared per-run collector for `--llm`: (label, sanitized_bytes) pairs in
/// input order. Wrapped in `Arc<Mutex>` so it can be passed into parallel file
/// processing paths alongside the report builder.
type LlmCollector = Arc<Mutex<Vec<LlmEntry>>>;

/// Global flag set by the SIGINT/SIGTERM handler.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Default UI refresh interval for live progress rendering.
const DEFAULT_PROGRESS_INTERVAL_MS: u64 = 200;

/// All format names accepted by `--format`. Must stay in sync with the
/// format-parsing logic in `ProcessorRegistry`.
const VALID_FORMATS: &[&str] = &[
    "text",
    "json",
    "jsonl",
    "ndjson",
    "yaml",
    "yml",
    "xml",
    "csv",
    "tsv",
    "key-value",
    "toml",
    "env",
    "ini",
    "log",
];

/// Check whether a graceful shutdown has been requested.
fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

#[derive(Copy, Clone)]
struct ArchiveDeps<'a> {
    scanner: &'a Arc<StreamScanner>,
    registry: &'a Arc<ProcessorRegistry>,
    store: &'a Arc<MappingStore>,
    profiles: &'a [sanitize_engine::processor::FileTypeProfile],
}

// ---------------------------------------------------------------------------
// Report format
// ---------------------------------------------------------------------------

/// Output format for `--report`.
#[derive(Debug, Clone, PartialEq, Default, clap::ValueEnum)]
enum ReportFormat {
    /// Structured JSON (default). Machine-readable.
    #[default]
    Json,
    /// SARIF 2.1.0. Consumed natively by GitHub Advanced Security,
    /// VS Code Problems panel, and most SIEM tooling.
    Sarif,
    /// Self-contained HTML. Human-readable summary with a per-file table.
    Html,
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Deterministic one-way data sanitization tool.
///
/// Scans files and archives for sensitive data described in an encrypted
/// secrets file and replaces every match with a category-aware substitute.
/// Replacements are ONE-WAY — no mapping file is stored and there is no
/// restore mode.
///
/// Use `sanitize encrypt` / `sanitize decrypt` to manage encrypted secrets
/// files, or omit the subcommand to sanitize data.
#[derive(Parser, Debug)]
#[command(
    name = "sanitize",
    version,
    about = "One-way data sanitization tool",
    long_about = "Deterministic one-way data sanitization tool.\n\n\
        Scans files and archives for sensitive data described in a secrets file \
        (plaintext by default) and replaces every match with a category-aware substitute.\n\
        Replacements are ONE-WAY — no mapping file is stored and there is no \
        restore mode.\n\n\
        Use `sanitize encrypt` / `sanitize decrypt` to manage encrypted secrets files.",
    after_help = "\
EXAMPLES:\n  \
  # Plaintext secrets file (default — no password needed):\n  \
  sanitize data.log -s secrets.yaml\n  \
  sanitize data.log -s secrets.yaml -o clean.log\n  \
  grep \"error\" log.txt | sanitize -s secrets.yaml\n\n  \
  # Encrypted secrets file (requires --encrypted-secrets):\n  \
  sanitize data.log -s s.enc --encrypted-secrets -p\n  \
  sanitize data.log -s s.enc --encrypted-secrets -P /run/secrets/pw\n  \
  SANITIZE_PASSWORD=hunter2 sanitize data.log -s s.enc --encrypted-secrets\n\n  \
  # Encrypt / decrypt secrets files:\n  \
  sanitize encrypt secrets.json secrets.json.enc --password\n  \
  sanitize decrypt secrets.json.enc secrets.json --password\n\n  \
  # Deterministic replacements with encrypted secrets:\n  \
  sanitize data.csv -s s.enc --encrypted-secrets -p -d\n\n  \
  # Extract error/warning context into the JSON report (--report required):\n  \
  sanitize app.log -s s.enc --encrypted-secrets -p --report report.json --extract-context\n  \
  cat app.log | sanitize -s s.enc --encrypted-secrets -p --report - --extract-context\n\n  \
  # Custom keywords and wider context window:\n  \
  sanitize app.log -s s.enc --encrypted-secrets -p --report - \\\n    \
    --extract-context --context-keywords timeout,oomkilled --context-lines 20\n\n  \
  # Strip values to generate a profile template (no secrets file needed):\n  \
  sanitize gitlab.rb --strip-values -o gitlab.rb.template\n  \
  cat config.rb | sanitize --strip-values\n\n  \
  # Inline mode: embed sanitized content in the prompt (pipe to clipboard, LLM, etc.):\n  \
  sanitize app.log -s secrets.yaml --llm | pbcopy\n  \
  sanitize config.yaml -s s.enc --encrypted-secrets -p --llm review-config\n  \
  sanitize nginx.conf --app nginx --llm review-security\n  \
  sanitize app.log -s s.yaml --llm --extract-context --context-lines 15\n  \
  sanitize app.log -s s.yaml --llm /path/to/custom-template.txt\n\n  \
  # Reference mode: write sanitized files to disk, prompt lists absolute paths:\n  \
  sanitize app.log -s s.yaml --llm --output /tmp/sanitized/app.log\n  \
  sanitize logs/ -s s.yaml --llm review-security --output /tmp/sanitized/"
)]
struct Cli {
    /// Subcommand: encrypt, decrypt, or omit for default sanitize mode.
    #[command(subcommand)]
    command: Option<SubCommand>,

    /// Path(s) to files or archives to sanitize. When omitted, reads
    /// from stdin. Use "-" to include stdin alongside file paths.
    #[arg(value_name = "INPUT")]
    input: Vec<PathBuf>,

    /// Output path. For a single input stream, writes to this file.
    /// For multiple inputs, this is treated as an output directory.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Path to a secrets file. Plaintext JSON / YAML / TOML files are
    /// loaded directly by default. Use `--encrypted-secrets` to decrypt
    /// an AES-256-GCM encrypted file.
    #[arg(short = 's', long = "secrets-file", value_name = "FILE")]
    secrets_file: Option<PathBuf>,

    /// Path to a file-type profile (JSON or YAML) defining which structured
    /// fields to sanitize. Each profile entry names a processor, file
    /// extensions, and field-path rules (e.g. `*.password`, `database.host`).
    ///
    /// Requires --secrets-file. The tool runs a structured pass (replacing
    /// named fields) followed by a scanner pass (catching any remaining
    /// secrets). The secrets file may be empty on the first run — discovered
    /// field values are appended to it automatically so subsequent runs can
    /// catch those same values everywhere.
    #[arg(long = "profile", value_name = "FILE")]
    profile: Option<PathBuf>,

    /// Trigger an interactive password prompt for decrypting the secrets
    /// file (masked input, never echoed). Requires `--encrypted-secrets`.
    /// Providing this flag without `--encrypted-secrets` is an error.
    /// For non-interactive automation use `--password-file` or the
    /// `SANITIZE_PASSWORD` environment variable instead.
    #[arg(short = 'p', long)]
    password: bool,

    /// Read the decryption password from a file. Requires `--encrypted-secrets`.
    /// The file must have permissions 0600 or 0400 (owner-only).
    /// Trailing newline is stripped.
    #[arg(short = 'P', long = "password-file", value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// Treat the secrets file as AES-256-GCM encrypted and decrypt it
    /// before loading. Requires a password via `-p`, `--password-file`,
    /// or the `SANITIZE_PASSWORD` environment variable. Without this
    /// flag the file is loaded as plaintext (JSON / YAML / TOML);
    /// providing any password input without this flag is an error.
    #[arg(long)]
    encrypted_secrets: bool,

    /// Force input format, overriding file-extension detection.
    /// Required when reading from stdin with structured data.
    /// Values: text, json, jsonl, yaml, xml, csv, key-value, toml, env, ini, log.
    #[arg(short = 'f', long, value_name = "FMT")]
    format: Option<String>,

    /// Scan and report matches without writing output.
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Exit with code 2 if any matches are found. Useful for CI
    /// pipelines that should fail when secrets are detected.
    #[arg(long)]
    fail_on_match: bool,

    /// Write a report to the given path (or stderr if no path).
    /// The report includes file-level match counts, per-pattern stats,
    /// processing duration, and tool metadata. No original secret values
    /// are included. Use --report-format to select the output format.
    #[arg(short = 'r', long, value_name = "PATH")]
    report: Option<Option<PathBuf>>,

    /// Output format for --report.
    /// json (default): structured JSON; sarif: SARIF 2.1.0 for GitHub Advanced
    /// Security / VS Code / SIEMs; html: self-contained human-readable summary.
    #[arg(long, value_name = "FORMAT", default_value = "json")]
    report_format: ReportFormat,

    /// Abort on the first error instead of skipping and continuing.
    #[arg(long)]
    strict: bool,

    /// Use HMAC-deterministic replacements so that identical inputs
    /// always produce identical outputs across runs (requires a stable
    /// seed derived from the secrets key).
    #[arg(short = 'd', long)]
    deterministic: bool,

    /// Disable the structured-to-scanner handoff. When a profile is active
    /// and `--secrets-file` is provided, values discovered in typed fields are
    /// appended to that file as `kind: literal` entries so the scanner pass
    /// can catch those same values in logs, comments, and unstructured text.
    /// Pass this flag to suppress that write.
    #[arg(long)]
    no_structured_handoff: bool,

    /// Disable the field-name signal heuristic. When a structured profile is
    /// active, keys matching built-in sensitive keywords (password, secret,
    /// token, api_key, …) are automatically flagged based on their value's
    /// Shannon entropy — even without an explicit FieldRule. The default
    /// entropy thresholds are 3.0 bits/char for strong keywords and 3.5 for
    /// ambiguous ones. Pass this flag to rely solely on explicit FieldRules
    /// and secrets patterns. Adjust per-signal thresholds in your secrets
    /// file with `kind: field-name` entries instead of disabling entirely.
    #[arg(long)]
    no_field_signal: bool,

    /// Process entries that appear to be binary data (default: skip).
    #[arg(long)]
    include_binary: bool,

    /// When a directory is given as input, also walk hidden files and
    /// directories (those whose name starts with `.`). VCS metadata
    /// directories (.git, .hg, .svn, .bzr) are always skipped regardless
    /// of this flag.
    #[arg(long)]
    hidden: bool,

    /// Enable Shannon entropy detection for high-entropy tokens not caught by
    /// pattern matching. THRESHOLD is bits per character (e.g. 4.5). Tokens
    /// of 20–200 alphanumeric characters whose entropy meets or exceeds this
    /// value are treated as secrets. Off by default. Supplement with
    /// `kind: entropy` entries in the secrets file for finer control.
    #[arg(long, value_name = "THRESHOLD")]
    entropy_threshold: Option<f64>,

    /// Exclude paths matching these glob patterns from scanning.
    /// Patterns are matched against the path relative to the input root
    /// (or against the filename alone when no `/` is present in the pattern).
    /// A trailing `/` excludes the entire subtree.
    /// Merged with `exclude` entries in `.sanitize.toml`; CLI patterns are
    /// applied in addition to, not instead of, project config patterns.
    /// Example: --exclude-path "tests/fixtures/" --exclude-path "**/*.generated.*"
    #[arg(long, value_name = "GLOB", num_args = 1)]
    exclude_path: Vec<String>,

    /// Only process files matching these glob patterns during directory walks.
    /// Patterns are matched against the path relative to the input root
    /// (or against the filename alone when no `/` is present in the pattern).
    /// A trailing `/` includes the entire subtree.
    /// When both --include-path and --exclude-path match a file, exclusion wins.
    /// Has no effect on explicitly named file arguments or archive entries.
    /// Example: --include-path "**/*.log" --include-path "**/*.conf"
    #[arg(long, value_name = "GLOB", num_args = 1)]
    include_path: Vec<String>,

    /// Bypass all structured processors (JSON, YAML, XML, TOML, etc.) and
    /// run only the streaming scanner on every file.
    ///
    /// Use this when you are uncertain about your field rules or want
    /// a guarantee that every byte in every file is pattern-scanned.
    /// The output is the same byte length as the input but structural
    /// formatting may differ for structured file types.
    /// Under normal operation the structured + scan double-pass handles
    /// this automatically; this flag disables the structured pass entirely.
    #[arg(long)]
    force_text: bool,

    /// Load the built-in balanced detection patterns without requiring a
    /// secrets file. Covers API keys (AWS, GCP, GitHub, GitLab, Stripe,
    /// Slack, OpenAI, Anthropic, HuggingFace, SendGrid, npm), JWTs, emails,
    /// IPv4/IPv6, UUIDs, MAC addresses, PEM headers, and credential URLs.
    /// Additive with `--secrets-file`, `--app`, and `--profile`.
    #[arg(long)]
    use_default: bool,

    /// Number of worker threads. When multiple input files are provided,
    /// files are processed in parallel up to this limit. For a single
    /// archive input, entries are sanitized in parallel using the same
    /// budget. Defaults to the number of logical CPUs. Capped to the
    /// system's available parallelism.
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Chunk size in bytes for the streaming scanner (default: 1 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 1_048_576, hide = true)]
    chunk_size: usize,

    /// Maximum number of unique replacement mappings to keep in memory.
    /// Guards against memory exhaustion when inputs contain huge numbers
    /// of unique matches.  Use 0 for unlimited (not recommended).
    #[arg(long, value_name = "N", default_value_t = 10_000_000, hide = true)]
    max_mappings: usize,

    /// Maximum structured file size in bytes. Files exceeding this limit
    /// fall back to streaming scanner instead of structured processing.
    /// Prevents unbounded memory usage from large structured files (F-03 fix).
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_STRUCTURED_FILE_SIZE, hide = true)]
    max_structured_size: u64,

    /// Maximum nesting depth for recursive archive processing.
    /// Nested archives (e.g. a .tar.gz inside a .zip) are extracted and
    /// sanitized recursively up to this depth. Exceeding the limit is an
    /// error. Maximum allowed value is 10 (each level may buffer up to
    /// 256 MiB).
    #[arg(long, value_name = "N", default_value_t = DEFAULT_ARCHIVE_DEPTH, hide = true)]
    max_archive_depth: u32,

    /// Log output format: "human" (default) or "json" (for SIEM ingestion).
    #[arg(long, value_name = "FMT")]
    log_format: Option<String>,

    /// Log level: off, error, warn (default), info, debug, or trace.
    /// Overrides SANITIZE_LOG when both are set.
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Progress display mode: auto (default), on, or off.
    #[arg(long, value_enum, value_name = "MODE")]
    progress: Option<ProgressMode>,

    /// Disable live progress output. Deprecated: use `--progress off` instead.
    #[arg(long, hide = true)]
    no_progress: bool,

    /// Suppress the post-run redaction summary and all decorative stderr output.
    /// Implies --progress off. Use in scripts or pipelines where only the exit
    /// code matters.
    #[arg(long)]
    quiet: bool,

    /// Minimum interval between live progress refreshes.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_PROGRESS_INTERVAL_MS, hide = true)]
    progress_interval_ms: u64,

    /// Write per-file findings as newline-delimited JSON (NDJSON) to PATH.
    /// Omit PATH to write to stdout. Use "-" explicitly for stdout.
    /// Each line is a JSON object: one `{"type":"file",...}` per processed
    /// file, followed by a `{"type":"summary",...}` line. Compatible with
    /// `jq`, SIEM ingest, and other line-oriented JSON tools.
    /// In default sanitize mode prefer an explicit path so sanitized content
    /// on stdout is not mixed with findings.
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "-")]
    findings: Option<PathBuf>,

    /// After sanitizing, extract lines matching error/warning keywords with
    /// surrounding context and include them in the JSON report. Useful when
    /// sending a large log to support: sanitize the full file, then share
    /// only the relevant excerpts via `--report`.
    ///
    /// Use `--context-lines` to control how many surrounding lines to capture,
    /// `--context-keywords` to add your own keywords, and `--context-keywords-replace`
    /// to use only your keywords instead of the built-in list.
    #[arg(long)]
    extract_context: bool,

    /// Lines of context before and after each keyword match. Default: 10.
    #[arg(long, value_name = "N", default_value_t = 10)]
    context_lines: usize,

    /// Comma-separated extra keywords to search for when `--extract-context`
    /// is set. Merged with the built-in list (error, failure, warning, warn,
    /// fatal, exception, critical, panic, timeout, oomkilled) by default.
    /// Use `--context-keywords-replace` to suppress the built-in list and use
    /// only these keywords.
    ///
    /// Example: --extract-context --context-keywords "connection refused,ECONNREFUSED"
    #[arg(long, value_name = "KEYWORDS", value_delimiter = ',')]
    context_keywords: Vec<String>,

    /// Replace the built-in keyword list entirely with the keywords given by
    /// `--context-keywords`. Without this flag, custom keywords are merged
    /// with the built-ins. Has no effect if `--context-keywords` is not set.
    #[arg(long)]
    context_keywords_replace: bool,

    /// Maximum number of keyword matches to capture per file when
    /// `--extract-context` is set. Matches beyond this limit are silently
    /// dropped and `truncated` is set to `true` in the report. Default: 50.
    #[arg(long, value_name = "N", default_value_t = 50)]
    max_context_matches: usize,

    /// Maximum number of per-match line numbers to record in the report when
    /// `--report` is active. Each entry stores the 1-based line number, byte
    /// offset, and pattern label for one scanner match. Set to 0 to disable
    /// line-number tracking entirely (useful for very large files where even
    /// the cap overhead is undesirable). Default: 500.
    #[arg(long, value_name = "N", default_value_t = 500)]
    max_match_locations: usize,

    /// Use case-sensitive keyword matching when `--extract-context` is set.
    /// By default matching is case-insensitive (`ERROR`, `error`, and `Error`
    /// all match the keyword `error`).
    #[arg(long)]
    context_case_sensitive: bool,

    /// Strip all values from structured output, emitting only keys and
    /// structure. Useful for generating a profile template from a real
    /// config file without exposing any secret values. Bypasses the
    /// sanitization pipeline — no secrets file is required.
    #[arg(long)]
    strip_values: bool,

    /// Key-value delimiter used by `--strip-values` (default: `=`).
    #[arg(
        long,
        value_name = "DELIM",
        default_value = "=",
        requires = "strip_values"
    )]
    strip_delimiter: String,

    /// Comment-line prefix used by `--strip-values` (default: `#`).
    #[arg(
        long,
        value_name = "PREFIX",
        default_value = "#",
        requires = "strip_values"
    )]
    strip_comment_prefix: String,

    /// Format sanitized output as an LLM-ready prompt on stdout.
    /// TEMPLATE chooses the instruction set:
    ///
    /// - `troubleshoot`    (default) — incident triage: root cause, event sequence, remediation
    /// - `review-config`             — config review: misconfigurations, best practices
    /// - `review-security`           — security posture: auth, exposure, TLS, CVEs, hardcoded secrets
    ///
    /// TEMPLATE may also be a path to a custom template file.
    /// Combine with `--extract-context` to include notable log events.
    ///
    /// Without `--output` (inline mode): sanitized content is embedded directly
    /// in `<content>` blocks in the prompt.
    ///
    /// With `--output` (reference mode): sanitized files are written to disk and
    /// the prompt lists their absolute paths — for large file sets or agentic
    /// LLMs that can read files with their own tools.
    #[arg(long, value_name = "TEMPLATE", default_missing_value = "troubleshoot", num_args = 0..=1)]
    llm: Option<String>,

    /// Load built-in secrets patterns and structured field profiles for one or
    /// more applications. Comma-separated list of app names.
    ///
    /// Example: `--app gitlab`  `--app gitlab,nginx,postgresql`
    ///
    /// Can be combined with `--secrets-file` (additive) and `--profile`
    /// (profiles are merged).
    ///
    /// Run `sanitize apps` to list available app names and descriptions.
    #[arg(long, value_delimiter = ',', value_name = "APPS")]
    app: Vec<String>,

    /// Allow a specific value through unchanged. Repeatable.
    ///
    /// Matched values are not replaced and not recorded in the mapping store,
    /// so they will also pass through in any other files processed in the same
    /// run. Three pattern forms are supported:
    ///
    /// - Exact: `--allow localhost`
    /// - Glob (`*` wildcard): `--allow "*.internal"`  `--allow "192.168.1.*"`
    /// - Regex (prefix with `regex:`): `--allow "regex:^10\.[0-9]+\.[0-9]+\.[0-9]+$"`
    ///
    /// Allowlist entries can also be placed in the secrets file as
    /// `kind: allow` entries.
    #[arg(long = "allow", value_name = "PATTERN")]
    allow: Vec<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            command: None,
            input: vec![],
            output: None,
            secrets_file: None,
            profile: None,
            password: false,
            password_file: None,
            encrypted_secrets: false,
            format: None,
            dry_run: false,
            fail_on_match: false,
            report: None,
            report_format: ReportFormat::Json,
            strict: false,
            deterministic: false,
            no_structured_handoff: false,
            no_field_signal: false,
            include_binary: false,
            hidden: false,
            force_text: false,
            use_default: false,
            threads: None,
            chunk_size: 1_048_576,
            max_mappings: 10_000_000,
            max_structured_size: DEFAULT_MAX_STRUCTURED_FILE_SIZE,
            max_archive_depth: DEFAULT_ARCHIVE_DEPTH,
            log_format: None,
            log_level: None,
            progress: None,
            no_progress: false,
            quiet: false,
            progress_interval_ms: DEFAULT_PROGRESS_INTERVAL_MS,
            findings: None,
            extract_context: false,
            context_lines: DEFAULT_CONTEXT_LINES,
            context_keywords: vec![],
            context_keywords_replace: false,
            max_context_matches: DEFAULT_MAX_MATCHES,
            context_case_sensitive: false,
            max_match_locations: 500,
            strip_values: false,
            strip_delimiter: "=".to_string(),
            strip_comment_prefix: "#".to_string(),
            llm: None,
            app: vec![],
            allow: vec![],
            exclude_path: vec![],
            include_path: vec![],
            entropy_threshold: None,
        }
    }
}

impl Cli {
    fn effective_progress_mode(&self) -> ProgressMode {
        if self.quiet {
            ProgressMode::Off
        } else if let Some(mode) = self.progress {
            mode
        } else if self.no_progress {
            ProgressMode::Off
        } else {
            ProgressMode::Auto
        }
    }

    fn effective_log_format(&self) -> &str {
        self.log_format.as_deref().unwrap_or("human")
    }

    fn effective_log_level(&self) -> &str {
        self.log_level.as_deref().unwrap_or("warn")
    }
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Encrypt a plaintext secrets file for use with the sanitizer.
    ///
    /// Uses AES-256-GCM authenticated encryption with a key derived via
    /// PBKDF2-HMAC-SHA256 (600,000 iterations).
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize encrypt secrets.json secrets.json.enc --password \"my-password\"\n  \
  SANITIZE_PASSWORD=hunter2 sanitize encrypt secrets.yaml secrets.yaml.enc\n  \
  sanitize encrypt secrets.toml secrets.toml.enc  # interactive prompt")]
    Encrypt(EncryptArgs),

    /// Decrypt an encrypted secrets file back to plaintext.
    ///
    /// Useful for editing secrets before re-encrypting.
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize decrypt secrets.json.enc secrets.json --password \"my-password\"\n  \
  sanitize decrypt secrets.enc out.yaml --password-file /run/secrets/pw")]
    Decrypt(DecryptArgs),

    /// Manage app bundles: list, add, remove, or show the user apps directory.
    ///
    /// Run `sanitize apps` with no subcommand to list all available bundles.
    #[command(name = "apps")]
    Apps(AppsArgs),

    /// Test which values match your allowlist patterns.
    ///
    /// Prints each value with a ✓ (matched) or ✗ (no match) and shows which
    /// pattern matched. Useful for verifying glob patterns before committing
    /// to a full sanitization run.
    #[command(
        name = "allow-test",
        after_help = "\
EXAMPLES:\n  \
  sanitize allow-test --allow '*.internal' db.internal github.com\n  \
  sanitize allow-test --allow localhost --allow '*.internal' --allow '192.168.1.*' db.internal 192.168.1.5 8.8.8.8\n  \
  sanitize allow-test --allow 'regex:^10\\.[0-9]+\\.[0-9]+\\.[0-9]+$' 10.0.0.1 192.168.1.1\n  \
  echo -e 'db.internal\\ngithub.com\\n192.168.1.5' | sanitize allow-test --allow '*.internal' --allow '192.168.1.*'\n  \
  sanitize allow-test --allow '*.internal' db.internal --json"
    )]
    AllowTest(AllowTestArgs),

    /// Interactive guided setup for logs-focused secrets templates.
    #[command(after_help = "\
EXAMPLES:\n  \
    sanitize guided")]
    Guided,

    /// Generate a starter secrets-template YAML file for a given use case.
    ///
    /// Templates include commented-out examples and common patterns so
    /// support engineers, sysadmins, and DevOps teams can get started
    /// quickly before sending logs or configs to an LLM.
    #[command(after_help = "\
PRESETS\n  \
  generic    Common secrets: tokens, emails, IPs, hostnames (default)\n  \
  web        Web-app logs: JWTs, sessions, emails, URLs\n  \
  k8s        Kubernetes configs: service-accounts, tokens, namespaces\n  \
  database   Database configs: passwords, connection strings, usernames\n  \
  aws        AWS: access keys, ARNs, account IDs\n\n\
EXAMPLES:\n  \
  sanitize template                     # generic → secrets.template.yaml\n  \
  sanitize template --preset web        # web-app template\n  \
  sanitize template --preset k8s -o k8s-secrets.yaml")]
    Template(TemplateArgs),

    /// Install a git hook that scans (or sanitizes) staged files before each commit.
    ///
    /// Detects husky and falls back to a raw .git/hooks/ script. Use --global
    /// to apply to every repository on this machine.
    ///
    /// The installed script is plain POSIX sh and can be inspected or edited
    /// directly. Remove it with --remove or by deleting the hook file.
    ///
    /// Run `sanitize init-hook` first to create the global settings file and
    /// install a hook in the current repository.
    #[command(
        name = "install-hook",
        after_help = "\
EXAMPLES:\n  \
  sanitize install-hook                              # scan with auto-loaded default secrets\n  \
  sanitize install-hook --app gitlab,kubernetes      # scan with app bundles\n  \
  sanitize install-hook -s secrets.yaml              # scan with custom secrets file\n  \
  sanitize install-hook --mode sanitize              # sanitize staged files in place\n  \
  sanitize install-hook --hook pre-push              # install a pre-push hook\n  \
  sanitize install-hook --global                     # apply to all repos on this machine\n  \
  sanitize install-hook --remove                     # remove the installed hook\n  \
  sanitize install-hook --dry-run                    # preview without writing"
    )]
    InstallHook(InstallHookArgs),

    /// Show the effective configuration that will be applied on the next run.
    ///
    /// Prints the paths and active values from `~/.config/sanitize/settings.yaml`
    /// and reports whether the default secrets file is present. Useful for
    /// debugging unexpected behaviour or verifying CI setup.
    #[command(name = "show-config")]
    ShowConfig,

    /// One-time repo setup: create the global settings file and install a git
    /// hook for the current repository.
    ///
    /// The settings file is written to ~/.config/sanitize/settings.yaml
    /// (or $XDG_CONFIG_HOME/sanitize/settings.yaml) and lets you set persistent
    /// flag defaults. The global secrets file is created automatically on the
    /// first plain `sanitize` run — no explicit setup needed.
    #[command(
        name = "init-hook",
        after_help = "\
EXAMPLES:\n  \
  sanitize init-hook                        # create settings file + pre-commit hook\n  \
  sanitize init-hook --mode sanitize        # hook sanitizes files in place\n  \
  sanitize init-hook --hook pre-push        # hook runs on push instead\n  \
  sanitize init-hook --global               # apply hook to all repos on this machine"
    )]
    InitHook(InitArgs),

    /// Scan files for secrets without modifying them. Exits 2 if any are found.
    ///
    /// Equivalent to running the default sanitize mode with --dry-run and
    /// --fail-on-match, but discoverable as a dedicated subcommand. Designed
    /// for CI pipelines where you want detection without rewriting files.
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize scan app.log -s secrets.yaml              # scan a log file\n  \
  sanitize scan ./logs/ -s secrets.yaml              # scan a directory\n  \
  sanitize scan app.log --app gitlab                 # scan using an app bundle\n  \
  sanitize scan . --exclude-path tests/fixtures/      # skip test fixtures\n  \
  git diff HEAD | sanitize scan                      # scan a patch from stdin\n  \
  sanitize scan app.log -s s.enc --encrypted-secrets -p  # encrypted secrets")]
    Scan(ScanArgs),

    /// Test whether secrets patterns match example values.
    ///
    /// Useful when authoring custom patterns in a secrets file. Provide one
    /// or more patterns (inline or from a file) and a set of example strings,
    /// and the tool reports exactly which pattern matched, the matched span,
    /// and the replacement category. Values can be positional arguments or
    /// piped via stdin.
    #[command(
        name = "test-pattern",
        after_help = "\
EXAMPLES:\n  \
  sanitize test-pattern --pattern 'ghp_[A-Za-z0-9_]{36}' 'ghp_abc123'\n  \
  sanitize test-pattern -s secrets.yaml 'my-secret-value' 'safe-value'\n  \
  sanitize test-pattern --app gitlab 'glpat-abc123'\n  \
  echo 'AKIA1234567890ABCDEF' | sanitize test-pattern --app aws\n  \
  sanitize test-pattern -s secrets.yaml --json 'value1' 'value2'"
    )]
    TestPattern(TestPatternArgs),
}

#[derive(Parser, Debug)]
struct EncryptArgs {
    /// Path to plaintext secrets file (.json, .yaml, .yml, .toml).
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Path for encrypted output file (.enc).
    #[arg(value_name = "OUTPUT")]
    output: PathBuf,

    /// Prompt interactively for the encryption password. The password is
    /// never echoed. For non-interactive automation use --password-file or
    /// the SANITIZE_PASSWORD environment variable instead.
    #[arg(long)]
    password: bool,

    /// Read the password from a file (must have 0600 or 0400 permissions).
    #[arg(long = "password-file", value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// Force secrets file format (json, yaml, toml). Default: auto-detect from
    /// file extension.
    #[arg(long, value_parser = parse_format)]
    secrets_format: Option<SecretsFormat>,

    /// Parse the plaintext before encrypting and report any errors.
    /// Enabled by default; use --no-validate to skip.
    #[arg(long, overrides_with = "_no_validate", default_value_t = true)]
    validate: bool,

    /// Skip pre-encryption validation.
    #[arg(long = "no-validate", hide = true)]
    _no_validate: bool,
}

#[derive(Parser, Debug)]
struct DecryptArgs {
    /// Path to encrypted secrets file (.enc).
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Path for decrypted plaintext output.
    #[arg(value_name = "OUTPUT")]
    output: PathBuf,

    /// Prompt interactively for the decryption password. The password is
    /// never echoed. For non-interactive automation use --password-file or
    /// the SANITIZE_PASSWORD environment variable instead.
    #[arg(long)]
    password: bool,

    /// Read the password from a file (must have 0600 or 0400 permissions).
    #[arg(long = "password-file", value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// Validate decrypted content as secrets in this format (json, yaml,
    /// toml). If omitted, the raw decrypted bytes are written as-is.
    #[arg(long, value_parser = parse_format)]
    secrets_format: Option<SecretsFormat>,
}

fn parse_format(s: &str) -> Result<SecretsFormat, String> {
    match s {
        "json" => Ok(SecretsFormat::Json),
        "yaml" | "yml" => Ok(SecretsFormat::Yaml),
        "toml" => Ok(SecretsFormat::Toml),
        other => Err(format!(
            "unknown format '{}' (use json, yaml, or toml)",
            other
        )),
    }
}

#[derive(Parser, Debug)]
struct TemplateArgs {
    /// Which preset to generate.
    ///
    /// Choices: generic, web, k8s, database, aws.
    #[arg(long, short = 'p', default_value = "generic", value_name = "PRESET")]
    preset: String,

    /// Output path for the generated YAML template.
    ///
    /// Default: secrets.template.yaml
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Overwrite the output file if it already exists.
    #[arg(long)]
    overwrite: bool,
}

#[derive(Parser, Debug)]
struct AllowTestArgs {
    /// Allowlist patterns to test. Supports exact strings, * glob wildcards,
    /// and regex: prefix patterns. Repeatable.
    #[arg(long = "allow", value_name = "PATTERN", required = true)]
    allow: Vec<String>,

    /// Values to test against the patterns. If omitted, values are read from
    /// stdin one per line.
    #[arg(value_name = "VALUE")]
    values: Vec<String>,

    /// Output results as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
}

#[derive(Parser, Debug)]
struct ScanArgs {
    /// Files, directories, or archives to scan. Omit to read from stdin.
    /// Use "-" to include stdin alongside file paths.
    #[arg(value_name = "INPUT")]
    input: Vec<PathBuf>,

    /// Path to a secrets file (JSON / YAML / TOML, or encrypted with --encrypted-secrets).
    #[arg(short = 's', long = "secrets-file", value_name = "FILE")]
    secrets_file: Option<PathBuf>,

    /// Treat the secrets file as AES-256-GCM encrypted.
    #[arg(long)]
    encrypted_secrets: bool,

    /// Prompt interactively for the decryption password.
    #[arg(short = 'p', long)]
    password: bool,

    /// Read the decryption password from a file (must be 0600/0400).
    #[arg(short = 'P', long = "password-file", value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// App bundle(s) to load. Comma-separated. Repeatable.
    #[arg(long, value_name = "APPS", value_delimiter = ',')]
    app: Vec<String>,

    /// Allow values through unchanged. Supports * glob patterns. Repeatable.
    #[arg(long, value_name = "PATTERN")]
    allow: Vec<String>,

    /// Field-level profile for structured files.
    #[arg(long = "profile", value_name = "FILE")]
    profile: Option<PathBuf>,

    /// Also walk hidden files and directories (names starting with `.`).
    #[arg(long)]
    hidden: bool,

    /// Exclude paths matching these glob patterns. A trailing `/` prunes the
    /// whole subtree. Merged with `exclude` in `.sanitize.toml`.
    #[arg(long, value_name = "GLOB", num_args = 1)]
    exclude_path: Vec<String>,

    /// Only scan files matching these glob patterns during directory walks.
    /// When both --include-path and --exclude-path match, exclusion wins.
    /// Has no effect on explicitly named file arguments.
    #[arg(long, value_name = "GLOB", num_args = 1)]
    include_path: Vec<String>,

    /// Write a report to this path (or stderr when no path given).
    #[arg(short = 'r', long, value_name = "PATH")]
    report: Option<Option<PathBuf>>,

    /// Output format for --report: json (default), sarif, or html.
    #[arg(long, value_name = "FORMAT", default_value = "json")]
    report_format: ReportFormat,

    /// Number of worker threads (default: auto-detect).
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Log format: "human" (default) or "json".
    #[arg(long, value_name = "FMT")]
    log_format: Option<String>,

    /// Log level: off, error, warn (default), info, debug, or trace.
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Disable progress output. Deprecated: use `--progress off` instead.
    #[arg(long, hide = true)]
    no_progress: bool,

    /// Write findings as NDJSON to stdout instead of human-readable log output.
    /// One JSON object per file, plus a summary line. Implies --progress off.
    /// Pipe into `jq`, `wc -l`, SIEM tools, etc.
    #[arg(long)]
    findings: bool,

    /// Enable Shannon entropy detection with this threshold (bits/char, e.g. 4.5).
    #[arg(long, value_name = "THRESHOLD")]
    entropy_threshold: Option<f64>,

    /// Load the built-in balanced detection patterns without a secrets file.
    /// Same as the main `--use-default` flag.
    #[arg(long)]
    use_default: bool,
}

#[derive(Parser, Debug)]
struct TestPatternArgs {
    /// Inline regex pattern to test. Repeatable — multiple patterns are all
    /// tested and each match is attributed to its pattern. Cannot be combined
    /// with --secrets-file or --app when used alone, but all three sources
    /// are additive if provided together.
    #[arg(long = "pattern", short = 'P', value_name = "REGEX")]
    patterns: Vec<String>,

    /// Secrets file whose patterns to test (JSON / YAML / TOML).
    #[arg(short = 's', long = "secrets-file", value_name = "FILE")]
    secrets_file: Option<PathBuf>,

    /// App bundle(s) whose patterns to test. Comma-separated. Repeatable.
    #[arg(long, value_name = "APPS", value_delimiter = ',')]
    app: Vec<String>,

    /// Example values to test against the patterns. If omitted, values are
    /// read from stdin one per line.
    #[arg(value_name = "VALUE")]
    values: Vec<String>,

    /// Output results as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct AppsArgs {
    #[command(subcommand)]
    command: Option<AppsSubCommand>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum AppsSubCommand {
    /// Install a custom app bundle from local YAML files.
    ///
    /// Copies the supplied profile and/or secrets files into the user apps
    /// directory so the bundle is available via `--app <name>`.
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize apps add elastic --profile elastic.profile.yaml --secrets-file elastic.secrets.yaml\n  \
  sanitize apps add myapp --profile myapp.profile.yaml\n  \
  sanitize apps add myapp --secrets-file myapp.secrets.yaml --overwrite")]
    Add(AppsAddArgs),

    /// Remove a custom app bundle from the user apps directory.
    ///
    /// Built-in bundles cannot be removed.
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize apps remove elastic --yes\n  \
  sanitize apps remove myapp -y")]
    Remove(AppsRemoveArgs),

    /// Copy a built-in app bundle to the user apps directory for editing.
    ///
    /// For built-in apps, copies profile.yaml and/or secrets.yaml into
    /// `~/.config/sanitize/apps/<name>/` so they can be customised. The local
    /// copy takes precedence over the built-in automatically — no extra flags
    /// needed. For user-defined apps the existing directory path is printed.
    ///
    /// To revert to the built-in, run `sanitize apps remove <name> --yes`.
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize apps edit rails\n  \
  sanitize apps edit kubernetes\n  \
  sanitize apps edit gitlab")]
    Edit(AppsEditArgs),

    /// Print the user apps directory path.
    ///
    /// Custom app bundles are stored here. You can also drop directories
    /// manually instead of using `sanitize apps add`.
    Dir,
}

#[derive(Parser, Debug)]
pub(crate) struct AppsAddArgs {
    /// Name for the new app bundle (used with `--app <name>`).
    ///
    /// Only letters, digits, hyphens, and underscores are allowed.
    #[arg(value_name = "NAME")]
    name: String,

    /// Path to a profile YAML file (`Vec<FileTypeProfile>`).
    #[arg(long, value_name = "FILE")]
    profile: Option<PathBuf>,

    /// Path to a secrets YAML file (`Vec<SecretEntry>`).
    #[arg(long, value_name = "FILE")]
    secrets_file: Option<PathBuf>,

    /// Overwrite an existing custom app bundle with the same name.
    #[arg(long)]
    overwrite: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct AppsRemoveArgs {
    /// Name of the custom app bundle to remove.
    #[arg(value_name = "NAME")]
    name: String,

    /// Confirm removal without an interactive prompt.
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct AppsEditArgs {
    /// Name of the app bundle to edit.
    ///
    /// For built-in apps this copies the files to the user apps directory.
    /// For user-defined apps this prints the existing directory path.
    #[arg(value_name = "NAME")]
    name: String,
}

// ─── install-hook types ───────────────────────────────────────────────────────

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum HookType {
    /// Run before each `git commit`.
    #[value(name = "pre-commit")]
    PreCommit,
    /// Run before each `git push`.
    #[value(name = "pre-push")]
    PrePush,
}

impl HookType {
    pub(crate) fn hook_name(&self) -> &'static str {
        match self {
            HookType::PreCommit => "pre-commit",
            HookType::PrePush => "pre-push",
        }
    }
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum HookMode {
    /// Scan staged files and block the commit if secrets are detected.
    /// No files are modified.
    Scan,
    /// Sanitize staged files in place and re-stage them before committing.
    /// WARNING: the committed content will differ from what you typed.
    Sanitize,
}

#[derive(Parser, Debug)]
#[command(after_help = "\
NOTE\n  \
  The hook calls `sanitize` from PATH at commit time — the binary must be\n  \
  installed on every machine that will run the hook. If `sanitize` is not\n  \
  found the hook silently passes rather than blocking the commit.")]
pub(crate) struct InstallHookArgs {
    /// Git hook type to install.
    #[arg(long, value_enum, default_value = "pre-commit", value_name = "HOOK")]
    pub(crate) hook: HookType,

    /// Hook behaviour: scan blocks the commit; sanitize modifies staged files.
    #[arg(long, value_enum, default_value = "scan", value_name = "MODE")]
    pub(crate) mode: HookMode,

    /// Install the hook globally so it applies to every git repository on
    /// this machine. Writes to the directory returned by
    /// `git config --global core.hooksPath` (or ~/.config/git/hooks/ if
    /// not configured).
    #[arg(long)]
    pub(crate) global: bool,

    /// Overwrite an existing hook without prompting. By default the command
    /// refuses to overwrite a hook it did not install.
    #[arg(long, short = 'f')]
    pub(crate) force: bool,

    /// Remove the hook previously installed by `sanitize install-hook`.
    /// Has no effect on hooks not created by this command.
    #[arg(long)]
    pub(crate) remove: bool,

    /// App bundles to load in the hook (comma-separated, e.g. gitlab,kubernetes).
    #[arg(long, value_name = "NAMES")]
    pub(crate) app: Option<String>,

    /// Path to a secrets file to bake into the hook invocation.
    #[arg(short = 's', long, value_name = "FILE")]
    pub(crate) secrets_file: Option<PathBuf>,

    /// Print the hook script that would be installed without writing any files.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct InitArgs {
    /// Hook type to install.
    #[arg(long, value_enum, default_value = "pre-commit", value_name = "HOOK")]
    pub(crate) hook: HookType,

    /// Hook behaviour: scan blocks the commit without modifying files;
    /// sanitize rewrites staged files in place.
    #[arg(long, value_enum, default_value = "scan", value_name = "MODE")]
    pub(crate) mode: HookMode,

    /// Install the hook globally (all repositories on this machine).
    #[arg(long)]
    pub(crate) global: bool,

    /// Overwrite an existing settings file even if it already exists.
    #[arg(long, short = 'f')]
    pub(crate) force: bool,

    /// Print what would be created without writing any files.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

fn run_scan(args: &ScanArgs) -> Result<(), (String, i32)> {
    // Resolve password before building Cli so interactive prompts fire before
    // any other output (mirrors the logic in run()).
    let pre_resolved_password: Option<Zeroizing<String>> =
        if args.encrypted_secrets && !args.password {
            // Non-interactive sources: env var or password file.
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
        // --findings suppresses progress so stdout stays clean for piping.
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
        use_default: args.use_default,
    };

    run_sanitize(cli, pre_resolved_password, HashMap::new())
}

fn run_test_pattern(args: &TestPatternArgs) -> Result<(), (String, i32)> {
    // ── Collect SecretEntry objects from all pattern sources ──────────────────
    let mut entries: Vec<SecretEntry> = Vec::new();

    // 1. Inline --pattern flags.
    for p in &args.patterns {
        entries.push(SecretEntry {
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

    // 2. --secrets-file.
    if let Some(ref path) = args.secrets_file {
        let bytes =
            fs::read(path).map_err(|e| (format!("failed to read {}: {e}", path.display()), 1))?;
        let format = SecretsFormat::from_extension(path.to_string_lossy().as_ref());
        let mut file_entries = parse_secrets(&bytes, format)
            .map_err(|e| (format!("failed to parse {}: {e}", path.display()), 1))?;
        // Strip allow entries — they're not patterns to test against.
        file_entries.retain(|e| e.kind != "allow");
        entries.extend(file_entries);
    }

    // 3. --app bundles.
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

    // ── Compile each entry into a (label, regex) pair ─────────────────────────
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

    // ── Collect values from positional args or stdin ──────────────────────────
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

    // ── Match each value against all patterns ────────────────────────────────
    struct MatchHit {
        label: String,
        category: String,
        matched_text: String,
        /// The span within `value` that was matched (for display).
        start: usize,
        end: usize,
        /// True when only capture group 1 is replaced (partial match).
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
                    // Capture group 1 = partial replacement; full match = group 0.
                    let (span, partial) = if let Some(g1) = m.get(1) {
                        (g1, true)
                    } else {
                        (m.get(0).unwrap(), false)
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

    // ── Output ────────────────────────────────────────────────────────────────
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

    // Exit 1 if any value was unmatched — useful for scripting / CI.
    if total_matched < results.len() {
        Err(("some values did not match any pattern".into(), 1))
    } else {
        Ok(())
    }
}

fn run_allow_test(args: &AllowTestArgs) -> Result<(), (String, i32)> {
    use sanitize_engine::allowlist::AllowlistMatcher;

    let (matcher, warnings) = AllowlistMatcher::new(args.allow.clone());
    for w in &warnings {
        eprintln!("warning: {w}");
    }

    // Collect values from positional args or stdin (one per line).
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

fn run_template(args: &TemplateArgs) -> Result<(), (String, i32)> {
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

fn normalize_guided_output_path(path: PathBuf) -> PathBuf {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        Some(ext) if ext == "yaml" || ext == "yml" => path,
        _ => path.with_extension("yaml"),
    }
}

fn prompt_confirm_password() -> Result<Zeroizing<String>, String> {
    loop {
        let pw1 = prompt_password("encryption")?;
        let pw2 = prompt_password("encryption (confirm)")?;
        if pw1 == pw2 {
            return Ok(pw1);
        }
        // pw1 and pw2 are Zeroizing<String>; both zeroed on drop here.
        eprintln!("Passwords did not match. Try again.");
    }
}

fn run_guided() -> Result<(), (String, i32)> {
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

    // --- Profile file ---
    let profile_path: Option<PathBuf> = if options.formats.is_empty() {
        None
    } else {
        let profiles = build_guided_profiles(&options);
        let profile_yaml = serde_yaml_ng::to_string(&profiles)
            .map_err(|e| (format!("failed to serialize profile: {e}"), 1))?;

        // Default profile filename mirrors the secrets filename.
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
        // Remove the plaintext file now that encryption succeeded — leaving it
        // on disk would defeat the purpose of encrypting.
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a password from multiple sources (priority order):
///   1. `--password` CLI flag
///   2. `--password-file <PATH>` (read file, check Unix permissions)
///   3. `SANITIZE_PASSWORD` environment variable
///   4. Interactive prompt via rpassword (stderr)
///
/// Returns an error only when all sources are exhausted or invalid.
fn resolve_password(
    password_flag: bool,
    cli_password_file: &Option<PathBuf>,
    interactive_label: &str,
) -> Result<Zeroizing<String>, String> {
    // 1. Explicit --password flag → interactive prompt.
    if password_flag {
        if !io::stdin().is_terminal() {
            return Err("--password requires an interactive terminal. \
                 For non-interactive use, supply the password via \
                 --password-file or the SANITIZE_PASSWORD environment variable."
                .into());
        }
        return prompt_password(interactive_label);
    }

    // 2. --password-file.
    if let Some(path) = cli_password_file {
        return read_password_file(path);
    }

    // 3. SANITIZE_PASSWORD env var.
    if let Ok(pw) = std::env::var("SANITIZE_PASSWORD") {
        if !pw.is_empty() {
            // Remove from the environment immediately so it is not visible
            // in /proc/self/environ or to child processes after this point.
            std::env::remove_var("SANITIZE_PASSWORD");
            eprintln!("info: using password from SANITIZE_PASSWORD environment variable");
            return Ok(Zeroizing::new(pw));
        }
    }

    // 4. Interactive prompt.
    prompt_password(interactive_label)
}

/// Read a password from a file, enforcing strict Unix permissions.
#[cfg(unix)]
fn read_password_file(path: &Path) -> Result<Zeroizing<String>, String> {
    use nix::sys::stat::fstat;
    use std::os::unix::io::AsRawFd;

    let file = fs::File::open(path)
        .map_err(|e| format!("cannot open password file {}: {e}", path.display()))?;

    let stat = fstat(file.as_raw_fd())
        .map_err(|e| format!("cannot stat password file {}: {e}", path.display()))?;

    let mode = stat.st_mode & 0o777;
    if mode != 0o600 && mode != 0o400 {
        return Err(format!(
            "password file {} has permissions {:04o}; expected 0600 or 0400. \
             Fix with: chmod 600 {}",
            path.display(),
            mode,
            path.display(),
        ));
    }

    read_password_file_contents(path)
}

/// Read a password from a file (no permission checks on non-Unix platforms).
#[cfg(not(unix))]
fn read_password_file(path: &Path) -> Result<Zeroizing<String>, String> {
    eprintln!(
        "warning: password-file permission checks are only available on Unix. \
         Ensure {} is not world-readable.",
        path.display(),
    );
    read_password_file_contents(path)
}

/// Shared helper: read and trim password file contents.
fn read_password_file_contents(path: &Path) -> Result<Zeroizing<String>, String> {
    const MAX_PASSWORD_FILE_BYTES: u64 = 4096;
    let size = fs::metadata(path)
        .map_err(|e| format!("cannot stat password file {}: {e}", path.display()))?
        .len();
    if size > MAX_PASSWORD_FILE_BYTES {
        return Err(format!(
            "password file {} is too large ({size} bytes); expected ≤ {MAX_PASSWORD_FILE_BYTES} bytes",
            path.display(),
        ));
    }

    let mut contents = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| format!("cannot read password file {}: {e}", path.display()))?,
    );

    // Trim a single trailing newline (common in files created by echo/printf).
    if contents.ends_with('\n') {
        contents.pop();
        if contents.ends_with('\r') {
            contents.pop();
        }
    }

    if contents.is_empty() {
        return Err(format!("password file {} is empty", path.display()));
        // contents is Zeroizing<String> — zeroed on drop.
    }

    Ok(contents)
}

/// Prompt for a password on stderr with hidden input.
fn prompt_password(label: &str) -> Result<Zeroizing<String>, String> {
    let pw = rpassword::prompt_password(format!("Enter {label} password: "))
        .map_err(|e| format!("failed to read password: {e}"))?;

    if pw.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(Zeroizing::new(pw))
}

/// Resolve password for the default sanitize mode.
fn resolve_sanitize_password(cli: &Cli) -> Result<Zeroizing<String>, String> {
    resolve_password(cli.password, &cli.password_file, "secrets decryption")
}

/// Return `true` if the first 512 bytes look like binary (contain NUL
/// bytes or a high ratio of non-UTF-8 bytes).
fn looks_binary(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(512)];
    if sample.contains(&0u8) {
        return true;
    }
    let non_text = sample
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    non_text as f64 / sample.len().max(1) as f64 > 0.10
}

/// Build an `Arc<MappingStore>` with the chosen generator mode.
fn build_store(
    deterministic: bool,
    password: Option<&str>,
    max_mappings: usize,
    allowlist: Option<Arc<sanitize_engine::allowlist::AllowlistMatcher>>,
) -> std::result::Result<Arc<MappingStore>, String> {
    let generator: Arc<dyn ReplacementGenerator> = if deterministic {
        match password {
            Some(k) => {
                use hmac::Hmac;
                use sha2::Sha256;
                let mut buf = Zeroizing::new([0u8; 32]);
                let salt = b"sanitize-engine:deterministic-seed:v1";
                pbkdf2::pbkdf2::<Hmac<Sha256>>(k.as_bytes(), salt, 600_000, buf.as_mut())
                    .expect("PBKDF2 output length is valid");
                // Pass *buf directly into HmacGenerator; no named intermediate means
                // no plain-stack copy of the derived key outlives this expression.
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
///
/// These values match the balanced detection patterns (IPs, UUIDs, URLs) but
/// carry no sensitive information — they appear in virtually every config file,
/// log, and deployment artefact.
pub(crate) fn common_allow_patterns() -> Vec<String> {
    vec![
        // Loopback and unroutable IPv4 addresses.
        "127.0.0.1".into(),
        "0.0.0.0".into(),
        "255.255.255.255".into(),
        "255.255.255.0".into(),
        "255.255.0.0".into(),
        "255.0.0.0".into(),
        // IPv6 loopback.
        "::1".into(),
        // Standard loopback hostnames.
        "localhost".into(),
        "localhost.localdomain".into(),
        // Loopback URLs — common in dev configs and health-check endpoints.
        "http://localhost*".into(),
        "https://localhost*".into(),
        "http://127.0.0.1*".into(),
        "https://127.0.0.1*".into(),
        // RFC 2606 example domains (IANA-reserved for documentation and testing).
        "example.com".into(),
        "example.org".into(),
        "example.net".into(),
        "http://example.com*".into(),
        "https://example.com*".into(),
        "https://example.org*".into(),
        "https://example.net*".into(),
        // Null UUID and common placeholder UUIDs.
        "00000000-0000-0000-0000-000000000000".into(),
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".into(),
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
        "12345678-1234-1234-1234-123456789abc".into(),
        // Common placeholder words that appear in docs, default configs, and templates.
        "changeme".into(),
        "example".into(),
        "sample".into(),
        "placeholder".into(),
        // Template variable syntax — these are never real secret values.
        "${*}".into(),
        "{{*}}".into(),
    ]
}

/// Compile the built-in balanced detection patterns used by `--default`.
///
/// Patterns are derived from `build_guided_entries` with `GuidedPreset::Balanced`
/// and no cloud providers, domains, or format overrides.
fn build_default_patterns() -> Vec<ScanPattern> {
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
        // Built-in patterns are known-good; log but don't abort.
        for (i, e) in &errors {
            warn!(entry = i, error = %e, "built-in default pattern failed to compile");
        }
    }
    patterns
}

// ---------------------------------------------------------------------------
// Built-in field-name signals
// ---------------------------------------------------------------------------

/// Build the two built-in field-name signal groups active when `--use-default`,
/// `--app`, or `--profile` is in use (unless `--no-field-signal` suppresses them).
///
/// # Pattern matching
///
/// Patterns are **unanchored substrings** (case-insensitive). A field name
/// triggers a signal when it **contains** the keyword anywhere, so compound
/// names like `password_hash`, `db_password`, `access_token`, `ssl_cert` all
/// fire without requiring an exact match. The Shannon entropy gate is the
/// semantic filter that rejects low-entropy values (`true`, `Bearer`, `disabled`).
///
/// # Thresholds
///
/// | Group | Keywords | Threshold | Rationale |
/// |-------|----------|-----------|-----------|
/// | Strong | `password`, `passwd`, `secret`, `private_key`, `api_secret`, `client_secret` | **3.0** bits/char | High-confidence keywords — flag even moderately weak values |
/// | Medium | `api_key`, `access_key`, `auth_token`, `token`, `signing_key`, `encryption_key`, `credential`, `cert` | **3.5** bits/char | Ambiguous keywords — skip enum-like values (`Bearer`, `basic`) |
///
/// Override per-signal in the secrets file with `kind: field-name` + `threshold: <f64>`.
/// Disable entirely with `--no-field-signal`.
fn builtin_field_name_signals() -> Vec<FieldNameSignal> {
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
/// them into [`FieldNameSignal`]s.  Invalid regex patterns are logged as
/// warnings and skipped.
fn field_signals_from_entries(entries: &[SecretEntry]) -> Vec<FieldNameSignal> {
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

// ---------------------------------------------------------------------------
// Augmented scanner (Phase 2)
// ---------------------------------------------------------------------------

/// Build an augmented scanner after the profile pass (Phase 1).
///
/// Takes the pre-compiled base patterns (from all sources — secrets file,
/// `--default`, `--app`) and adds a literal `ScanPattern` for every original
/// value recorded in `store` during Phase 1. This allows the scanner to catch
/// those same values verbatim in plain-text files processed in Phase 2.
///
/// Values shorter than 4 bytes are skipped to avoid false positives.
fn build_augmented_scanner(
    base_patterns: &[ScanPattern],
    store: &Arc<MappingStore>,
    scan_config: ScanConfig,
) -> std::result::Result<Arc<StreamScanner>, (String, i32)> {
    let mut patterns = base_patterns.to_vec();

    // Harvest original values recorded by the profile processor in Phase 1.
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
fn build_scan_config(chunk_size: usize) -> Result<ScanConfig, String> {
    if chunk_size == 0 {
        return Err("--chunk-size must be greater than 0".into());
    }
    // Overlap = 25% of chunk, capped at 4 KiB, minimum 1 byte.
    // This replaces the previous `chunk_size.clamp(256, 4096)` which
    // returned chunk_size itself for any value in [256, 4096], making
    // overlap >= chunk_size and causing every small chunk to be rejected.
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

/// Derive a default output path for archive files.
fn default_archive_output(input: &Path, fmt: ArchiveFormat) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = match fmt {
        ArchiveFormat::Zip => "zip",
        ArchiveFormat::Tar => "tar",
        ArchiveFormat::TarGz => "tar.gz",
    };
    let base = if matches!(fmt, ArchiveFormat::TarGz) {
        stem.strip_suffix(".tar").unwrap_or(stem)
    } else {
        stem
    };
    input.with_file_name(format!("{base}.sanitized.{ext}"))
}

// ---------------------------------------------------------------------------
// Logging initialisation
// ---------------------------------------------------------------------------

/// Initialise the `tracing` subscriber based on the `--log-format` flag.
///
/// - `"human"` → compact human-readable on stderr.
/// - `"json"` → structured JSON on stderr (SIEM-friendly).
///
/// In both modes the default level is `INFO` and can be overridden via
/// the `SANITIZE_LOG` environment variable (e.g. `SANITIZE_LOG=debug`).
///
/// **Security**: no secret values are ever passed to tracing macros —
/// only opaque identifiers, counts, paths, and durations are logged.
fn init_logging(log_format: &str, log_level: &str) {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_env("SANITIZE_LOG").unwrap_or_else(|_| EnvFilter::new(log_level));

    match log_format {
        "json" => {
            let _ = fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .with_writer(io::stderr)
                .try_init();
        }
        _ => {
            let _ = fmt()
                .compact()
                .with_env_filter(filter)
                .with_target(false)
                .with_writer(io::stderr)
                .try_init();
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns `true` when input should be read from stdin.
fn has_stdin_input(cli: &Cli) -> bool {
    cli.input.is_empty() || cli.input.iter().any(|p| p.as_os_str() == "-")
}

/// Returns `true` when stdin is an OS-level pipe (FIFO), not a terminal,
/// a regular file, or /dev/null.  This distinguishes `cat foo | sanitize`
/// from test harnesses that pass `Stdio::null()` or redirect a plain file.
#[cfg(unix)]
fn stdin_is_pipe() -> bool {
    use nix::sys::stat::fstat;
    use std::os::unix::io::AsRawFd;
    fstat(io::stdin().as_raw_fd())
        .map(|s| {
            nix::sys::stat::SFlag::from_bits_truncate(s.st_mode)
                .contains(nix::sys::stat::SFlag::S_IFIFO)
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn stdin_is_pipe() -> bool {
    // GetFileType returns FILE_TYPE_PIPE (3) only for actual anonymous/named
    // pipes.  NUL, regular files, and consoles return other values, so this
    // correctly excludes `Stdio::null()` (which maps to NUL) from being
    // treated as piped input.
    use std::os::windows::io::AsRawHandle;
    extern "system" {
        fn GetFileType(hFile: *mut std::ffi::c_void) -> u32;
    }
    const FILE_TYPE_PIPE: u32 = 3;
    let handle = io::stdin().as_raw_handle();
    // SAFETY: stdin handle is valid for the lifetime of the process.
    unsafe { GetFileType(handle as *mut _) == FILE_TYPE_PIPE }
}

#[cfg(not(any(unix, windows)))]
fn stdin_is_pipe() -> bool {
    !io::stdin().is_terminal()
}

/// Returns file-path inputs, excluding explicit stdin markers ("-").
fn file_inputs(cli: &Cli) -> Vec<&PathBuf> {
    cli.input.iter().filter(|p| p.as_os_str() != "-").collect()
}

/// Map the `--format` value to extension-like string for structured processor
/// lookup. Returns `None` for "text" or unrecognised values.
fn format_to_ext(fmt: &str) -> Option<&str> {
    match fmt {
        "json" => Some("json"),
        "jsonl" | "ndjson" => Some("jsonl"),
        "yaml" | "yml" => Some("yaml"),
        "xml" => Some("xml"),
        "csv" => Some("csv"),
        "tsv" => Some("tsv"),
        "key-value" | "key_value" | "kv" => Some("conf"),
        "toml" => Some("toml"),
        "env" => Some("env"),
        "ini" => Some("ini"),
        "log" => Some("log"),
        _ => None,
    }
}

fn default_plain_output(input: &Path) -> PathBuf {
    let name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output");

    let output_name = if let Some((stem, ext)) = name.rsplit_once('.') {
        format!("{stem}-sanitized.{ext}")
    } else {
        format!("{name}-sanitized")
    };

    input.with_file_name(output_name)
}

fn split_name_for_suffix(name: &str) -> (String, String) {
    if let Some(stem) = name.strip_suffix(".tar.gz") {
        return (stem.to_string(), ".tar.gz".to_string());
    }
    if let Some((stem, ext)) = name.rsplit_once('.') {
        return (stem.to_string(), format!(".{ext}"));
    }
    (name.to_string(), String::new())
}

fn uniquify_output_path(path: PathBuf, used: &mut HashSet<PathBuf>) -> PathBuf {
    if !path.exists() && !used.contains(&path) {
        used.insert(path.clone());
        return path;
    }

    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output")
        .to_string();
    let (stem, ext) = split_name_for_suffix(&name);

    let mut idx = 1usize;
    loop {
        let candidate = parent.join(format!("{stem}-{idx}{ext}"));
        if !candidate.exists() && !used.contains(&candidate) {
            used.insert(candidate.clone());
            return candidate;
        }
        idx += 1;
    }
}

enum InputTarget {
    Stdin { output: Option<PathBuf> },
    File { input: PathBuf, output: PathBuf },
}

/// VCS metadata directories skipped unconditionally during directory walks.
const SKIP_VCS_DIRS: &[&str] = &[".git", ".hg", ".svn", ".bzr"];

/// A single file resolved from a CLI input (explicit file or directory walk).
/// `dir_root` is set when the file was expanded from a directory argument;
/// it is used to compute relative paths for mirrored output trees.
struct ExpandedInput {
    path: PathBuf,
    dir_root: Option<PathBuf>,
}

/// Recursively collect all files under `dir`, skipping VCS dirs and
/// (unless `include_hidden`) any entry whose name starts with `.`.
/// Symlinks are never followed. Entries are yielded in sorted order for
/// deterministic processing.
fn walk_dir(dir: &Path, include_hidden: bool) -> Result<Vec<PathBuf>, String> {
    use walkdir::WalkDir;
    let mut files = Vec::new();
    let walker = WalkDir::new(dir).follow_links(false).sort_by_file_name();

    for entry in walker {
        let entry = entry.map_err(|e| format!("error walking {}: {e}", dir.display()))?;
        let name = entry.file_name().to_str().unwrap_or("");

        // Skip VCS dirs (filter on the directory entry so the entire subtree
        // is pruned, not just the top-level dir itself).
        if entry.file_type().is_dir() && SKIP_VCS_DIRS.contains(&name) {
            continue;
        }

        // Skip hidden entries unless --hidden is set.  The walk root itself
        // may be hidden (e.g. `sanitize .hidden-dir/`) — allow it through.
        if !include_hidden && entry.depth() > 0 && name.starts_with('.') {
            continue;
        }

        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    Ok(files)
}

/// Compiled glob patterns used to exclude files from scanning.
///
/// Patterns are sourced from `.sanitize.toml` `exclude` entries and the
/// `--exclude` CLI flag (CLI patterns are merged in after project config).
/// Each pattern is matched against:
///   1. The path **relative to the project config directory** (or CWD when no
///      config file was found).
///   2. The **bare filename** alone — so `*.min.js` skips minified files
///      anywhere in the tree without needing a `**/*.min.js` prefix.
///
/// A trailing `/` in a pattern means "match any path that starts with this
/// prefix" — it prunes the whole subtree.
struct IgnoreList {
    /// Compiled patterns together with a flag for trailing-slash (subtree) semantics.
    patterns: Vec<(glob::Pattern, bool)>,
}

impl IgnoreList {
    /// Build from a list of raw glob strings.  Invalid patterns emit a warning
    /// and are skipped rather than aborting.
    fn new(raw: &[String]) -> Self {
        let mut patterns = Vec::with_capacity(raw.len());
        for p in raw {
            let is_subtree = p.ends_with('/');
            // Strip the trailing slash before compiling — glob::Pattern doesn't
            // want it and we record the flag separately.
            let trimmed = p.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            match glob::Pattern::new(trimmed) {
                Ok(compiled) => patterns.push((compiled, is_subtree)),
                Err(e) => eprintln!("warning: invalid exclude pattern '{p}': {e} — skipping"),
            }
        }
        Self { patterns }
    }

    /// Returns `true` if `path` should be excluded.
    ///
    /// `root` is the directory the pattern is anchored to (the `.sanitize.toml`
    /// location, or CWD when there is no project config).
    fn is_excluded(&self, path: &Path, root: &Path) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        let opts = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: false,
        };
        // Relative path from the anchor root.  Fall back to the full path when
        // strip_prefix fails (e.g. the file is outside the root).
        // Canonicalize both sides so relative paths (e.g. `./tests/…`) and
        // symlink-resolved absolute paths match correctly.  Fall back to the
        // raw path when canonicalization fails (e.g. the file doesn't exist yet).
        let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let rel = canon_path.strip_prefix(&canon_root).unwrap_or(&canon_path);
        let rel_str = rel.to_string_lossy();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();

        for (pat, is_subtree) in &self.patterns {
            if *is_subtree {
                // Subtree match: the relative path must start with the pattern
                // string as a prefix (e.g. pattern "tests/fixtures" matches
                // "tests/fixtures/a.yaml").
                let prefix = pat.as_str();
                if rel_str.starts_with(prefix)
                    && (rel_str.len() == prefix.len()
                        || rel_str.as_bytes().get(prefix.len()) == Some(&b'/'))
                {
                    return true;
                }
            } else {
                // Normal glob: try relative path first, then bare filename.
                if pat.matches_with(&rel_str, opts) {
                    return true;
                }
                // If the pattern has no path separator, also match on filename alone.
                if !pat.as_str().contains('/') && pat.matches_with(&filename, opts) {
                    return true;
                }
            }
        }
        false
    }
}

/// Compiled glob patterns used to restrict directory walks to matching files.
///
/// An empty `IncludeList` is a no-op — all files are included.  When patterns
/// are present a file must match at least one to pass.  Matching uses the same
/// rules as `IgnoreList`: relative path first, then bare filename for patterns
/// without a path separator.  A trailing `/` includes the entire subtree.
///
/// When a file matches both an `IncludeList` pattern and an `IgnoreList`
/// pattern, exclusion wins.
struct IncludeList {
    patterns: Vec<(glob::Pattern, bool)>,
}

impl IncludeList {
    fn new(raw: &[String]) -> Self {
        let mut patterns = Vec::with_capacity(raw.len());
        for p in raw {
            let is_subtree = p.ends_with('/');
            let trimmed = p.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            match glob::Pattern::new(trimmed) {
                Ok(compiled) => patterns.push((compiled, is_subtree)),
                Err(e) => eprintln!("warning: invalid include-path pattern '{p}': {e} — skipping"),
            }
        }
        Self { patterns }
    }

    /// Returns `true` if `path` should be included (or no patterns are set).
    fn is_included(&self, path: &Path, root: &Path) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        let opts = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: false,
        };
        let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let rel = canon_path.strip_prefix(&canon_root).unwrap_or(&canon_path);
        let rel_str = rel.to_string_lossy();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();

        for (pat, is_subtree) in &self.patterns {
            if *is_subtree {
                let prefix = pat.as_str();
                if rel_str.starts_with(prefix)
                    && (rel_str.len() == prefix.len()
                        || rel_str.as_bytes().get(prefix.len()) == Some(&b'/'))
                {
                    return true;
                }
            } else {
                if pat.matches_with(&rel_str, opts) {
                    return true;
                }
                if !pat.as_str().contains('/') && pat.matches_with(&filename, opts) {
                    return true;
                }
            }
        }
        false
    }
}

fn plan_input_targets(cli: &Cli) -> Result<Vec<InputTarget>, String> {
    let explicit_stdin_count = cli.input.iter().filter(|p| p.as_os_str() == "-").count();

    if explicit_stdin_count > 1 {
        return Err("stdin marker '-' can be specified at most once".into());
    }

    let has_piped_stdin = explicit_stdin_count == 0 && stdin_is_pipe();

    // No file inputs — stdin only.
    if cli.input.is_empty() {
        return Ok(vec![InputTarget::Stdin {
            output: cli.output.clone(),
        }]);
    }

    // ── build ignore / include lists ──────────────────────────────────────────
    // Ignore patterns come from two sources, merged in precedence order:
    //   1. `.sanitize.toml` `exclude` field (project config)
    //   2. `--exclude-path` CLI flags (extend, not replace)
    // Include patterns come from `--include-path` CLI flags only.
    // The anchor root for relative-path matching is the `.sanitize.toml`
    // directory when a project config was found, otherwise CWD.
    let (ignore_patterns, ignore_root): (Vec<String>, PathBuf) = {
        let mut patterns: Vec<String> = Vec::new();
        let root = if let Some(ref cfg_path) = find_project_config() {
            let (pc, cfg_dir) = load_project_config(cfg_path);
            patterns.extend(pc.exclude);
            cfg_dir
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        };
        patterns.extend(cli.exclude_path.iter().cloned());
        (patterns, root)
    };
    let ignore_list = IgnoreList::new(&ignore_patterns);
    let include_list = IncludeList::new(&cli.include_path);

    // ── expand directory inputs ───────────────────────────────────────────────
    // Each CLI argument is either a `-` (stdin), a plain file, or a directory.
    // Directories are walked recursively and each discovered file is added with
    // its `dir_root` recorded so we can mirror the tree into the output dir.
    let mut expanded: Vec<ExpandedInput> = Vec::new();

    for input in &cli.input {
        if input.as_os_str() == "-" {
            continue; // handled separately below
        }
        if input.is_dir() {
            let files = walk_dir(input, cli.hidden)?;
            if files.is_empty() {
                warn!(dir = %input.display(), "directory contains no processable files");
                continue;
            }
            let before = files.len();
            // Use the input directory as the anchor for --exclude-path /
            // --include-path so that patterns like "skip/" are matched against
            // paths relative to the walked root, not the project config dir.
            let walk_root = input.canonicalize().unwrap_or_else(|_| input.to_path_buf());
            let files: Vec<PathBuf> = files
                .into_iter()
                .filter(|f| {
                    if ignore_list.is_excluded(f, &walk_root) {
                        info!(path = %f.display(), "excluded by ignore pattern");
                        return false;
                    }
                    if !include_list.is_included(f, &walk_root) {
                        info!(path = %f.display(), "excluded by include-path filter");
                        return false;
                    }
                    true
                })
                .collect();
            if files.is_empty() {
                warn!(dir = %input.display(), excluded = before, "all files in directory excluded by path filters");
                continue;
            }
            let excluded = before - files.len();
            info!(dir = %input.display(), files = files.len(), excluded, "expanding directory input");
            if cli.effective_log_format() != "json" {
                if excluded > 0 {
                    eprintln!(
                        "  {} files in {} ({} excluded)",
                        files.len(),
                        input.display(),
                        excluded
                    );
                } else {
                    eprintln!("  {} files in {}", files.len(), input.display());
                }
            }
            for f in files {
                expanded.push(ExpandedInput {
                    path: f,
                    dir_root: Some(input.clone()),
                });
            }
        } else {
            // Explicit file path: warn when excluded rather than silently drop,
            // since the user named it directly.
            if ignore_list.is_excluded(input, &ignore_root) {
                warn!(path = %input.display(), "explicitly specified file matches an exclude pattern — skipping");
                continue;
            }
            expanded.push(ExpandedInput {
                path: input.clone(),
                dir_root: None,
            });
        }
    }

    let multi_input = expanded.len() + explicit_stdin_count + (has_piped_stdin as usize) > 1;
    let mut used_outputs = HashSet::new();
    let mut units = Vec::new();

    // ── resolve output directory when multi_input ────────────────────────────
    let output_dir: Option<PathBuf> = if multi_input {
        if let Some(path) = &cli.output {
            if path.exists() && !path.is_dir() {
                return Err(format!(
                    "--output must be a directory when multiple inputs are provided: {}",
                    path.display()
                ));
            }
            if !path.exists() {
                fs::create_dir_all(path).map_err(|e| {
                    format!("failed to create output directory {}: {e}", path.display())
                })?;
            }
            Some(path.clone())
        } else {
            None
        }
    } else {
        None
    };

    // ── build InputTarget for each expanded file ─────────────────────────────
    for ei in expanded {
        let planned_out = if let Some(ref root) = ei.dir_root {
            // File came from a directory walk. Mirror the structure relative to
            // the directory root that was passed on the CLI.
            let rel = ei.path.strip_prefix(root).unwrap_or(&ei.path);
            if let Some(out_root) = &cli.output {
                // --output <dir>: out_root/relative/path/file (exact name, no suffix)
                let dest = out_root.join(rel);
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
                }
                uniquify_output_path(dest, &mut used_outputs)
            } else {
                // No --output: mirror the tree into a peer directory named
                // <dirname>-sanitized/ next to the input directory.
                // Falls back to a "sanitized/" peer when the directory has no
                // usable name (e.g. the input was `.` or `/`).
                let dir_name = root
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("sanitized");
                let peer_dir = root
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(format!("{dir_name}-sanitized"));
                let dest = peer_dir.join(rel);
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
                }
                uniquify_output_path(dest, &mut used_outputs)
            }
        } else if multi_input {
            // Explicit file in a multi-file invocation.
            let default_out = match ArchiveFormat::from_path(&ei.path.to_string_lossy()) {
                Some(fmt) => default_archive_output(&ei.path, fmt),
                None => default_plain_output(&ei.path),
            };
            let out_name = default_out
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("output")
                .to_string();
            if let Some(dir) = &output_dir {
                uniquify_output_path(dir.join(out_name), &mut used_outputs)
            } else {
                uniquify_output_path(default_out, &mut used_outputs)
            }
        } else {
            // Single explicit file.
            let default_out = match ArchiveFormat::from_path(&ei.path.to_string_lossy()) {
                Some(fmt) => default_archive_output(&ei.path, fmt),
                None => default_plain_output(&ei.path),
            };
            if let Some(out) = &cli.output {
                // If the caller passed an existing directory, place the output
                // file inside it (same behaviour as multi-file mode). This lets
                // callers like the MCP server always pass a directory without
                // needing to predict the output filename.
                if out.is_dir() {
                    let out_name = default_out
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("output")
                        .to_string();
                    uniquify_output_path(out.join(out_name), &mut used_outputs)
                } else {
                    out.clone()
                }
            } else {
                default_out
            }
        };

        units.push(InputTarget::File {
            input: ei.path,
            output: planned_out,
        });
    }

    // ── stdin targets ─────────────────────────────────────────────────────────
    if explicit_stdin_count > 0 || has_piped_stdin {
        let stdin_out = if multi_input {
            Some(
                output_dir
                    .as_ref()
                    .map(|d| d.join("input-sanitized.txt"))
                    .unwrap_or_else(|| PathBuf::from("input-sanitized.txt")),
            )
        } else {
            cli.output.clone()
        };
        units.push(InputTarget::Stdin { output: stdin_out });
    }

    Ok(units)
}

// ---------------------------------------------------------------------------
// Archive filter pre-parser
// ---------------------------------------------------------------------------

/// Pre-parse `--only` / `--exclude` flags that are interleaved with archive
/// paths in the raw argument list, **before** clap sees them.
///
/// Syntax:
/// ```text
/// archive.zip --only PATTERN... --exclude PATTERN... other.tar.gz --only PATTERN...
/// ```
///
/// Rules:
/// - `--only` / `--exclude` must appear **after** an archive path.  Using
///   them before any archive is a hard error.
/// - A non-flag argument appearing while collecting patterns is treated as
///   a new archive path if it matches a known archive extension **and** the
///   file exists on disk.  Otherwise it is a hard error ("non-archive path
///   cannot appear between filter flags").
/// - The `--only` / `--exclude` tokens and their value arguments are
///   **stripped** from the returned cleaned argument list; everything else
///   passes through to clap unchanged.
/// - Glob patterns are validated eagerly; invalid syntax is reported before
///   any archive is opened.
///
/// Returns `(filter_map, cleaned_args)` where `filter_map` maps each
/// archive path (as it appeared on the command line) to its
/// `(only_patterns, exclude_patterns)` pair.
#[allow(clippy::type_complexity)]
fn parse_archive_filters(
    args: &[OsString],
) -> Result<(HashMap<PathBuf, (Vec<String>, Vec<String>)>, Vec<OsString>), String> {
    #[derive(PartialEq)]
    enum State {
        Global,
        AfterArchive,
        CollectingOnly,
        CollectingExclude,
    }

    let mut state = State::Global;
    let mut current_archive: Option<PathBuf> = None;
    let mut filter_map: HashMap<PathBuf, (Vec<String>, Vec<String>)> = HashMap::new();
    let mut cleaned: Vec<OsString> = Vec::with_capacity(args.len());

    // Validate a glob pattern (patterns ending with '/' are directory
    // prefixes and require no glob validation).
    let validate_pattern = |p: &str| -> Result<(), String> {
        if !p.ends_with('/') {
            glob::Pattern::new(p).map_err(|e| format!("invalid glob pattern '{p}': {e}"))?;
        }
        Ok(())
    };

    for arg in args {
        let s = arg.to_string_lossy();

        match s.as_ref() {
            "--only" => {
                if state == State::Global {
                    return Err(
                        "--only must follow an archive path (e.g. archive.zip --only PATTERN)"
                            .into(),
                    );
                }
                state = State::CollectingOnly;
                // strip from cleaned args
            }
            "--exclude" => {
                if state == State::Global {
                    return Err(
                        "--exclude must follow an archive path (e.g. archive.zip --exclude PATTERN)"
                            .into(),
                    );
                }
                state = State::CollectingExclude;
                // strip from cleaned args
            }
            _ if (state == State::CollectingOnly || state == State::CollectingExclude)
                && !s.starts_with('-') =>
            {
                let candidate = PathBuf::from(s.as_ref());
                if ArchiveFormat::from_path(&s).is_some() && candidate.is_file() {
                    // Transition: start a new archive group.
                    filter_map
                        .entry(candidate.clone())
                        .or_insert_with(|| (Vec::new(), Vec::new()));
                    current_archive = Some(candidate.clone());
                    state = State::AfterArchive;
                    cleaned.push(arg.clone());
                } else if candidate.is_file() {
                    // Plain file (not an archive) between filter flags — hard error.
                    return Err(format!(
                        "non-archive path '{}' cannot appear between filter flags; \
                         move it before or after the archive+filter group",
                        candidate.display()
                    ));
                } else {
                    // Treat as a pattern value (e.g. "*.json", "config/", "/logs/**").
                    // Patterns that look like paths but don't exist on disk are valid.
                    validate_pattern(&s)?;
                    let key = current_archive.as_ref().unwrap();
                    let entry = filter_map.entry(key.clone()).or_default();
                    if state == State::CollectingOnly {
                        entry.0.push(s.into_owned());
                    } else {
                        entry.1.push(s.into_owned());
                    }
                    // pattern values are NOT passed to cleaned args
                }
            }
            _ if (state == State::CollectingOnly || state == State::CollectingExclude)
                && s.starts_with('-') =>
            {
                // Another flag ends pattern collection.
                state = State::AfterArchive;
                cleaned.push(arg.clone());
            }
            _ => {
                // Regular argument in Global or AfterArchive state.
                let candidate = PathBuf::from(s.as_ref());
                if ArchiveFormat::from_path(&s).is_some() {
                    filter_map
                        .entry(candidate.clone())
                        .or_insert_with(|| (Vec::new(), Vec::new()));
                    current_archive = Some(candidate.clone());
                    state = State::AfterArchive;
                }
                cleaned.push(arg.clone());
            }
        }
    }

    Ok((filter_map, cleaned))
}

fn validate_args(cli: &Cli) -> Result<(), String> {
    if has_stdin_input(cli) && io::stdin().is_terminal() {
        return Err("stdin was requested but stdin is a terminal.\n\
             Provide file path(s) only, or pipe data into sanitize when using '-'.\n\n\
             Usage: sanitize [OPTIONS] [INPUT]...\n       \
             command | sanitize -s secrets.yaml"
            .into());
    }

    let explicit_stdin_count = cli.input.iter().filter(|p| p.as_os_str() == "-").count();
    if explicit_stdin_count > 1 {
        return Err("stdin marker '-' can be specified at most once".into());
    }

    for input in file_inputs(cli) {
        if !input.exists() {
            return Err(format!("input path not found: {}", input.display()));
        }
        if !input.is_file() && !input.is_dir() {
            return Err(format!(
                "input path is not a file or directory: {}",
                input.display()
            ));
        }
    }

    if let Some(ref fmt) = cli.format {
        if !VALID_FORMATS.contains(&fmt.as_str()) {
            return Err(format!(
                "invalid --format '{}': must be one of: {}",
                fmt,
                VALID_FORMATS.join(", ")
            ));
        }
    }

    if let Some(ref sf) = cli.secrets_file {
        if !sf.exists() && !cli.deterministic {
            return Err(format!("secrets file not found: {}", sf.display()));
        }
        if sf.exists() && !sf.is_file() {
            return Err(format!(
                "secrets path is not a regular file: {}",
                sf.display()
            ));
        }
    }

    build_scan_config(cli.chunk_size)?;

    if let Some(t) = cli.threads {
        if t == 0 {
            return Err("--threads must be ≥ 1".into());
        }
    }

    if cli.max_archive_depth > 10 {
        return Err(format!(
            "--max-archive-depth {} exceeds maximum of 10 (each nesting level \
             may buffer up to 256 MiB of archive data)",
            cli.max_archive_depth
        ));
    }
    if cli.max_archive_depth == 0 {
        return Err("--max-archive-depth must be ≥ 1".into());
    }

    if !matches!(cli.effective_log_format(), "human" | "json") {
        return Err(format!(
            "invalid --log-format '{}': must be 'human' or 'json'",
            cli.effective_log_format()
        ));
    }

    if !matches!(
        cli.effective_log_level(),
        "off" | "error" | "warn" | "info" | "debug" | "trace"
    ) {
        return Err(format!(
            "invalid --log-level '{}': must be one of off, error, warn, info, debug, trace",
            cli.effective_log_level()
        ));
    }

    if cli.progress_interval_ms == 0 {
        return Err("--progress-interval-ms must be greater than 0".into());
    }

    // Password inputs require --encrypted-secrets; reject early to avoid
    // confusing "failed to load secrets" errors later.
    let has_password_source = cli.password
        || cli.password_file.is_some()
        || std::env::var("SANITIZE_PASSWORD").is_ok_and(|v| !v.is_empty());
    if has_password_source && !cli.encrypted_secrets && !cli.deterministic {
        return Err(
            "password input (--password, --password-file, or SANITIZE_PASSWORD) \
             was provided but --encrypted-secrets is not set.\n\
             Add --encrypted-secrets to decrypt the secrets file, or remove \
             password inputs to use a plaintext file."
                .into(),
        );
    }

    for app in &cli.app {
        let is_builtin = BUILTIN_APPS.iter().any(|a| a.name == app.as_str());
        let is_user = user_apps_dir()
            .map(|d| d.join(app).is_dir())
            .unwrap_or(false);
        if !is_builtin && !is_user {
            return Err(format!(
                "unknown --app '{}'. Built-in apps: {}. \
                 Add a custom app at $SANITIZE_APPS_DIR/{} (secrets.yaml / profile.yaml).",
                app,
                builtin_app_names().join(", "),
                app,
            ));
        }
    }

    // --llm validations.
    if let Some(ref template) = cli.llm {
        // --dry-run produces no output, so the prompt content would be empty.
        if cli.dry_run {
            return Err(
                "--llm and --dry-run cannot be combined: dry-run does not produce \
                 sanitized output, so the generated prompt would have no content."
                    .into(),
            );
        }

        // Validate custom template path early so the error surfaces before processing.
        let known = matches!(
            template.as_str(),
            "troubleshoot" | "review-config" | "review-security"
        );
        if !known {
            let path = Path::new(template);
            if !path.exists() {
                return Err(format!(
                    "--llm template '{}' is not a known template name and the path \
                     does not exist.\n\
                     Built-in templates: troubleshoot, review-config, review-security\n\
                     To use a custom template, provide a path to an existing file.",
                    template
                ));
            }
            if !path.is_file() {
                return Err(format!(
                    "--llm template '{}' exists but is not a regular file.",
                    template
                ));
            }
        }
    }

    Ok(())
}

/// Resolve and cap thread count to available parallelism.
fn resolve_thread_count(requested: Option<usize>) -> usize {
    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    match requested {
        Some(n) => n.min(available),
        None => available,
    }
}

/// CLI-only state captured before settings.yaml / .sanitize.toml are merged in.
/// Used to annotate the run header with `[config]` for values that came from a
/// config file rather than the command line.
struct CliConfigSnapshot {
    had_secrets: bool,
    had_profile: bool,
    apps: Vec<String>,
    allow: Vec<String>,
    strict: bool,
    fail_on_match: bool,
    no_structured_handoff: bool,
    deterministic: bool,
    dry_run: bool,
}

impl CliConfigSnapshot {
    fn capture(cli: &Cli) -> Self {
        Self {
            had_secrets: cli.secrets_file.is_some(),
            had_profile: cli.profile.is_some(),
            apps: cli.app.clone(),
            allow: cli.allow.clone(),
            strict: cli.strict,
            fail_on_match: cli.fail_on_match,
            no_structured_handoff: cli.no_structured_handoff,
            deterministic: cli.deterministic,
            dry_run: cli.dry_run,
        }
    }
}

/// Print a one-time run configuration summary to stderr so the user can see
/// exactly what secrets file, profile, and apps are active — and whether any
/// of them came from a config file rather than the command line.
fn print_run_header(cli: &Cli, snap: &CliConfigSnapshot, json_logs: bool) {
    if json_logs {
        info!(
            secrets = cli.secrets_file.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            profile = cli.profile.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            apps    = %cli.app.join(","),
            "run config"
        );
        return;
    }

    // Secrets file
    match &cli.secrets_file {
        Some(p) => {
            let ann = if !snap.had_secrets { "  [config]" } else { "" };
            eprintln!("  secrets:  {}{}", p.display(), ann);
        }
        None => {
            eprintln!("  secrets:  (none — built-in patterns only)");
        }
    }

    // Profile (only shown when active)
    if let Some(p) = &cli.profile {
        let ann = if !snap.had_profile { "  [config]" } else { "" };
        eprintln!("  profile:  {}{}", p.display(), ann);
    }

    // App bundles (only shown when any are active)
    if !cli.app.is_empty() {
        let parts: Vec<String> = cli
            .app
            .iter()
            .map(|a| {
                if snap.apps.contains(a) {
                    a.clone()
                } else {
                    format!("{a}  [config]")
                }
            })
            .collect();
        eprintln!("  apps:     {}", parts.join(", "));
    }

    // Allow-list (only shown when any entries are active)
    if !cli.allow.is_empty() {
        let parts: Vec<String> = cli
            .allow
            .iter()
            .map(|v| {
                if snap.allow.contains(v) {
                    format!("{v:?}")
                } else {
                    format!("{v:?}  [config]")
                }
            })
            .collect();
        eprintln!("  allow:    {}", parts.join(", "));
    }

    // Non-default boolean flags
    let mut flags: Vec<String> = Vec::new();
    if cli.strict {
        flags.push(if !snap.strict {
            "--strict  [config]".into()
        } else {
            "--strict".into()
        });
    }
    if cli.fail_on_match {
        flags.push(if !snap.fail_on_match {
            "--fail-on-match  [config]".into()
        } else {
            "--fail-on-match".into()
        });
    }
    if cli.no_structured_handoff {
        flags.push(if !snap.no_structured_handoff {
            "--no-structured-handoff  [config]".into()
        } else {
            "--no-structured-handoff".into()
        });
    }
    if cli.deterministic {
        flags.push(if !snap.deterministic {
            "--deterministic  [config]".into()
        } else {
            "--deterministic".into()
        });
    }
    if cli.dry_run {
        flags.push(if !snap.dry_run {
            "--dry-run  [config]".into()
        } else {
            "--dry-run".into()
        });
    }
    if !flags.is_empty() {
        eprintln!("  flags:    {}", flags.join(", "));
    }
    eprintln!();
}

// ---------------------------------------------------------------------------
// Processing helpers
// ---------------------------------------------------------------------------

/// Merge entropy per-label counts into an existing `ScanStats`.
fn merge_entropy_counts(stats: &mut ScanStats, label_counts: HashMap<String, u64>) {
    let total: u64 = label_counts.values().sum();
    stats.matches_found += total;
    stats.replacements_applied += total;
    for (label, count) in label_counts {
        *stats.pattern_counts.entry(label).or_insert(0) += count;
    }
}

/// Merge per-buffer entropy histogram data into the shared accumulator.
fn accumulate_entropy_histogram(
    acc: &Arc<Mutex<Vec<EntropyBuckets>>>,
    buf: &[u8],
    configs: &[EntropyConfig],
) {
    let local = entropy_histogram_bytes(buf, configs);
    let mut guard = acc.lock().expect("entropy histogram lock");
    if guard.is_empty() {
        *guard = local;
    } else {
        for (dst, src) in guard.iter_mut().zip(local.iter()) {
            dst.merge(src);
        }
    }
}

/// Print the entropy calibration histogram to stderr.
///
/// Shows candidate token counts by entropy level so users can tune
/// `--entropy-threshold` before committing to a full sanitization run.
/// No token values are printed.
fn print_entropy_histogram(buckets: &[EntropyBuckets]) {
    for b in buckets {
        let label_suffix = if b.label != "high_entropy_token" {
            format!(" [{}]", b.label)
        } else {
            String::new()
        };
        if b.total_candidates == 0 {
            eprintln!(
                "Entropy calibration{} — {} ({}–{} chars): no candidates found",
                label_suffix, b.charset_desc, b.min_length, b.max_length
            );
            continue;
        }
        eprintln!(
            "Entropy calibration{} — {} ({}–{} chars):",
            label_suffix, b.charset_desc, b.min_length, b.max_length
        );
        for (i, &thresh) in HISTOGRAM_THRESHOLDS.iter().enumerate() {
            let count = b.counts[i];
            let marker = if (thresh - b.configured_threshold).abs() < 1e-9 {
                "  ← threshold"
            } else {
                ""
            };
            eprintln!("  ≥{:.1} bits  {:>6}{}", thresh, count, marker);
        }
        if !HISTOGRAM_THRESHOLDS
            .iter()
            .any(|&t| (t - b.configured_threshold).abs() < 1e-9)
        {
            eprintln!(
                "  (configured threshold {:.2} bits falls between standard levels above)",
                b.configured_threshold
            );
        }
        eprintln!("  {} candidates examined", b.total_candidates);
    }
}

/// Build a scan progress callback that forwards updates to the shared reporter.
///
/// Eliminates the boilerplate of cloning the `SharedProgressReporter` and
/// constructing an identical `move` closure at every `scan_reader_with_progress`
/// call site.
fn make_scan_callback(
    progress: Option<SharedProgressReporter>,
    label: impl Into<String>,
) -> impl FnMut(&sanitize_engine::ScanProgress) {
    let label = label.into();
    move |scan_progress| {
        if let Some(reporter) = &progress {
            reporter
                .lock()
                .expect("progress reporter lock")
                .update_scan(&label, scan_progress);
        }
    }
}

/// Scan a reader while collecting per-match line numbers up to `max_locations`.
///
/// Returns `(stats, locations, truncated)`. When `max_locations` is 0 the
/// location Vec is always empty and `truncated` is always false — use this
/// to disable line-number tracking with zero overhead from the collection
/// side (the scanner still tracks newlines internally; set
/// `--max-match-locations 0` when that overhead is unacceptable).
fn scan_with_locations<R, W>(
    scanner: &StreamScanner,
    reader: R,
    writer: W,
    total_bytes: Option<u64>,
    progress_cb: impl FnMut(&sanitize_engine::ScanProgress),
    max_locations: usize,
) -> Result<
    (
        ScanStats,
        Vec<sanitize_engine::scanner::MatchLocation>,
        bool,
    ),
    String,
>
where
    R: std::io::Read,
    W: std::io::Write,
{
    let mut locations: Vec<sanitize_engine::scanner::MatchLocation> = Vec::new();
    let mut truncated = false;
    let stats = scanner
        .scan_reader_with_callbacks(reader, writer, total_bytes, progress_cb, |loc| {
            if max_locations == 0 {
                return;
            }
            if locations.len() < max_locations {
                locations.push(loc);
            } else {
                truncated = true;
            }
        })
        .map_err(|e| format!("scanner error: {e}"))?;
    Ok((stats, locations, truncated))
}

// ---------------------------------------------------------------------------
// Processing
// ---------------------------------------------------------------------------

/// Process input from stdin. Returns `true` if matches were found.
#[allow(clippy::too_many_arguments)]
fn process_stdin(
    cli: &Cli,
    output_path: Option<&Path>,
    scanner: &Arc<StreamScanner>,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    profiles: &[sanitize_engine::processor::FileTypeProfile],
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
    llm_collector: Option<&LlmCollector>,
    entropy_configs: &Arc<Vec<EntropyConfig>>,
    entropy_histogram_acc: Option<&Arc<Mutex<Vec<EntropyBuckets>>>>,
) -> Result<bool, String> {
    // Determine whether structured processing should be attempted.
    // Skipped entirely when --force-text is set.
    let structured_ext = if cli.force_text {
        None
    } else {
        cli.format.as_deref().and_then(format_to_ext)
    };

    let mut had_matches = false;

    if let Some(ext) = structured_ext {
        // Buffer stdin for structured processing (bounded by max_structured_size).
        let mut input_bytes = Vec::new();
        let limit = cli.max_structured_size;
        io::stdin()
            .take(limit + 1)
            .read_to_end(&mut input_bytes)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        if input_bytes.len() as u64 > limit {
            warn!(
                max = limit,
                "stdin exceeds --max-structured-size, falling back to streaming scanner"
            );
            // Too large — fall through to streaming below.
            // Re-combine what we read with the rest of stdin.
            let cursor = Cursor::new(input_bytes);
            let chained = cursor.chain(io::stdin().lock());
            let reader = BufReader::new(chained);
            return process_stdin_streaming(
                reader,
                output_path,
                cli,
                scanner,
                store,
                report_builder,
                progress,
                llm_collector,
                entropy_configs,
                cli.max_match_locations,
                entropy_histogram_acc,
            );
        }

        let store_len_before = store.len();
        let store_snapshot = store.snapshot();
        let label = format!("Processing structured stdin ({ext})");
        return with_progress_scope(progress, &label, |_| {
            let structured_result = try_structured_processing(
                &input_bytes,
                &format!("stdin.{ext}"),
                registry,
                store,
                profiles,
            );

            match structured_result {
                Some(Ok(_structured_bytes)) => {
                    // Format-preserving double-pass (mirrors file-mode behaviour):
                    //   1. Structured pass populated the store — diff it against the
                    //      snapshot to find the literals this content contributed.
                    //   2. Build a scanner from base patterns (KV patterns excluded so
                    //      JSON/YAML key names are never matched) plus those literals.
                    //   3. Scan the *original* bytes so indentation, comments, and key
                    //      order are preserved and key names cannot be mangled.
                    let per_content_scanner =
                        build_format_preserving_scanner(scanner, store, store_snapshot)
                            .map_err(|e| format!("failed to build content scanner: {e}"))?;
                    let (mut output_bytes, scan_stats) =
                        scanner_fallback(&per_content_scanner, &input_bytes)?;
                    let (ent_out, ent_lc) =
                        entropy_scan_bytes(&output_bytes, entropy_configs, store);
                    output_bytes = ent_out;
                    let ent_total: u64 = ent_lc.values().sum();
                    let method = format!("structured+scan:{ext}");
                    let structured_reps = store.len().saturating_sub(store_len_before) as u64;
                    let total_replacements =
                        structured_reps + scan_stats.replacements_applied + ent_total;
                    if total_replacements > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = report_builder {
                        let mut pattern_counts = scan_stats.pattern_counts.clone();
                        for (label, count) in &ent_lc {
                            *pattern_counts.entry(label.clone()).or_insert(0) += count;
                        }
                        let stats = ScanStats {
                            matches_found: total_replacements,
                            replacements_applied: total_replacements,
                            bytes_processed: input_bytes.len() as u64,
                            bytes_output: output_bytes.len() as u64,
                            pattern_counts,
                        };
                        rb.record_file(FileReport::from_scan_stats(
                            "<stdin>".to_string(),
                            &stats,
                            method,
                        ));
                    }
                    maybe_extract_context(&output_bytes, "<stdin>", cli, report_builder);
                    if !cli.dry_run {
                        write_or_collect(&output_bytes, "<stdin>", output_path, llm_collector)?;
                    }
                    return Ok(had_matches);
                }
                Some(Err(e)) => {
                    if cli.strict {
                        return Err(format!("structured processing failed: {e}"));
                    }
                    warn!(error = %e, "structured processing failed, falling back to scanner");
                }
                None => {}
            }

            let (mut output_bytes, mut stats) = scanner_fallback(scanner, &input_bytes)?;
            let (ent_out, ent_lc) = entropy_scan_bytes(&output_bytes, entropy_configs, store);
            output_bytes = ent_out;
            merge_entropy_counts(&mut stats, ent_lc);
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    "<stdin>".to_string(),
                    &stats,
                    "scanner",
                ));
            }
            maybe_extract_context(&output_bytes, "<stdin>", cli, report_builder);
            if !cli.dry_run {
                write_or_collect(&output_bytes, "<stdin>", output_path, llm_collector)?;
            }
            Ok(had_matches)
        });
    }

    // Plain text streaming from stdin.
    let reader = BufReader::new(io::stdin().lock());
    process_stdin_streaming(
        reader,
        output_path,
        cli,
        scanner,
        store,
        report_builder,
        progress,
        llm_collector,
        entropy_configs,
        cli.max_match_locations,
        entropy_histogram_acc,
    )
}

/// Stream stdin through the scanner, writing to output (stdout or file).
#[allow(clippy::too_many_arguments)]
fn process_stdin_streaming<R: io::Read>(
    reader: BufReader<R>,
    output_path: Option<&Path>,
    cli: &Cli,
    scanner: &Arc<StreamScanner>,
    store: &Arc<MappingStore>,
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
    llm_collector: Option<&LlmCollector>,
    entropy_configs: &Arc<Vec<EntropyConfig>>,
    max_match_locations: usize,
    entropy_histogram_acc: Option<&Arc<Mutex<Vec<EntropyBuckets>>>>,
) -> Result<bool, String> {
    let label = if cli.dry_run {
        "Scanning stdin (dry-run)"
    } else {
        "Scanning stdin"
    };
    let entropy_active = !entropy_configs.is_empty();

    with_progress_scope(progress, label, |progress| {
        let mut had_matches = false;

        if cli.dry_run {
            // For dry-run with entropy, buffer so we can count entropy matches.
            // Dry-run doesn't write output so location tracking has no extra cost.
            let (stats, locs, locs_truncated) = if entropy_active {
                let mut buf: Vec<u8> = Vec::new();
                let (mut s, locs, tr) = scan_with_locations(
                    scanner,
                    reader,
                    &mut buf,
                    None,
                    make_scan_callback(progress.clone(), label),
                    max_match_locations,
                )?;
                let (_ent_out, ent_lc) = entropy_scan_bytes(&buf, entropy_configs, store);
                merge_entropy_counts(&mut s, ent_lc);
                if let Some(acc) = entropy_histogram_acc {
                    accumulate_entropy_histogram(acc, &buf, entropy_configs);
                }
                (s, locs, tr)
            } else {
                let (s, locs, tr) = scan_with_locations(
                    scanner,
                    reader,
                    io::sink(),
                    None,
                    make_scan_callback(progress.clone(), label),
                    max_match_locations,
                )?;
                (s, locs, tr)
            };
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(
                    FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                        .with_match_locations(locs, locs_truncated),
                );
            }
            info!(
                matches = stats.matches_found,
                replacements = stats.replacements_applied,
                "dry-run complete"
            );
            return Ok(had_matches);
        }

        // Buffer when extract-context, llm, or entropy are active; streaming otherwise.
        // Note: for direct-to-stdout streaming (no output path, no buffering reason),
        // entropy is skipped because stdin is potentially unbounded.
        let needs_buffer = cli.extract_context || llm_collector.is_some() || entropy_active;

        if let Some(out_path) = output_path {
            if needs_buffer {
                let mut buf: Vec<u8> = Vec::new();
                let (mut stats, locs, locs_truncated) = scan_with_locations(
                    scanner,
                    reader,
                    &mut buf,
                    None,
                    make_scan_callback(progress.clone(), label),
                    max_match_locations,
                )?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                if entropy_active {
                    let (ent_out, ent_lc) = entropy_scan_bytes(&buf, entropy_configs, store);
                    buf = ent_out;
                    merge_entropy_counts(&mut stats, ent_lc);
                }
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context(&buf, "<stdin>", cli, report_builder);
                if let Some(c) = llm_collector {
                    maybe_collect_for_llm(&buf, "<stdin>", Some(c));
                } else {
                    atomic_write(out_path, &buf)
                        .map_err(|e| format!("failed to write {}: {e}", out_path.display()))?;
                    info!(output = %out_path.display(), "output written");
                }
            } else {
                let mut atomic_writer = AtomicFileWriter::new(out_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;

                let (stats, locs, locs_truncated) = scan_with_locations(
                    scanner,
                    reader,
                    &mut atomic_writer,
                    None,
                    make_scan_callback(progress.clone(), label),
                    max_match_locations,
                )?;

                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }

                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;

                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                            .with_match_locations(locs, locs_truncated),
                    );
                }
            }
        } else if needs_buffer {
            let mut buf: Vec<u8> = Vec::new();
            let (mut stats, locs, locs_truncated) = scan_with_locations(
                scanner,
                reader,
                &mut buf,
                None,
                make_scan_callback(progress.clone(), label),
                max_match_locations,
            )?;
            if entropy_active {
                let (ent_out, ent_lc) = entropy_scan_bytes(&buf, entropy_configs, store);
                buf = ent_out;
                merge_entropy_counts(&mut stats, ent_lc);
            }
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(
                    FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                        .with_match_locations(locs, locs_truncated),
                );
            }
            maybe_extract_context(&buf, "<stdin>", cli, report_builder);
            if let Some(c) = llm_collector {
                maybe_collect_for_llm(&buf, "<stdin>", Some(c));
            } else {
                if let Some(p) = progress {
                    p.lock().expect("progress reporter lock").clear_live_line();
                }
                let stdout = io::stdout();
                stdout
                    .lock()
                    .write_all(&buf)
                    .map_err(|e| format!("failed to write to stdout: {e}"))?;
            }
        } else {
            // Direct streaming to stdout — entropy skipped (stdin is unbounded).
            if let Some(ref p) = progress {
                p.lock().expect("progress reporter lock").clear_live_line();
            }
            let stdout = io::stdout();
            let writer = BufWriter::new(stdout.lock());
            let (stats, locs, locs_truncated) = scan_with_locations(
                scanner,
                reader,
                writer,
                None,
                make_scan_callback(progress.clone(), label),
                max_match_locations,
            )?;
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(
                    FileReport::from_scan_stats("<stdin>".to_string(), &stats, "scanner")
                        .with_match_locations(locs, locs_truncated),
                );
            }
        }

        Ok(had_matches)
    })
}

/// Process a plain (non-archive) file. Returns `true` if matches were found.
#[allow(clippy::too_many_arguments)]
fn process_plain_file(
    input: &Path,
    cli: &Cli,
    output_path: Option<&Path>,
    scanner: &Arc<StreamScanner>,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    profiles: &[sanitize_engine::processor::FileTypeProfile],
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
    llm_collector: Option<&LlmCollector>,
    entropy_configs: &Arc<Vec<EntropyConfig>>,
    max_match_locations: usize,
    entropy_histogram_acc: Option<&Arc<Mutex<Vec<EntropyBuckets>>>>,
) -> Result<bool, String> {
    // --- binary detection ---
    let mut sample = [0u8; 512];
    let sample_len = {
        let mut f = fs::File::open(input)
            .map_err(|e| format!("failed to open {}: {e}", input.display()))?;
        io::Read::read(&mut f, &mut sample)
            .map_err(|e| format!("failed to read {}: {e}", input.display()))?
    };
    if !cli.include_binary && looks_binary(&sample[..sample_len]) {
        let file_size = sample_len as u64;
        warn!(
            file = %input.display(),
            bytes = file_size,
            "skipping binary file — use --include-binary to process it"
        );
        return Ok(false);
    }

    let filename = if let Some(ref fmt) = cli.format {
        // --format overrides extension-based detection.
        format_to_ext(fmt)
            .map(|ext| format!("override.{ext}"))
            .unwrap_or_default()
    } else {
        input
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string()
    };

    let structured_ext = matches!(
        filename.rsplit('.').next().unwrap_or(""),
        "json"
            | "jsonl"
            | "ndjson"
            | "yaml"
            | "yml"
            | "xml"
            | "csv"
            | "tsv"
            | "rb"
            | "conf"
            | "cfg"
            | "ini"
            | "env"
            | "properties"
            | "toml"
    ) || {
        // Handle `.env` and `.env.local` style filenames where the file
        // name itself starts with `.env`.
        filename
            .rsplit('/')
            .next()
            .unwrap_or(&filename)
            .starts_with(".env")
    };

    let mut had_matches = false;

    // --- Bounded-memory scanner path for known structured extensions ---
    // Files with structured extensions (json, yaml, toml, etc.) are read
    // fully into memory (up to --max-structured-size) so the scanner can
    // operate on a contiguous buffer.  The streaming scanner path below
    // handles everything else and files that exceed the size limit.
    if structured_ext && !cli.force_text {
        let file_meta =
            fs::metadata(input).map_err(|e| format!("failed to stat {}: {e}", input.display()))?;
        let file_size = file_meta.len();

        // --- Streaming structured path ---
        // If the matching profile names a processor that supports streaming,
        // bypass fs::read entirely: pass 1 opens the file as a BufReader and
        // populates the store, then pass 2 runs the streaming scanner over the
        // file a second time to produce output. Both passes are bounded-memory.
        let maybe_streaming = profiles
            .iter()
            .find(|p| p.matches_filename(&filename))
            .and_then(|p| {
                registry
                    .get(&p.processor)
                    .filter(|proc| proc.supports_streaming())
                    .map(|proc| (p.clone(), Arc::clone(proc)))
            });

        if let Some((streaming_profile, streaming_proc)) = maybe_streaming {
            let store_snapshot = store.snapshot();
            // Pass 1: populate store (output discarded).
            {
                let mut reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                streaming_proc
                    .process_stream(&mut reader, &mut io::sink(), &streaming_profile, store)
                    .map_err(|e| {
                        format!("structured pass 1 failed for {}: {e}", input.display())
                    })?;
            }
            // Build scanner augmented with store-discovered literals.
            let per_file_scanner = Arc::new(
                build_format_preserving_scanner(scanner, store, store_snapshot)
                    .map_err(|e| format!("failed to build per-file scanner: {e}"))?,
            );
            let ext = filename.rsplit('.').next().unwrap_or("unknown");
            let method = format!("structured+scan:{ext}");
            let sz = file_size;

            // Pass 2: streaming scan → output.
            if cli.dry_run {
                let label = format!("Scanning {} (dry-run)", input.display());
                let progress_label = label.clone();
                return with_progress_scope(progress, &label, move |progress| {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                    );
                    let (stats, locs, locs_truncated) = scan_with_locations(
                        &per_file_scanner,
                        reader,
                        io::sink(),
                        Some(sz),
                        make_scan_callback(progress.clone(), &progress_label),
                        max_match_locations,
                    )?;
                    if stats.matches_found > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = report_builder {
                        rb.record_file(
                            FileReport::from_scan_stats(
                                input.display().to_string(),
                                &stats,
                                &method,
                            )
                            .with_match_locations(locs, locs_truncated),
                        );
                    }
                    info!(
                        matches = stats.matches_found,
                        replacements = stats.replacements_applied,
                        "dry-run complete"
                    );
                    Ok(had_matches)
                });
            } else if let Some(out_path) = output_path {
                let label = format!("Scanning {}", input.display());
                let progress_label = label.clone();
                let llm_opt = llm_collector.cloned();
                return with_progress_scope(progress, &label, move |progress| {
                    if llm_opt.is_some() {
                        // Buffer for LLM collection instead of writing to file.
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let mut buf: Vec<u8> = Vec::new();
                        let (stats, locs, locs_truncated) = scan_with_locations(
                            &per_file_scanner,
                            reader,
                            &mut buf,
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                            max_match_locations,
                        )?;
                        if is_interrupted() {
                            return Err("interrupted — partial output discarded".into());
                        }
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = report_builder {
                            rb.record_file(
                                FileReport::from_scan_stats(
                                    input.display().to_string(),
                                    &stats,
                                    &method,
                                )
                                .with_match_locations(locs, locs_truncated),
                            );
                        }
                        maybe_extract_context(
                            &buf,
                            &input.display().to_string(),
                            cli,
                            report_builder,
                        );
                        maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                    } else {
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let mut atomic_writer = AtomicFileWriter::new(out_path)
                            .map_err(|e| format!("failed to create output: {e}"))?;
                        let (stats, locs, locs_truncated) = scan_with_locations(
                            &per_file_scanner,
                            reader,
                            &mut atomic_writer,
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                            max_match_locations,
                        )?;
                        if is_interrupted() {
                            return Err("interrupted — partial output discarded".into());
                        }
                        atomic_writer
                            .finish()
                            .map_err(|e| format!("failed to finalize output: {e}"))?;
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = report_builder {
                            rb.record_file(
                                FileReport::from_scan_stats(
                                    input.display().to_string(),
                                    &stats,
                                    &method,
                                )
                                .with_match_locations(locs, locs_truncated),
                            );
                        }
                        maybe_extract_context_reader(
                            out_path,
                            &input.display().to_string(),
                            cli,
                            report_builder,
                        );
                    }
                    Ok(had_matches)
                });
            } else {
                let label = format!("Scanning {}", input.display());
                let progress_label = label.clone();
                let llm_opt = llm_collector.cloned();
                return with_progress_scope(progress, &label, move |progress| {
                    let needs_buffer = (cli.extract_context || llm_opt.is_some())
                        && sz <= MAX_CONTEXT_BUFFER_BYTES;
                    if needs_buffer {
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let mut buf: Vec<u8> = Vec::new();
                        let (stats, locs, locs_truncated) = scan_with_locations(
                            &per_file_scanner,
                            reader,
                            &mut buf,
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                            max_match_locations,
                        )?;
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = report_builder {
                            rb.record_file(
                                FileReport::from_scan_stats(
                                    input.display().to_string(),
                                    &stats,
                                    &method,
                                )
                                .with_match_locations(locs, locs_truncated),
                            );
                        }
                        maybe_extract_context(
                            &buf,
                            &input.display().to_string(),
                            cli,
                            report_builder,
                        );
                        if llm_opt.is_some() {
                            maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                        } else {
                            let stdout = io::stdout();
                            stdout
                                .lock()
                                .write_all(&buf)
                                .map_err(|e| format!("failed to write to stdout: {e}"))?;
                        }
                    } else {
                        if cli.extract_context {
                            warn!(
                                file = %input.display(),
                                size = sz,
                                max = MAX_CONTEXT_BUFFER_BYTES,
                                "--extract-context: file too large to buffer for stdout; \
                                 use -o/--output to write to a file for context extraction"
                            );
                        }
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let stdout = io::stdout();
                        let writer = BufWriter::new(stdout.lock());
                        let (stats, locs, locs_truncated) = scan_with_locations(
                            &per_file_scanner,
                            reader,
                            writer,
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                            max_match_locations,
                        )?;
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = report_builder {
                            rb.record_file(
                                FileReport::from_scan_stats(
                                    input.display().to_string(),
                                    &stats,
                                    &method,
                                )
                                .with_match_locations(locs, locs_truncated),
                            );
                        }
                    }
                    Ok(had_matches)
                });
            }
        }

        if file_size > cli.max_structured_size {
            warn!(
                file = %input.display(),
                size = file_size,
                max = cli.max_structured_size,
                "structured file exceeds size limit, falling back to streaming scanner"
            );
        } else {
            let input_bytes =
                fs::read(input).map_err(|e| format!("failed to read {}: {e}", input.display()))?;

            // Track store size before processing to compute replacements
            // without a redundant re-scan of the input.
            let store_len_before = store.len();

            // Snapshot existing store keys so we can diff after structured
            // processing to find the literals discovered by this file.
            let store_snapshot = store.snapshot();

            let label = format!("Processing structured {}", input.display());
            return with_progress_scope(progress, &label, |_| {
                let structured_result =
                    try_structured_processing(&input_bytes, &filename, registry, store, profiles);

                let (output_bytes, method, _was_structured, fallback_stats) =
                    match structured_result {
                        Some(Ok(_structured_bytes)) => {
                            // Format-preserving double-pass:
                            //   1. Structured processing already populated the store with
                            //      field-value mappings — its re-serialized output is discarded.
                            //   2. We diff the store against the pre-pass snapshot to find the
                            //      literals this file contributed.
                            //   3. A per-file scanner (base patterns + new literals) scans the
                            //      *original* bytes, preserving comments, indentation, and key order.
                            let ext = filename.rsplit('.').next().unwrap_or("unknown");
                            let per_file_scanner =
                                build_format_preserving_scanner(scanner, store, store_snapshot)
                                    .map_err(|e| {
                                        format!("failed to build per-file scanner: {e}")
                                    })?;
                            let (scanned_bytes, scan_stats) =
                                scanner_fallback(&per_file_scanner, &input_bytes)?;
                            (
                                scanned_bytes,
                                format!("structured+scan:{ext}"),
                                true,
                                Some(scan_stats),
                            )
                        }
                        Some(Err(e)) => {
                            if cli.strict {
                                return Err(format!("structured processing failed: {e}"));
                            }
                            warn!(error = %e, "structured processing failed, falling back to scanner");
                            let (out, stats) = scanner_fallback(scanner, &input_bytes)?;
                            (out, "scanner".into(), false, Some(stats))
                        }
                        None => {
                            let (out, stats) = scanner_fallback(scanner, &input_bytes)?;
                            (out, "scanner".into(), false, Some(stats))
                        }
                    };

                // Apply entropy detection on top of the scanner output.
                let (output_bytes, fallback_stats) = {
                    let (ent_out, ent_lc) =
                        entropy_scan_bytes(&output_bytes, entropy_configs, store);
                    let stats = fallback_stats.map(|mut s| {
                        merge_entropy_counts(&mut s, ent_lc);
                        s
                    });
                    (ent_out, stats)
                };

                if cli.dry_run || report_builder.is_some() || cli.fail_on_match {
                    // In both structured and scanner paths the final output comes from
                    // a streaming scan pass, so replacements_applied is accurate.
                    let _ = store_len_before; // no longer used for counting
                    let replacements = fallback_stats
                        .as_ref()
                        .map_or(0, |s| s.replacements_applied);

                    if replacements > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = report_builder {
                        let stats = fallback_stats
                            .map(|mut s| {
                                s.matches_found = replacements;
                                s.replacements_applied = replacements;
                                s.bytes_processed = input_bytes.len() as u64;
                                s.bytes_output = output_bytes.len() as u64;
                                s
                            })
                            .unwrap_or_else(|| ScanStats {
                                matches_found: replacements,
                                replacements_applied: replacements,
                                bytes_processed: input_bytes.len() as u64,
                                bytes_output: output_bytes.len() as u64,
                                ..Default::default()
                            });
                        rb.record_file(FileReport::from_scan_stats(
                            input.display().to_string(),
                            &stats,
                            method,
                        ));
                    }
                    if cli.dry_run {
                        info!(
                            matches = replacements,
                            replacements = replacements,
                            "dry-run complete"
                        );
                        return Ok(had_matches);
                    }
                }
                maybe_extract_context(
                    &output_bytes,
                    &input.display().to_string(),
                    cli,
                    report_builder,
                );
                write_or_collect(
                    &output_bytes,
                    &input.display().to_string(),
                    output_path,
                    llm_collector,
                )?;
                Ok(had_matches)
            });
        }
    }

    // --- Streaming path ---
    let method = "scanner";
    let entropy_active = !entropy_configs.is_empty();

    if cli.dry_run {
        let label = format!("Scanning {} (dry-run)", input.display());
        let progress_label = label.clone();
        let ent_cfgs = Arc::clone(entropy_configs);
        let store_arc = Arc::clone(store);
        with_progress_scope(progress, &label, move |progress| {
            let reader = BufReader::new(
                fs::File::open(input)
                    .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
            );
            let progress_for_scan = progress.clone();
            let sz = file_size(input)?;
            // Buffer when entropy is active so we can count entropy matches.
            let (stats, locs, locs_truncated) = if entropy_active {
                let mut buf: Vec<u8> = Vec::new();
                let (mut s, locs, tr) = scan_with_locations(
                    scanner,
                    reader,
                    &mut buf,
                    Some(sz),
                    make_scan_callback(progress_for_scan, &progress_label),
                    max_match_locations,
                )?;
                let (_ent_out, ent_lc) = entropy_scan_bytes(&buf, &ent_cfgs, &store_arc);
                merge_entropy_counts(&mut s, ent_lc);
                if let Some(acc) = entropy_histogram_acc {
                    accumulate_entropy_histogram(acc, &buf, &ent_cfgs);
                }
                (s, locs, tr)
            } else {
                scan_with_locations(
                    scanner,
                    reader,
                    io::sink(),
                    Some(sz),
                    make_scan_callback(progress_for_scan, &progress_label),
                    max_match_locations,
                )?
            };
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(
                    FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                        .with_match_locations(locs, locs_truncated),
                );
            }
            info!(
                matches = stats.matches_found,
                replacements = stats.replacements_applied,
                "dry-run complete"
            );
            Ok(had_matches)
        })
    } else if let Some(out_path) = output_path {
        // Real streaming output.
        let label = format!("Scanning {}", input.display());
        let progress_label = label.clone();
        let llm_opt = llm_collector.cloned();
        let ent_cfgs = Arc::clone(entropy_configs);
        let store_arc = Arc::clone(store);
        with_progress_scope(progress, &label, move |progress| {
            if llm_opt.is_some() || entropy_active {
                // Buffer: needed for LLM collection and/or entropy post-processing.
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut buf: Vec<u8> = Vec::new();
                let progress_for_scan = progress.clone();
                let (mut stats, locs, locs_truncated) = scan_with_locations(
                    scanner,
                    reader,
                    &mut buf,
                    Some(file_size(input)?),
                    make_scan_callback(progress_for_scan, &progress_label),
                    max_match_locations,
                )?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                if entropy_active {
                    let (ent_out, ent_lc) = entropy_scan_bytes(&buf, &ent_cfgs, &store_arc);
                    buf = ent_out;
                    merge_entropy_counts(&mut stats, ent_lc);
                }
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context(&buf, &input.display().to_string(), cli, report_builder);
                if llm_opt.is_some() {
                    maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                } else {
                    atomic_write(out_path, &buf)
                        .map_err(|e| format!("failed to write output: {e}"))?;
                }
            } else {
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(out_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;

                let progress_for_scan = progress.clone();
                let (stats, locs, locs_truncated) = scan_with_locations(
                    scanner,
                    reader,
                    &mut atomic_writer,
                    Some(file_size(input)?),
                    make_scan_callback(progress_for_scan, &progress_label),
                    max_match_locations,
                )?;

                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }

                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;

                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context_reader(
                    out_path,
                    &input.display().to_string(),
                    cli,
                    report_builder,
                );
            }
            Ok(had_matches)
        })
    } else {
        let label = format!("Scanning {}", input.display());
        let progress_label = label.clone();
        let llm_opt = llm_collector.cloned();
        let ent_cfgs = Arc::clone(entropy_configs);
        let store_arc = Arc::clone(store);
        with_progress_scope(progress, &label, move |progress| {
            let sz = file_size(input)?;
            let needs_buffer = (cli.extract_context || llm_opt.is_some() || entropy_active)
                && sz <= MAX_CONTEXT_BUFFER_BYTES;
            if needs_buffer {
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut buf: Vec<u8> = Vec::new();
                let progress_for_scan = progress.clone();
                let (mut stats, locs, locs_truncated) = scan_with_locations(
                    scanner,
                    reader,
                    &mut buf,
                    Some(sz),
                    make_scan_callback(progress_for_scan, &progress_label),
                    max_match_locations,
                )?;
                if entropy_active {
                    let (ent_out, ent_lc) = entropy_scan_bytes(&buf, &ent_cfgs, &store_arc);
                    buf = ent_out;
                    merge_entropy_counts(&mut stats, ent_lc);
                }
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
                maybe_extract_context(&buf, &input.display().to_string(), cli, report_builder);
                if llm_opt.is_some() {
                    maybe_collect_for_llm(&buf, &abs_label(input), llm_opt.as_ref());
                } else {
                    let stdout = io::stdout();
                    stdout
                        .lock()
                        .write_all(&buf)
                        .map_err(|e| format!("failed to write to stdout: {e}"))?;
                }
            } else {
                if cli.extract_context {
                    warn!(
                        file = %input.display(),
                        size = sz,
                        max = MAX_CONTEXT_BUFFER_BYTES,
                        "--extract-context: file too large to buffer for stdout; \
                         use -o/--output to write to a file for context extraction"
                    );
                }
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let stdout = io::stdout();
                let writer = BufWriter::new(stdout.lock());
                let progress_for_scan = progress.clone();
                let (stats, locs, locs_truncated) = scan_with_locations(
                    scanner,
                    reader,
                    writer,
                    Some(sz),
                    make_scan_callback(progress_for_scan, &progress_label),
                    max_match_locations,
                )?;
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(
                        FileReport::from_scan_stats(input.display().to_string(), &stats, method)
                            .with_match_locations(locs, locs_truncated),
                    );
                }
            }
            Ok(had_matches)
        })
    }
}

/// Persist values discovered by structured scanning into a YAML secrets file.
///
/// Called at the end of a deterministic run so that the literal values found
/// by profile-based processors are available to future runs' streaming scanner.
///
/// - If `path` already exists: parse its entries, merge, deduplicate, rewrite.
/// - If `path` does not exist: create it with the discovered entries.
/// - Empty values are skipped; length enforcement is handled by `ScanPattern::min_length`.
/// - Entries whose `pattern` already appears in the file are skipped.
fn save_discovered_secrets(
    store: &Arc<MappingStore>,
    path: &Path,
) -> std::result::Result<usize, String> {
    // Collect discovered (original, category) pairs from the store.
    let mut new_entries: Vec<SecretEntry> = store
        .iter()
        .filter(|(_, original, _)| !original.is_empty())
        .map(|(category, original, _)| SecretEntry {
            pattern: original.to_string(),
            kind: "literal".into(),
            category: category.to_string(),
            label: Some("discovered".into()),
            values: vec![],
            min_length: None,
            max_length: None,
            threshold: None,
            charset: None,
        })
        .collect();

    if new_entries.is_empty() {
        return Ok(0);
    }

    // Load existing entries to deduplicate against.
    let existing: Vec<SecretEntry> = if path.exists() {
        let raw = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
        serde_yaml_ng::from_str::<Vec<SecretEntry>>(text).unwrap_or_default()
    } else {
        vec![]
    };

    let existing_patterns: std::collections::HashSet<&str> =
        existing.iter().map(|e| e.pattern.as_str()).collect();

    new_entries.retain(|e| !existing_patterns.contains(e.pattern.as_str()));
    let added = new_entries.len();

    if added == 0 {
        return Ok(0);
    }

    // Merge and serialize.
    let mut all_entries: Vec<&SecretEntry> = existing.iter().collect();
    all_entries.extend(new_entries.iter());

    let yaml = serde_yaml_ng::to_string(&all_entries)
        .map_err(|e| format!("failed to serialize discovered secrets: {e}"))?;

    atomic_write(path, yaml.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;

    Ok(added)
}

/// Load file-type profiles from a JSON or YAML file.
///
/// The file must deserialize to `Vec<FileTypeProfile>`. Format is detected
/// from the file extension; unknown extensions are tried as JSON then YAML.
fn load_profiles(path: &Path) -> Result<Vec<sanitize_engine::processor::FileTypeProfile>, String> {
    let raw =
        fs::read(path).map_err(|e| format!("failed to read profile '{}': {e}", path.display()))?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| format!("profile '{}' is not valid UTF-8", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let profiles: Vec<sanitize_engine::processor::FileTypeProfile> = match ext {
        "json" => serde_json::from_str(text)
            .map_err(|e| format!("profile '{}': invalid JSON: {e}", path.display())),
        "yaml" | "yml" => serde_yaml_ng::from_str(text)
            .map_err(|e| format!("profile '{}': invalid YAML: {e}", path.display())),
        _ => serde_json::from_str(text)
            .or_else(|_| serde_yaml_ng::from_str(text))
            .map_err(|e| {
                format!(
                    "profile '{}': could not parse as JSON or YAML: {e}",
                    path.display()
                )
            }),
    }?;

    // Validate include/exclude globs eagerly so bad patterns are caught at startup.
    for (i, p) in profiles.iter().enumerate() {
        for pat in p.include.iter().chain(p.exclude.iter()) {
            glob::Pattern::new(pat).map_err(|e| {
                format!(
                    "profile '{}' entry {i}: invalid glob '{pat}': {e}",
                    path.display()
                )
            })?;
        }
    }

    Ok(profiles)
}

/// Attempt structured processing for a file using the provided profiles.
///
/// Finds the first profile whose extensions match `filename` and runs the
/// corresponding structured processor. Returns `None` when no profile
/// matches, falling through to the streaming scanner.
///
/// When `--profile` is not supplied `profiles` is empty and this always
/// returns `None`, routing every file through the scanner (value-based
/// replacement that preserves all formatting).
fn try_structured_processing(
    content: &[u8],
    filename: &str,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    profiles: &[sanitize_engine::processor::FileTypeProfile],
) -> Option<Result<Vec<u8>, String>> {
    let profile = profiles.iter().find(|p| p.matches_filename(filename))?;
    match registry.process(content, profile, store) {
        Ok(Some(result)) => Some(Ok(result)),
        Ok(None) => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

/// Build a per-file scanner for the format-preserving structured pass.
///
/// Diffs the store against `before_snapshot` to find literals discovered by
/// the most recent structured processor call, compiles each into a
/// `ScanPattern::from_literal`, then extends `base_scanner` with those patterns.
///
/// Values shorter than 4 bytes are skipped to keep false-positive risk low.
fn build_format_preserving_scanner(
    base_scanner: &Arc<StreamScanner>,
    store: &Arc<MappingStore>,
    snapshot: usize,
) -> Result<StreamScanner, sanitize_engine::error::SanitizeError> {
    let extra: Vec<ScanPattern> = store
        .iter_since(snapshot)
        .filter(|(_, orig, _)| orig.len() >= 4)
        .filter_map(|(category, original, _)| {
            let s = original.as_str();
            match ScanPattern::from_literal(s, category, format!("field:{s}")) {
                Ok(pat) => Some(pat),
                Err(e) => {
                    warn!(value = %s, error = %e, "could not compile field literal pattern");
                    None
                }
            }
        })
        .collect();

    base_scanner.for_structured_pass(extra)
}

/// Process an archive file. Returns `true` if entries were processed.
#[allow(clippy::too_many_arguments)]
fn process_archive(
    input: &Path,
    cli: &Cli,
    output_path: &Path,
    deps: ArchiveDeps<'_>,
    format: ArchiveFormat,
    filter: ArchiveFilter,
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
    suppress_inner_parallelism: bool,
    _max_match_locations: usize,
) -> Result<bool, String> {
    let label = format!("Processing archive {}", input.display());

    with_progress_scope(progress, &label, |progress| {
        let base_proc = ArchiveProcessor::new(
            Arc::clone(deps.registry),
            Arc::clone(deps.scanner),
            Arc::clone(deps.store),
            deps.profiles.to_vec(),
        )
        .with_max_depth(cli.max_archive_depth)
        .with_force_text(cli.force_text)
        .with_filter(filter);

        // When the outer file-level loop is already running in parallel,
        // suppress per-entry parallelism to avoid oversubscribing the
        // rayon thread pool.
        let base_proc = if suppress_inner_parallelism {
            base_proc.with_parallel_threshold(usize::MAX)
        } else {
            base_proc
        };

        let archive_proc = if let Some(progress) = &progress {
            let label = label.clone();
            let progress = Arc::clone(progress);
            base_proc.with_progress_callback(Arc::new(move |archive_progress: &ArchiveProgress| {
                progress
                    .lock()
                    .unwrap()
                    .update_archive(&label, archive_progress);
            }))
        } else {
            base_proc
        };

        if cli.dry_run {
            let stats = match format {
                ArchiveFormat::Tar => {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    archive_proc
                        .process_tar(reader, io::sink())
                        .map_err(|e| format!("archive error: {e}"))?
                }
                ArchiveFormat::TarGz => {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    archive_proc
                        .process_tar_gz(reader, io::sink())
                        .map_err(|e| format!("archive error: {e}"))?
                }
                ArchiveFormat::Zip => {
                    let mut reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    let mut null_out = NullSeekWriter { pos: 0, len: 0 };
                    archive_proc
                        .process_zip(&mut reader, &mut null_out)
                        .map_err(|e| format!("archive error: {e}"))?
                }
            };

            if let Some(rb) = report_builder {
                record_archive_stats(rb, &stats);
            }

            info!(
                files = stats.files_processed,
                structured = stats.structured_hits,
                scanner = stats.scanner_fallback,
                "dry-run archive processing complete"
            );

            return Ok(stats.files_processed > 0);
        }

        let stats = match format {
            ArchiveFormat::Tar => {
                let reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open input: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_tar(reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
            ArchiveFormat::TarGz => {
                let reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open input: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_tar_gz(reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
            ArchiveFormat::Zip => {
                let mut reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open archive: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_zip(&mut reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
        };

        if let Some(rb) = report_builder {
            record_archive_stats(rb, &stats);
        }
        print_archive_stats(output_path, &stats);

        Ok(stats.files_processed > 0)
    })
}

fn file_size(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|e| format!("failed to stat {}: {e}", path.display()))
}

/// Convert archive stats into per-entry [`FileReport`]s and record them.
fn record_archive_stats(rb: &ReportBuilder, stats: &sanitize_engine::ArchiveStats) {
    for (path, method) in &stats.file_methods {
        if let Some(scan_stats) = stats.file_scan_stats.get(path) {
            rb.record_file(FileReport::from_scan_stats(
                path.clone(),
                scan_stats,
                method.clone(),
            ));
        } else {
            rb.record_file(FileReport {
                path: path.clone(),
                matches: 0,
                replacements: 0,
                bytes_processed: 0,
                bytes_output: 0,
                pattern_counts: std::collections::HashMap::new(),
                method: method.clone(),
                log_context: None,
                match_locations: None,
            });
        }
    }

    if stats.file_methods.is_empty() {
        rb.record_file(FileReport {
            path: "(archive)".into(),
            matches: 0,
            replacements: 0,
            bytes_processed: stats.total_input_bytes,
            bytes_output: stats.total_output_bytes,
            pattern_counts: std::collections::HashMap::new(),
            method: format!(
                "archive({} files, {} structured, {} scanner)",
                stats.files_processed, stats.structured_hits, stats.scanner_fallback
            ),
            log_context: None,
            match_locations: None,
        });
    }
}

fn print_archive_stats(output: &Path, stats: &sanitize_engine::ArchiveStats) {
    info!(
        files = stats.files_processed,
        structured = stats.structured_hits,
        scanner = stats.scanner_fallback,
        output = %output.display(),
        "archive processing complete"
    );
}

/// Write output bytes atomically to the given path, or stdout.
fn write_output(output_path: Option<&Path>, data: &[u8]) -> Result<(), String> {
    match output_path {
        Some(path) => {
            atomic_write(path, data)
                .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
            info!(output = %path.display(), "output written");
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(data)
                .map_err(|e| format!("failed to write to stdout: {e}"))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Log context extraction helper
// ---------------------------------------------------------------------------

/// Build a `LogContextConfig` from the relevant CLI flags.
fn build_log_context_config(cli: &Cli) -> LogContextConfig {
    let mut config = LogContextConfig::new()
        .with_context_lines(cli.context_lines)
        .with_max_matches(cli.max_context_matches)
        .case_sensitive(cli.context_case_sensitive);
    if !cli.context_keywords.is_empty() {
        config = if cli.context_keywords_replace {
            config.with_keywords(cli.context_keywords.iter().cloned())
        } else {
            config.with_extra_keywords(cli.context_keywords.iter().cloned())
        };
    }
    config
}

/// If `--extract-context` is set and a report builder is present, run log
/// context extraction on `bytes` and attach the result to the file entry
/// identified by `report_path`.
fn maybe_extract_context(
    bytes: &[u8],
    report_path: &str,
    cli: &Cli,
    report_builder: Option<&ReportBuilder>,
) {
    if !cli.extract_context {
        return;
    }
    let Some(rb) = report_builder else { return };
    let text = String::from_utf8_lossy(bytes);
    rb.set_file_log_context(
        report_path,
        extract_context(&text, &build_log_context_config(cli)),
    );
}

/// Streaming variant: re-opens `out_path` (the committed output file) and runs
/// log context extraction without loading the full file into memory.
/// Suitable for large log files where buffering the sanitized output is not
/// feasible. `report_path` is the key used in the report (the input file path).
/// No-ops when `--extract-context` is not set or there is no report builder.
fn maybe_extract_context_reader(
    out_path: &Path,
    report_path: &str,
    cli: &Cli,
    report_builder: Option<&ReportBuilder>,
) {
    if !cli.extract_context {
        return;
    }
    let Some(rb) = report_builder else { return };
    let config = build_log_context_config(cli);
    let file = match fs::File::open(out_path) {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, path = %out_path.display(), "--extract-context: failed to open output file for context scan");
            return;
        }
    };
    match extract_context_reader(BufReader::new(file), &config) {
        Ok(result) => rb.set_file_log_context(report_path, result),
        Err(e) => warn!(error = %e, "--extract-context: failed to read output for log context"),
    }
}

// ---------------------------------------------------------------------------
// LLM collector helpers
// ---------------------------------------------------------------------------
// strip_values_from_text, resolve_llm_template, and format_llm_prompt live in
// sanitize_engine::strip_values / sanitize_engine::llm and are imported above.

/// Return an absolute path string for `path`, resolving symlinks when the path
/// already exists or falling back to `cwd.join(path)` for planned output paths.
fn abs_label(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(path))
        .display()
        .to_string()
}

/// Push `(label, bytes)` onto the collector when `--llm` is active.
fn maybe_collect_for_llm(bytes: &[u8], label: &str, collector: Option<&LlmCollector>) {
    if let Some(c) = collector {
        if let Ok(mut guard) = c.lock() {
            guard.push((label.to_string(), bytes.to_vec()));
        }
    }
}

/// Write `data` to the output path (or stdout) unless a collector is present,
/// in which case the bytes are collected for the LLM prompt instead.
fn write_or_collect(
    data: &[u8],
    label: &str,
    output_path: Option<&Path>,
    collector: Option<&LlmCollector>,
) -> Result<(), String> {
    if let Some(c) = collector {
        maybe_collect_for_llm(data, label, Some(c));
        Ok(())
    } else {
        write_output(output_path, data)
    }
}

// ---------------------------------------------------------------------------
// Encrypt subcommand
// ---------------------------------------------------------------------------

fn run_encrypt(args: &EncryptArgs) -> Result<(), (String, i32)> {
    let validate = args.validate && !args._no_validate;

    // Resolve password.
    let password =
        resolve_password(args.password, &args.password_file, "encryption").map_err(|e| (e, 1))?;

    // Read plaintext file.
    let plaintext = fs::read(&args.input)
        .map_err(|e| (format!("cannot read '{}': {e}", args.input.display()), 1))?;

    // Determine format.
    let format = args
        .secrets_format
        .or_else(|| SecretsFormat::from_extension(args.input.to_string_lossy().as_ref()));

    // Validate (parse) before encrypting.
    if validate {
        eprint!("Validating secrets file... ");
        match parse_secrets(&plaintext, format) {
            Ok(entries) => {
                eprintln!("OK ({} entries)", entries.len());
            }
            Err(e) => {
                eprintln!("FAILED");
                return Err((format!("validation error: {e}"), 1));
            }
        }
    }

    // Encrypt.
    eprint!("Encrypting... ");
    let encrypted = encrypt_secrets(&plaintext, &password).map_err(|e| {
        eprintln!("FAILED");
        (format!("encryption failed: {e}"), 1)
    })?;

    // Write output atomically.
    atomic_write(&args.output, &encrypted)
        .map_err(|e| (format!("cannot write '{}': {e}", args.output.display()), 1))?;

    eprintln!("done");
    eprintln!(
        "Wrote {} bytes to '{}'",
        encrypted.len(),
        args.output.display()
    );
    eprintln!();
    eprintln!("To use with the sanitizer:");
    eprintln!(
        "  sanitize data.log -s {} --password",
        args.output.display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Decrypt subcommand
// ---------------------------------------------------------------------------

fn run_decrypt(args: &DecryptArgs) -> Result<(), (String, i32)> {
    // Resolve password.
    let password =
        resolve_password(args.password, &args.password_file, "decryption").map_err(|e| (e, 1))?;

    // Read encrypted file.
    let encrypted = fs::read(&args.input)
        .map_err(|e| (format!("cannot read '{}': {e}", args.input.display()), 1))?;

    // Decrypt.
    eprint!("Decrypting... ");
    let plaintext = decrypt_secrets(&encrypted, &password).map_err(|e| {
        eprintln!("FAILED");
        (format!("decryption failed: {e}"), 1)
    })?;

    // Optionally validate the decrypted content.
    if let Some(fmt) = args.secrets_format {
        eprint!("Validating... ");
        match parse_secrets(&plaintext, Some(fmt)) {
            Ok(entries) => {
                eprintln!("OK ({} entries)", entries.len());
            }
            Err(e) => {
                eprintln!("FAILED");
                return Err((format!("decrypted content is not valid {:?}: {e}", fmt), 1));
            }
        }
    }

    // Write output atomically.
    atomic_write(&args.output, &plaintext)
        .map_err(|e| (format!("cannot write '{}': {e}", args.output.display()), 1))?;

    eprintln!("done");
    eprintln!(
        "Wrote {} bytes to '{}'",
        plaintext.len(),
        args.output.display()
    );
    eprintln!();
    eprintln!("Remember to re-encrypt after editing:");
    eprintln!(
        "  sanitize encrypt {} {}.enc",
        args.output.display(),
        args.output.display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn run() -> Result<(), (String, i32)> {
    // Pre-parse --only / --exclude flags that are interleaved with archive
    // paths before handing the cleaned arg list to clap.
    let raw_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let (raw_filter_map, cleaned_args) = parse_archive_filters(&raw_args).map_err(|e| (e, 1))?;

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

    let cli = Cli::parse_from(std::iter::once(OsString::from("sanitize")).chain(cleaned_args));

    // --- initialise logging -------------------------------------------------
    init_logging(cli.effective_log_format(), cli.effective_log_level());

    // --- dispatch subcommands -----------------------------------------------
    match &cli.command {
        Some(SubCommand::Encrypt(args)) => return run_encrypt(args),
        Some(SubCommand::Decrypt(args)) => return run_decrypt(args),
        Some(SubCommand::Apps(args)) => return run_apps(args),
        Some(SubCommand::Guided) => return run_guided(),
        Some(SubCommand::Template(args)) => return run_template(args),
        Some(SubCommand::AllowTest(args)) => return run_allow_test(args),
        Some(SubCommand::InstallHook(args)) => return run_install_hook(args),
        Some(SubCommand::InitHook(args)) => return run_init(args),
        Some(SubCommand::ShowConfig) => return run_show_config(),
        Some(SubCommand::Scan(args)) => return run_scan(args),
        Some(SubCommand::TestPattern(args)) => return run_test_pattern(args),
        None => {} // fall through to default sanitize mode
    }

    run_sanitize(cli, None, filter_map)
}

fn run_sanitize(
    mut cli: Cli,
    pre_resolved_password: Option<Zeroizing<String>>,
    filter_map: HashMap<PathBuf, ArchiveFilter>,
) -> Result<(), (String, i32)> {
    // --- install signal handler (graceful shutdown) --------------------------
    if let Err(e) = ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }) {
        eprintln!("warning: failed to install signal handler: {e}");
    }

    // Snapshot what the user actually typed before config files override anything.
    let cli_snapshot = CliConfigSnapshot::capture(&cli);

    // --- apply settings.yaml defaults (CLI flags always win) -----------------
    let settings = load_settings();
    if cli.app.is_empty() && !settings.app.is_empty() {
        cli.app = settings.app;
    }
    if cli.allow.is_empty() && !settings.allow.is_empty() {
        cli.allow = settings.allow;
    }
    if !cli.fail_on_match {
        if let Some(v) = settings.fail_on_match {
            cli.fail_on_match = v;
        }
    }
    if !cli.strict {
        if let Some(v) = settings.strict {
            cli.strict = v;
        }
    }
    if !cli.no_structured_handoff {
        if let Some(v) = settings.no_structured_handoff {
            cli.no_structured_handoff = v;
        }
    }
    if !cli.no_field_signal {
        if let Some(v) = settings.no_field_signal {
            cli.no_field_signal = v;
        }
    }
    if cli.threads.is_none() {
        cli.threads = settings.threads;
    }
    if cli.log_format.is_none() {
        cli.log_format = settings.log_format;
    }
    if cli.log_level.is_none() {
        cli.log_level = settings.log_level;
    }
    if !cli.no_progress {
        if let Some(v) = settings.no_progress {
            cli.no_progress = v;
        }
    }

    // --- apply .sanitize.toml project config (project > settings, CLI > project) --
    if let Some(project_config_path) = find_project_config() {
        let (pc, config_dir) = load_project_config(&project_config_path);

        // App bundles: merge — project bundles extend settings bundles unless
        // the user already gave --app on the CLI (non-empty after settings apply).
        for bundle in &pc.app {
            if !cli.app.contains(bundle) {
                cli.app.push(bundle.clone());
            }
        }
        // Allow-list: same merge strategy.
        for val in &pc.allow {
            if !cli.allow.contains(val) {
                cli.allow.push(val.clone());
            }
        }
        // secrets_file: project config wins over global default, CLI wins over project.
        if cli.secrets_file.is_none() {
            if let Some(rel) = pc.secrets_file {
                cli.secrets_file = Some(config_dir.join(rel));
            }
        }
        // encrypted_secrets: project config sets it when CLI did not.
        if !cli.encrypted_secrets {
            if let Some(v) = pc.encrypted_secrets {
                cli.encrypted_secrets = v;
            }
        }
        // profile: project config wins over nothing, CLI wins over project.
        if cli.profile.is_none() {
            if let Some(rel) = pc.profile {
                cli.profile = Some(config_dir.join(rel));
            }
        }
        if !cli.fail_on_match {
            if let Some(v) = pc.fail_on_match {
                cli.fail_on_match = v;
            }
        }
        if !cli.strict {
            if let Some(v) = pc.strict {
                cli.strict = v;
            }
        }
        if !cli.no_structured_handoff {
            if let Some(v) = pc.no_structured_handoff {
                cli.no_structured_handoff = v;
            }
        }
        if !cli.no_field_signal {
            if let Some(v) = pc.no_field_signal {
                cli.no_field_signal = v;
            }
        }
    }

    // --- validate -----------------------------------------------------------
    validate_args(&cli).map_err(|e| (e, 1))?;

    let progress_mode = cli.effective_progress_mode();
    let progress_context = ProgressContext::detect(cli.effective_log_format());
    let progress_policy = ProgressPolicy::from_mode(progress_mode, progress_context);
    let progress_reporter = if progress_policy.live_updates || progress_policy.milestone_updates {
        Some(Arc::new(Mutex::new(ProgressReporter::new(
            progress_policy,
            progress_context.json_logs,
            cli.progress_interval_ms,
        ))))
    } else {
        None
    };

    let thread_count = resolve_thread_count(cli.threads);

    // Initialise the global rayon thread pool from the resolved thread count.
    // build_global() is a no-op if called more than once (e.g. in tests).
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global();

    // --- auto-load (and auto-create) global default secrets -------------------
    // Skipped when --app is active: each app bundle is self-contained and
    // provides its own write-back target.
    if cli.secrets_file.is_none() && cli.app.is_empty() {
        let default_path = global_default_secrets_path();
        if !default_path.exists() {
            // First run: create a minimal secrets file so the user has a
            // visible, editable file to customise. Detection patterns are
            // applied from hardcoded defaults; the file starts with just the
            // allowlist so it stays small and readable.
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
            if let Ok(yaml) = serde_yaml_ng::to_string(&[allow_entry]) {
                let header = "# Global sanitize allowlist — add patterns or kind:regex entries here.\n# Auto-loaded on every plain run. Edit freely; deleted values take effect immediately.\n\n";
                let _ = fs::write(&default_path, format!("{header}{yaml}"));
            }
        }
        if default_path.exists() {
            cli.secrets_file = Some(default_path);
        }
    }

    // --- auto-provision local app bundle copies and set write-back target --------
    // On first use of --app <name>, copy the built-in bundle into the user apps
    // directory so profile.yaml and secrets.yaml are both on disk and editable.
    // For single-app runs without an explicit --secrets-file, also point
    // cli.secrets_file at the local secrets.yaml so save_discovered_secrets can
    // persist the literals found by the profile pass for future runs.
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

    // --- validate profile requires a secrets file --------------------------------
    // A profile-only run would complete Phase 1 but have no patterns for Phase 2,
    // producing half-sanitized output with no indication of what was missed.
    // The secrets file can be blank — it will be populated by the handoff on the
    // first run and used by the scanner on all subsequent runs.
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

    // --- print run configuration header to stderr ----------------------------
    // Only emit when progress is active (interactive TTY or --progress on/ci).
    // In auto+non-TTY mode (pipes, scripts) we stay silent.
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

    let effective_password: Option<Zeroizing<String>> =
        if cli.encrypted_secrets || cli.deterministic {
            if let Some(pw) = pre_resolved_password {
                Some(pw)
            } else {
                Some(resolve_sanitize_password(&cli).map_err(|e| (e, 1))?)
            }
        } else {
            None
        };
    // effective_password is Zeroizing<String> — scrubbed automatically on drop.

    // --- build core components ----------------------------------------------
    let scan_config = build_scan_config(cli.chunk_size).map_err(|e| (e, 1))?;
    let registry = Arc::new(ProcessorRegistry::with_builtins());

    // --- load field-path profiles (--profile) --------------------------------
    let file_profiles: Vec<sanitize_engine::processor::FileTypeProfile> =
        if let Some(ref profile_path) = cli.profile {
            load_profiles(profile_path).map_err(|e| (e, 1))?
        } else {
            vec![]
        };

    // --- compile base patterns from all sources --------------------------------
    // All sources (--secrets-file, --app) contribute to a single
    // Vec<ScanPattern> that is reused by both the initial scanner and the
    // Phase 2 augmented scanner (which appends profile-discovered literals).
    let mut base_patterns: Vec<ScanPattern> = vec![];
    // Allow patterns accumulate from secrets file + --allow CLI values and are
    // used to build the AllowlistMatcher before constructing the store.
    let mut all_allow_patterns: Vec<String> = cli.allow.clone();
    // Entropy configs built from kind:entropy secrets entries + --entropy-threshold.
    let mut entropy_configs: Vec<EntropyConfig> = vec![];

    // Pre-pass: collect allow patterns from --app bundles so they are included
    // in the allowlist that gates the MappingStore. Without this, app bundle
    // `kind: allow` entries would never reach the store and profile-discovered
    // placeholder values (e.g. "token", "secret") would still enter the literal
    // pool and propagate via the augmented scanner.
    for app_name in &cli.app {
        if let Ok(bundle) = load_app_bundle(app_name) {
            all_allow_patterns.extend(extract_allow_patterns(&bundle.secrets));
        }
    }

    // 1. From --secrets-file (plaintext or encrypted).
    let secrets_raw_bytes: Option<Vec<u8>> = if let Some(ref secrets_path) = cli.secrets_file {
        if secrets_path.exists() {
            Some(fs::read(secrets_path).map_err(|e| {
                (
                    format!(
                        "failed to read secrets file {}: {e}",
                        secrets_path.display()
                    ),
                    1,
                )
            })?)
        } else if cli.deterministic {
            None
        } else {
            return Err((
                format!("secrets file not found: {}", secrets_path.display()),
                1,
            ));
        }
    } else {
        None
    };

    let mut was_encrypted_secrets = false;
    if let Some(ref raw_bytes) = secrets_raw_bytes {
        let secrets_format = cli
            .secrets_file
            .as_ref()
            .and_then(|p| SecretsFormat::from_extension(p.to_string_lossy().as_ref()));
        let (((patterns, warnings), allow_from_secrets), was_encrypted) =
            sanitize_engine::secrets::load_secrets_auto(
                raw_bytes,
                effective_password.as_ref().map(|s| s.as_str()),
                secrets_format,
                !cli.encrypted_secrets,
            )
            .map_err(|e| (format!("failed to load secrets: {e}"), 1))?;

        let secrets_display = cli
            .secrets_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        was_encrypted_secrets = was_encrypted;
        if was_encrypted {
            info!(secrets_file = %secrets_display, "loaded encrypted secrets");
        } else {
            info!(secrets_file = %secrets_display, "loaded plaintext secrets (unencrypted)");
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
        base_patterns.extend(patterns);
        all_allow_patterns.extend(allow_from_secrets);

        // Extract entropy configs from kind:entropy entries in the secrets file.
        // We re-parse the (possibly decrypted) bytes to get the entries because
        // load_secrets_auto zeroizes them after pattern compilation.
        let entropy_plaintext: Option<Zeroizing<Vec<u8>>> = if was_encrypted {
            effective_password
                .as_ref()
                .and_then(|pw| decrypt_secrets(raw_bytes, pw.as_str()).ok())
        } else {
            None
        };
        let bytes_for_entropy: &[u8] = entropy_plaintext
            .as_deref()
            .map_or(raw_bytes.as_slice(), |v| v);
        if let Ok(ent_entries) = parse_secrets(bytes_for_entropy, None) {
            entropy_configs.extend(entropy_configs_from_entries(&ent_entries));
        }
    }

    // --entropy-threshold adds a global catch-all entropy config (alphanumeric,
    // 20–200 chars) using the user-supplied threshold, unless a kind:entropy entry
    // with the same label already covers it.
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

    // Accumulator for entropy calibration histogram (dry-run only).
    // Token values are never stored — only per-threshold counts.
    let entropy_histogram_acc: Option<Arc<Mutex<Vec<EntropyBuckets>>>> =
        if cli.dry_run && !entropy_configs.is_empty() {
            Some(Arc::new(Mutex::new(Vec::new())))
        } else {
            None
        };

    // 2. Implicit baseline: load built-in patterns when no explicit detection
    //    source is provided (zero-config), when --app is used without a secrets
    //    file, or when a profile is active. Passing --secrets-file is the signal
    //    that the caller knows exactly what they want, so defaults are skipped.
    //    Common allow patterns are added here — before the allowlist is built —
    //    so the store is aware of them from the first matched value.
    let nothing_specified = cli.secrets_file.is_none()
        && cli.app.is_empty()
        && cli.profile.is_none()
        && !cli.use_default;
    let load_defaults =
        cli.use_default || nothing_specified || (!cli.app.is_empty() && cli.secrets_file.is_none());
    if load_defaults {
        all_allow_patterns.extend(common_allow_patterns());
    }

    // Build allowlist from all sources (secrets file, --allow CLI, built-in defaults).
    let allowlist: Option<Arc<sanitize_engine::allowlist::AllowlistMatcher>> =
        if all_allow_patterns.is_empty() {
            None
        } else {
            let (matcher, al_warnings) =
                sanitize_engine::allowlist::AllowlistMatcher::new(all_allow_patterns);
            for w in &al_warnings {
                warn!(warning = %w, "allowlist pattern warning");
            }
            let matcher = Arc::new(matcher);
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

    // 3. From --app bundles (secrets + collect profiles for merging below).
    let mut app_profiles: Vec<FileTypeProfile> = vec![];
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

    // --- merge profiles (--app bundles first, then --profile file) -----------
    // App profiles are prepended so that the user's --profile rules take
    // precedence when both match the same file.
    let mut profiles: Vec<sanitize_engine::processor::FileTypeProfile> = {
        let mut merged = app_profiles;
        merged.extend(file_profiles);
        merged
    };

    // --- inject field-name signals into every active profile -----------------
    // When a profile is active and --no-field-signal is not set, key-name
    // heuristics fire as a fallback inside walk_tree when no explicit FieldRule
    // matches.  Built-in signals cover the most common sensitive keyword families;
    // user-defined signals come from `kind: field-name` entries in the secrets file.
    if !cli.no_field_signal && !profiles.is_empty() {
        let mut active_signals = builtin_field_name_signals();

        // Collect user-defined `kind: field-name` entries by re-parsing the
        // secrets bytes (load_secrets_auto zeroizes entries after pattern
        // compilation, so we parse again — same as the entropy-config path).
        if let Some(ref raw_bytes) = secrets_raw_bytes {
            let plaintext_for_signals: Option<Zeroizing<Vec<u8>>> = if was_encrypted_secrets {
                effective_password
                    .as_ref()
                    .and_then(|pw| decrypt_secrets(raw_bytes, pw.as_str()).ok())
            } else {
                None
            };
            let bytes = plaintext_for_signals
                .as_deref()
                .map_or(raw_bytes.as_slice(), |v| v);
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
        for profile in &mut profiles {
            profile.field_name_signals = active_signals.clone();
        }
        info!(
            signals = signal_count,
            "field-name signals active (disable with --no-field-signal)"
        );
    }

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

    // --- build report builder -----------------------------------------------
    // Force report building when --llm or --findings is active so we have
    // per-file stats available for those output paths. Also enabled by default
    // so the post-run redaction summary can be printed (suppressed by --quiet).
    let report_enabled =
        cli.report.is_some() || cli.llm.is_some() || cli.findings.is_some() || !cli.quiet;
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

    // Reference mode: --llm + --output → write sanitized files to disk and emit
    // a prompt listing their absolute paths instead of inlining content.
    // Inline mode (default): --llm alone → bytes are collected and embedded in
    // <content> blocks in the prompt (no files written to disk).
    let reference_mode = cli.llm.is_some() && cli.output.is_some();

    // --- LLM collector (only allocated for inline mode) ----------------------
    let llm_collector: Option<LlmCollector> = if cli.llm.is_some() && !reference_mode {
        Some(Arc::new(Mutex::new(Vec::new())))
    } else {
        None
    };

    let input_targets = plan_input_targets(&cli).map_err(|e| (e, 1))?;

    // --- --strip-values early exit -----------------------------------------
    // Bypass the full sanitization pipeline: emit key structure only (no values).
    if cli.strip_values {
        let delimiter = "#strip-values-delimiter#"; // placeholder; real one below
        let _ = delimiter; // suppress lint
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

    // --- split stdin (serial) from file targets (parallel) ------------------
    // Stdin must always be processed serially to preserve stream semantics and
    // terminal UX. File targets are processed in parallel via rayon when
    // thread_count > 1 and there is more than one file target.
    //
    // When --profile is active, stdin is deferred until after file processing
    // so that the augmented scanner (base patterns + all literals discovered
    // from profile-matched files and archives) is fully built before stdin
    // is read. Without this, values discovered from structured files would
    // not be replaced in the piped input.
    let (stdin_targets, file_targets): (Vec<_>, Vec<_>) = input_targets
        .into_iter()
        .partition(|t| matches!(t, InputTarget::Stdin { .. }));

    // Capture (input_label, planned_output_path) pairs for reference-mode prompt
    // before the targets are consumed by processing.
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

    let mut had_matches = false;

    // When no --profile is active there is no augmented scanner to wait for,
    // so process stdin immediately (original behaviour).
    if profiles.is_empty() {
        for target in &stdin_targets {
            let InputTarget::Stdin { ref output } = target else {
                unreachable!()
            };
            let result = process_stdin(
                &cli,
                output.as_deref(),
                &scanner,
                &registry,
                &store,
                &profiles,
                report_builder.as_ref(),
                progress_reporter.as_ref(),
                llm_collector.as_ref(),
                &entropy_configs,
                entropy_histogram_acc.as_ref(),
            )
            .map_err(|e| (e, 1))?;
            had_matches |= result;
        }
    }

    // --- two-phase file processing ------------------------------------------
    //
    // Phase 1: process profile-matched plain files serially so that every
    //   value replaced via field-path rules is recorded in `store`.
    //
    // Phase 2: build an augmented scanner that includes those discovered
    //   literals (on top of any secrets-file patterns), then process all
    //   remaining files (archives + non-profile plain files) with it.
    //   Archives are always Phase 2 because we can't pre-partition their
    //   entries before reading them.
    let (phase1_targets, phase2_targets): (Vec<_>, Vec<_>) = if profiles.is_empty() {
        // No profiles → skip Phase 1 entirely.
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

    // Phase 1 — serial, profile-matched plain files.
    for target in phase1_targets {
        if is_interrupted() {
            break;
        }
        let InputTarget::File { input, output } = target else {
            unreachable!()
        };
        let result = process_plain_file(
            &input,
            &cli,
            Some(output.as_path()),
            &scanner,
            &registry,
            &store,
            &profiles,
            report_builder.as_ref(),
            progress_reporter.as_ref(),
            llm_collector.as_ref(),
            &entropy_configs,
            cli.max_match_locations,
            entropy_histogram_acc.as_ref(),
        )
        .map_err(|e| (e, 1))?;
        had_matches |= result;
    }

    // Archive discovery pre-pass: for any archive in Phase 2 that has
    // profile-matched entries, run the structured processor on those entries
    // (discarding output) so their replaced values are recorded in the store.
    // This is a second read of the archive file — correctness over speed.
    if !profiles.is_empty() {
        let discovery = ArchiveProcessor::new(
            Arc::clone(&registry),
            Arc::clone(&scanner), // scanner unused in discovery — just satisfies the API
            Arc::clone(&store),
            profiles.to_vec(),
        );
        for target in &phase2_targets {
            if is_interrupted() {
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

    // Build augmented scanner: base secrets patterns + literals discovered in
    // Phase 1 (plain files) and the archive discovery pre-pass above.
    let augmented_scanner = build_augmented_scanner(&base_patterns, &store, scan_config)?;

    // When --profile is active, stdin was deferred until here so it benefits
    // from the fully-populated augmented scanner.
    if !profiles.is_empty() {
        for target in stdin_targets {
            let InputTarget::Stdin { output } = target else {
                unreachable!()
            };
            let result = process_stdin(
                &cli,
                output.as_deref(),
                &augmented_scanner,
                &registry,
                &store,
                &profiles,
                report_builder.as_ref(),
                progress_reporter.as_ref(),
                llm_collector.as_ref(),
                &entropy_configs,
                entropy_histogram_acc.as_ref(),
            )
            .map_err(|e| (e, 1))?;
            had_matches |= result;
        }
    }

    // Phase 2 — parallel when multiple targets, serial otherwise.
    // Each worker gets Arc clones — all inner state is Send + Sync.
    // Results are collected and folded after all workers finish.
    let file_results: Vec<Result<bool, (String, i32)>> = if phase2_targets.len() > 1 {
        phase2_targets
            .into_par_iter()
            .map(|target| {
                if is_interrupted() {
                    return Ok(false);
                }
                let InputTarget::File { input, output } = target else {
                    unreachable!()
                };
                let input_str = input.to_string_lossy();
                if let Some(fmt) = ArchiveFormat::from_path(&input_str) {
                    let filter = filter_map.get(&input).cloned().unwrap_or_default();
                    process_archive(
                        &input,
                        &cli,
                        &output,
                        ArchiveDeps {
                            scanner: &augmented_scanner,
                            registry: &registry,
                            store: &store,
                            profiles: &profiles,
                        },
                        fmt,
                        filter,
                        report_builder.as_ref(),
                        progress_reporter.as_ref(),
                        // suppress per-entry parallelism: file-level parallelism
                        // is already consuming the thread budget.
                        true,
                        cli.max_match_locations,
                    )
                    .map_err(|e| (e, 1))
                } else {
                    process_plain_file(
                        &input,
                        &cli,
                        Some(output.as_path()),
                        &augmented_scanner,
                        &registry,
                        &store,
                        &profiles,
                        report_builder.as_ref(),
                        progress_reporter.as_ref(),
                        llm_collector.as_ref(),
                        &entropy_configs,
                        cli.max_match_locations,
                        entropy_histogram_acc.as_ref(),
                    )
                    .map_err(|e| (e, 1))
                }
            })
            .collect()
    } else {
        // Single Phase 2 target — run on the current thread (no rayon overhead).
        phase2_targets
            .into_iter()
            .map(|target| {
                let InputTarget::File { input, output } = target else {
                    unreachable!()
                };
                let input_str = input.to_string_lossy();
                if let Some(fmt) = ArchiveFormat::from_path(&input_str) {
                    let filter = filter_map.get(&input).cloned().unwrap_or_default();
                    process_archive(
                        &input,
                        &cli,
                        &output,
                        ArchiveDeps {
                            scanner: &augmented_scanner,
                            registry: &registry,
                            store: &store,
                            profiles: &profiles,
                        },
                        fmt,
                        filter,
                        report_builder.as_ref(),
                        progress_reporter.as_ref(),
                        // single file target: archive entry parallelism is enabled.
                        false,
                        cli.max_match_locations,
                    )
                    .map_err(|e| (e, 1))
                } else {
                    process_plain_file(
                        &input,
                        &cli,
                        Some(output.as_path()),
                        &augmented_scanner,
                        &registry,
                        &store,
                        &profiles,
                        report_builder.as_ref(),
                        progress_reporter.as_ref(),
                        llm_collector.as_ref(),
                        &entropy_configs,
                        cli.max_match_locations,
                        entropy_histogram_acc.as_ref(),
                    )
                    .map_err(|e| (e, 1))
                }
            })
            .collect()
    };

    // Return the first error encountered (if any), then fold had_matches.
    for result in file_results {
        had_matches |= result?;
    }

    // --- check for interruption ---------------------------------------------
    if is_interrupted() {
        return Err(("interrupted by signal".into(), 130));
    }

    // --- persist discovered secrets (profile active + not suppressed) -------------------
    // When a profile is active and --secrets-file was explicitly provided, append any
    // literal values found by structured scanning back into that file so future runs can
    // match them everywhere they appear.  We intentionally skip this when no --secrets-file
    // was given — writing a surprise file to CWD is worse than doing nothing.
    // Pass --no-structured-handoff to suppress the write even when a secrets file is set.
    if !cli.no_structured_handoff && !profiles.is_empty() {
        if let Some(save_path) = &cli.secrets_file {
            match save_discovered_secrets(&store, save_path) {
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

    // --- write report / LLM prompt -----------------------------------------
    if let Some(builder) = report_builder {
        let report = builder.finish();

        // --- LLM prompt (--llm) ---
        if let Some(ref template_name) = cli.llm {
            let prompt = if reference_mode {
                format_llm_prompt_reference(template_name, &llm_ref_entries, Some(&report))
                    .map_err(|e| (e, 1))?
            } else {
                let entries = llm_collector
                    .as_ref()
                    .and_then(|c| c.lock().ok())
                    .map(|g| g.clone())
                    .unwrap_or_default();
                format_llm_prompt(template_name, &entries, Some(&report)).map_err(|e| (e, 1))?
            };
            let stdout = io::stdout();
            stdout
                .lock()
                .write_all(prompt.as_bytes())
                .map_err(|e| (format!("failed to write LLM prompt: {e}"), 1))?;
        }

        // --- report (--report / --report-format) ---
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
                    eprintln!("{content}");
                }
            }
        }

        // --- NDJSON findings (--findings / scan --json) ---
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

        // --- human-readable redaction summary (default on, suppressed by --quiet) ---
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

    // --- entropy calibration histogram (dry-run with entropy active) ---------
    if let Some(acc) = entropy_histogram_acc {
        if let Ok(buckets) = acc.lock() {
            if !buckets.is_empty() {
                print_entropy_histogram(&buckets);
            }
        }
    }

    // --- Performance summary (bench feature) --------------------------------
    #[cfg(feature = "bench")]
    {
        let mappings = store.len();
        info!(unique_mappings = mappings, "performance summary");
    }

    // --- --fail-on-match ----------------------------------------------------
    if cli.fail_on_match && had_matches {
        return Err(("matches found (--fail-on-match)".into(), 2));
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guided::{CloudProvider, GuidedFormat};
    use crate::hooks::{
        build_hook_flags, build_hook_script, hook_script_pre_commit_scan, remove_hook, sh_quote,
        HOOK_MARKER,
    };
    use clap::Parser;
    use tempfile::tempdir;

    fn make_progress_context(
        stderr_is_terminal: bool,
        is_ci: bool,
        term_is_dumb: bool,
        json_logs: bool,
    ) -> ProgressContext {
        ProgressContext {
            stderr_is_terminal,
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
        let _ = Cli::try_parse_from(["sanitize", "input.txt"]);
    }

    #[test]
    fn cli_parses_basic_input() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt"]).unwrap();
        assert_eq!(cli.input, vec![PathBuf::from("input.txt")]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_input_with_output() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "-o", "output.txt"]).unwrap();
        assert_eq!(cli.input, vec![PathBuf::from("input.txt")]);
        assert_eq!(cli.output.unwrap(), PathBuf::from("output.txt"));
    }

    #[test]
    fn cli_parses_multiple_inputs() {
        let cli = Cli::try_parse_from(["sanitize", "test.txt", "a.json", "b.zip"]).unwrap();
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
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--output", "out.txt"]).unwrap();
        assert_eq!(cli.output.unwrap(), PathBuf::from("out.txt"));
    }

    #[test]
    fn cli_parses_secrets_file_flag() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--secrets-file", "secrets.json"])
            .unwrap();
        assert_eq!(cli.secrets_file.unwrap(), PathBuf::from("secrets.json"));
    }

    #[test]
    fn cli_parses_short_flags() {
        let cli = Cli::try_parse_from([
            "sanitize",
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
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--dry-run"]).unwrap();
        assert!(cli.dry_run);
    }

    #[test]
    fn cli_parses_progress_mode() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--progress", "on"]).unwrap();
        assert_eq!(cli.progress, Some(ProgressMode::On));
        assert_eq!(cli.effective_progress_mode(), ProgressMode::On);
    }

    #[test]
    fn cli_no_progress_maps_to_off() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--no-progress"]).unwrap();
        assert!(cli.no_progress);
        assert_eq!(cli.effective_progress_mode(), ProgressMode::Off);
    }

    #[test]
    fn cli_explicit_progress_takes_precedence_over_no_progress() {
        let cli =
            Cli::try_parse_from(["sanitize", "input.txt", "--no-progress", "--progress", "on"])
                .unwrap();
        assert!(cli.no_progress);
        assert_eq!(cli.progress, Some(ProgressMode::On));
        assert_eq!(cli.effective_progress_mode(), ProgressMode::On);
    }

    #[test]
    fn cli_parses_progress_interval() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--progress-interval-ms", "500"])
            .unwrap();
        assert_eq!(cli.progress_interval_ms, 500);
    }

    #[test]
    fn validate_args_rejects_zero_progress_interval() {
        let mut cli = Cli::try_parse_from(["sanitize", "input.txt"]).unwrap();
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
        assert!(!policy.live_updates);
        assert!(!policy.milestone_updates);
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
    fn cli_parses_encrypt_subcommand() {
        let cli = Cli::try_parse_from([
            "sanitize",
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
            "sanitize",
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
    fn cli_parses_guided_subcommand() {
        let cli = Cli::try_parse_from(["sanitize", "guided"]).unwrap();
        assert!(matches!(cli.command, Some(SubCommand::Guided)));
        assert!(cli.input.is_empty());
    }

    #[test]
    fn cli_no_input_no_subcommand_is_ok_at_parse_time() {
        // Clap allows it (input is Vec); we validate manually in run().
        let cli = Cli::try_parse_from(["sanitize", "--dry-run"]).unwrap();
        assert!(cli.input.is_empty());
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "sanitize",
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
        let cli = Cli::try_parse_from(["sanitize", "-", "-s", "s.json"]).unwrap();
        assert!(has_stdin_input(&cli));
    }

    #[test]
    fn cli_stdin_no_input() {
        let cli = Cli::try_parse_from(["sanitize", "-s", "s.json"]).unwrap();
        assert!(has_stdin_input(&cli));
    }

    #[test]
    fn cli_file_input_not_stdin() {
        let cli = Cli::try_parse_from(["sanitize", "data.log"]).unwrap();
        assert!(!has_stdin_input(&cli));
    }

    #[test]
    fn cli_file_and_stdin_mix_is_supported() {
        let cli = Cli::try_parse_from(["sanitize", "test.txt", "-", "-s", "s.json"]).unwrap();
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
            "sanitize",
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
            "sanitize",
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

    #[test]
    fn guided_entries_compile_balanced() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Balanced,
            domains: vec!["corp.internal".into()],
            providers: vec![CloudProvider::Aws],
            exclude_noise_ids: true,
            formats: vec![GuidedFormat::YamlJson, GuidedFormat::Env],
        };

        let entries = build_guided_entries(&opts);
        let (_patterns, warnings) = entries_to_patterns(&entries);
        assert!(warnings.is_empty());
    }

    #[test]
    fn guided_entries_include_gcp_custom_when_selected() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Aggressive,
            domains: vec![],
            providers: vec![CloudProvider::Gcp],
            exclude_noise_ids: false,
            formats: vec![],
        };

        let entries = build_guided_entries(&opts);
        assert!(entries
            .iter()
            .any(|e| e.category == "custom:gcp_service_account"));
        assert!(entries.iter().any(|e| e.category == "custom:gcp_resource"));
    }

    #[test]
    fn guided_profiles_use_known_processor_names() {
        use sanitize_engine::processor::ProcessorRegistry;
        let registry = ProcessorRegistry::with_builtins();

        for preset in [
            GuidedPreset::Balanced,
            GuidedPreset::Aggressive,
            GuidedPreset::WebApp,
            GuidedPreset::Kubernetes,
            GuidedPreset::Database,
        ] {
            let opts = GuidedOptions {
                preset,
                domains: vec![],
                providers: vec![],
                exclude_noise_ids: false,
                formats: vec![
                    GuidedFormat::YamlJson,
                    GuidedFormat::JsonLines,
                    GuidedFormat::Env,
                    GuidedFormat::Toml,
                    GuidedFormat::IniConf,
                ],
            };
            let profiles = build_guided_profiles(&opts);
            for p in &profiles {
                assert!(
                    registry.get(&p.processor).is_some(),
                    "preset {:?}: unknown processor '{}'",
                    preset,
                    p.processor
                );
            }
        }
    }

    #[test]
    fn guided_profiles_all_formats_produce_non_empty_field_rules() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Balanced,
            domains: vec![],
            providers: vec![],
            exclude_noise_ids: false,
            formats: vec![
                GuidedFormat::YamlJson,
                GuidedFormat::JsonLines,
                GuidedFormat::Env,
                GuidedFormat::Toml,
                GuidedFormat::IniConf,
            ],
        };
        let profiles = build_guided_profiles(&opts);
        // YamlJson produces 2 profiles (yaml + json), each other format 1 → 6 total.
        assert_eq!(
            profiles.len(),
            6,
            "expected 6 profiles (yaml, json, jsonl, env, toml, ini)"
        );
        for p in &profiles {
            assert!(
                !p.fields.is_empty(),
                "profile '{}' has no field rules",
                p.processor
            );
        }
    }

    #[test]
    fn guided_profiles_k8s_adds_secret_data_fields() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Kubernetes,
            domains: vec![],
            providers: vec![],
            exclude_noise_ids: false,
            formats: vec![GuidedFormat::YamlJson],
        };
        let profiles = build_guided_profiles(&opts);
        let yaml_profile = profiles.iter().find(|p| p.processor == "yaml").unwrap();
        let patterns: Vec<&str> = yaml_profile
            .fields
            .iter()
            .map(|f| f.pattern.as_str())
            .collect();
        assert!(
            patterns.contains(&"data.*"),
            "k8s yaml profile missing data.*"
        );
        assert!(
            patterns.contains(&"stringData.*"),
            "k8s yaml profile missing stringData.*"
        );
    }

    #[test]
    fn guided_profiles_jsonl_has_skip_invalid_option() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Balanced,
            domains: vec![],
            providers: vec![],
            exclude_noise_ids: false,
            formats: vec![GuidedFormat::JsonLines],
        };
        let profiles = build_guided_profiles(&opts);
        let jsonl = profiles.iter().find(|p| p.processor == "jsonl").unwrap();
        assert_eq!(
            jsonl.options.get("skip_invalid").map(|s| s.as_str()),
            Some("true"),
            "jsonl profile should have skip_invalid=true for mixed log files"
        );
    }

    #[test]
    fn guided_entries_k8s_includes_container_id_short() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Kubernetes,
            domains: vec![],
            providers: vec![],
            exclude_noise_ids: false,
            formats: vec![],
        };
        let entries = build_guided_entries(&opts);
        assert!(
            entries
                .iter()
                .any(|e| e.label.as_deref() == Some("container_id_short")),
            "k8s preset should include container_id_short"
        );
    }

    #[test]
    fn guided_entries_balanced_excludes_container_id_short() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Balanced,
            domains: vec![],
            providers: vec![],
            exclude_noise_ids: false,
            formats: vec![],
        };
        let entries = build_guided_entries(&opts);
        assert!(
            !entries
                .iter()
                .any(|e| e.label.as_deref() == Some("container_id_short")),
            "balanced preset should not include container_id_short"
        );
    }

    // -----------------------------------------------------------------------
    // validate_args: additional cases
    // -----------------------------------------------------------------------

    fn real_file_cli() -> Cli {
        let mut cli = Cli::try_parse_from(["sanitize", "placeholder"]).unwrap();
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
            script.contains("SANITIZE_SKIP"),
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
        let script = hook_script_pre_commit_scan("--use-default");
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
        let our_block = hook_script_pre_commit_scan("--use-default");
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
