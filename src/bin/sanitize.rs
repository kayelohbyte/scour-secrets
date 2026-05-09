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

mod progress;
use progress::{
    with_progress_scope, ProgressContext, ProgressMode, ProgressPolicy, ProgressReporter,
    SharedProgressReporter,
};

use clap::{Parser, Subcommand};
use rayon::prelude::*;
use sanitize_engine::secrets::{
    decrypt_secrets, encrypt_secrets, entries_to_patterns, parse_secrets, serialize_secrets,
    SecretEntry, SecretsFormat,
};
use sanitize_engine::{
    atomic_write, extract_context, extract_context_reader, format_llm_prompt,
    strip_values_from_text, ArchiveFilter, ArchiveFormat, ArchiveProcessor, ArchiveProgress,
    AtomicFileWriter, Category, FieldRule, FileReport, FileTypeProfile, HmacGenerator, LlmEntry,
    LogContextConfig, MappingStore, ProcessorRegistry, RandomGenerator, ReplacementGenerator,
    ReportBuilder, ReportMetadata, ScanConfig, ScanPattern, ScanStats, StreamScanner,
    DEFAULT_ARCHIVE_DEPTH, DEFAULT_CONTEXT_LINES, DEFAULT_MAX_MATCHES,
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
/// input order. Wrapped in Arc<Mutex> so it can be passed into parallel file
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
  # Format sanitized output as an LLM prompt (print to stdout for piping):\n  \
  sanitize app.log -s secrets.yaml --llm | pbcopy\n  \
  sanitize config.yaml -s s.enc --encrypted-secrets -p --llm review-config\n  \
  sanitize app.log -s s.yaml --llm --extract-context --context-lines 15\n  \
  sanitize app.log -s s.yaml --llm /path/to/custom-template.txt"
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
    /// When combined with --secrets-file the tool runs a structured pass
    /// (replacing named fields) followed by a scanner pass (catching any
    /// remaining secrets). Without --secrets-file only the structured pass
    /// runs.
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

    /// Write a JSON report to the given path (or stderr if no path).
    /// The report includes file-level match counts, per-pattern stats,
    /// processing duration, and tool metadata. No original secret values
    /// are included.
    #[arg(short = 'r', long, value_name = "PATH")]
    report: Option<Option<PathBuf>>,

    /// Abort on the first error instead of skipping and continuing.
    #[arg(long)]
    strict: bool,

    /// Use HMAC-deterministic replacements so that identical inputs
    /// always produce identical outputs across runs (requires a stable
    /// seed derived from the secrets key).
    #[arg(short = 'd', long)]
    deterministic: bool,

    /// Disable the automatic save of values discovered by structured
    /// scanning. By default, when a profile is active, any field values
    /// found are appended to the secrets file (`--secrets-file`, or
    /// `sanitize-discovered.yaml` if none is given) as `kind: literal`
    /// entries so future runs can match them without re-running the profile.
    /// Pass this flag to suppress that write.
    #[arg(long)]
    no_update_secrets: bool,

    /// Process entries that appear to be binary data (default: skip).
    #[arg(long)]
    include_binary: bool,

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

    /// Number of worker threads. When multiple input files are provided,
    /// files are processed in parallel up to this limit. For a single
    /// archive input, entries are sanitized in parallel using the same
    /// budget. Defaults to the number of logical CPUs. Capped to the
    /// system's available parallelism.
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Chunk size in bytes for the streaming scanner (default: 1 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 1_048_576)]
    chunk_size: usize,

    /// Maximum number of unique replacement mappings to keep in memory.
    /// Guards against memory exhaustion when inputs contain huge numbers
    /// of unique matches.  Use 0 for unlimited (not recommended).
    #[arg(long, value_name = "N", default_value_t = 10_000_000)]
    max_mappings: usize,

    /// Maximum structured file size in bytes. Files exceeding this limit
    /// fall back to streaming scanner instead of structured processing.
    /// Prevents unbounded memory usage from large structured files (F-03 fix).
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_STRUCTURED_FILE_SIZE)]
    max_structured_size: u64,

    /// Maximum nesting depth for recursive archive processing.
    /// Nested archives (e.g. a .tar.gz inside a .zip) are extracted and
    /// sanitized recursively up to this depth. Exceeding the limit is an
    /// error. Maximum allowed value is 10 (each level may buffer up to
    /// 256 MiB).
    #[arg(long, value_name = "N", default_value_t = DEFAULT_ARCHIVE_DEPTH)]
    max_archive_depth: u32,

    /// Log output format: "human" (default) or "json" (for SIEM ingestion).
    #[arg(long, value_name = "FMT", default_value = "human")]
    log_format: String,

    /// Progress display mode: auto (default), on, or off.
    #[arg(long, value_enum, value_name = "MODE")]
    progress: Option<ProgressMode>,

    /// Disable live progress output.
    #[arg(long)]
    no_progress: bool,

    /// Minimum interval between live progress refreshes.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_PROGRESS_INTERVAL_MS)]
    progress_interval_ms: u64,

    /// After sanitizing, scan the output for error/warning/failure keywords
    /// and include matching lines with surrounding context in the JSON report.
    /// Requires `--report`.
    #[arg(long)]
    extract_context: bool,

    /// Number of lines of context to capture before and after each keyword
    /// match when `--extract-context` is set. Default: 10.
    #[arg(long, value_name = "N", default_value_t = 10)]
    context_lines: usize,

    /// Comma-separated list of keywords to search for when `--extract-context`
    /// is set. By default merged with the built-in list (error, failure,
    /// warning, warn, fatal, exception, critical). Pass
    /// `--context-keywords-only` to replace the defaults entirely.
    #[arg(long, value_name = "KEYWORDS", value_delimiter = ',')]
    context_keywords: Vec<String>,

    /// When set, `--context-keywords` replaces the built-in default keywords
    /// entirely instead of being merged with them. Has no effect if
    /// `--context-keywords` is not also provided.
    #[arg(long)]
    context_keywords_only: bool,

    /// Maximum number of keyword matches to capture per file when
    /// `--extract-context` is set. Matches beyond this limit are silently
    /// dropped and `truncated` is set to `true` in the report. Default: 50.
    #[arg(long, value_name = "N", default_value_t = 50)]
    max_context_matches: usize,

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

    /// Format sanitized output as an LLM-ready prompt on stdout instead of
    /// writing raw sanitized bytes. TEMPLATE chooses the instruction set:
    ///
    /// - `troubleshoot` (default) — root cause analysis of logs/errors
    /// - `review-config`          — configuration review and security audit
    ///
    /// TEMPLATE may also be a path to a custom template file.
    /// Combine with `--extract-context` to include notable log events.
    #[arg(long, value_name = "TEMPLATE", default_missing_value = "troubleshoot", num_args = 0..=1)]
    llm: Option<String>,

    /// Use built-in balanced detection patterns without requiring a secrets
    /// file. Covers the most common high-value secrets: API keys (AWS, GCP,
    /// GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, GitLab,
    /// SendGrid, npm), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM
    /// headers, password/secret key=value pairs, and credential URLs.
    ///
    /// Cannot be combined with `--secrets-file`.
    #[arg(long, conflicts_with = "secrets_file")]
    default: bool,

    /// Load built-in secrets patterns and structured field profiles for one or
    /// more applications. Comma-separated list of app names.
    ///
    /// Example: `--app gitlab`  `--app gitlab,nginx,postgresql`
    ///
    /// Can be combined with `--default` (app patterns are merged on top of the
    /// balanced base), `--secrets-file` (additive), and `--profile` (profiles
    /// are merged).
    ///
    /// Run `sanitize apps` to list available app names and descriptions.
    #[arg(long, value_delimiter = ',', value_name = "APPS")]
    app: Vec<String>,

    /// Allow a specific value through unchanged. Repeatable.
    ///
    /// Matched values are not replaced and not recorded in the mapping store,
    /// so they will also pass through in any other files processed in the same
    /// run. Supports exact strings and `*` glob patterns.
    ///
    /// Examples: `--allow localhost`  `--allow "*.internal"`  `--allow "192.168.1.*"`
    ///
    /// Allowlist entries can also be placed in the secrets file as
    /// `kind: allow` entries.
    #[arg(long = "allow", value_name = "PATTERN")]
    allow: Vec<String>,
}

impl Cli {
    fn effective_progress_mode(&self) -> ProgressMode {
        if let Some(mode) = self.progress {
            mode
        } else if self.no_progress {
            ProgressMode::Off
        } else {
            ProgressMode::Auto
        }
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

    /// Force input format (json, yaml, toml). Default: auto-detect from
    /// file extension.
    #[arg(long, value_parser = parse_format)]
    format: Option<SecretsFormat>,

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
    format: Option<SecretsFormat>,
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
    /// Allowlist patterns to test. Supports exact strings and * glob wildcards.
    /// Repeatable.
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
struct AppsArgs {
    #[command(subcommand)]
    command: Option<AppsSubCommand>,
}

#[derive(Subcommand, Debug)]
enum AppsSubCommand {
    /// Install a custom app bundle from local YAML files.
    ///
    /// Copies the supplied profile and/or secrets files into the user apps
    /// directory so the bundle is available via --app <name>.
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize apps add elastic --profile elastic.profile.yaml --secrets elastic.secrets.yaml\n  \
  sanitize apps add myapp --profile myapp.profile.yaml\n  \
  sanitize apps add myapp --secrets myapp.secrets.yaml --overwrite")]
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
    /// ~/.config/sanitize/apps/<name>/ so they can be customised. The local
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
struct AppsAddArgs {
    /// Name for the new app bundle (used with --app <name>).
    ///
    /// Only letters, digits, hyphens, and underscores are allowed.
    #[arg(value_name = "NAME")]
    name: String,

    /// Path to a profile YAML file (Vec<FileTypeProfile>).
    #[arg(long, value_name = "FILE")]
    profile: Option<PathBuf>,

    /// Path to a secrets YAML file (Vec<SecretEntry>).
    #[arg(long, value_name = "FILE")]
    secrets: Option<PathBuf>,

    /// Overwrite an existing custom app bundle with the same name.
    #[arg(long)]
    overwrite: bool,
}

#[derive(Parser, Debug)]
struct AppsRemoveArgs {
    /// Name of the custom app bundle to remove.
    #[arg(value_name = "NAME")]
    name: String,

    /// Confirm removal without an interactive prompt.
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Parser, Debug)]
struct AppsEditArgs {
    /// Name of the app bundle to edit.
    ///
    /// For built-in apps this copies the files to the user apps directory.
    /// For user-defined apps this prints the existing directory path.
    #[arg(value_name = "NAME")]
    name: String,
}

fn parse_template_preset(s: &str) -> Result<TemplatePreset, String> {
    match s {
        "generic" => Ok(TemplatePreset::Generic),
        "web" => Ok(TemplatePreset::Web),
        "k8s" | "kubernetes" => Ok(TemplatePreset::K8s),
        "database" | "db" => Ok(TemplatePreset::Database),
        "aws" => Ok(TemplatePreset::Aws),
        other => Err(format!(
            "unknown preset '{}' (choices: generic, web, k8s, database, aws)",
            other
        )),
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum TemplatePreset {
    Generic,
    Web,
    K8s,
    Database,
    Aws,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum GuidedPreset {
    Balanced,
    Aggressive,
    WebApp,
    Kubernetes,
    Database,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

/// Structured file formats to include in the generated profile.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum GuidedFormat {
    YamlJson,
    JsonLines,
    Env,
    Toml,
    IniConf,
}

#[derive(Clone, Debug)]
struct GuidedOptions {
    preset: GuidedPreset,
    domains: Vec<String>,
    providers: Vec<CloudProvider>,
    exclude_noise_ids: bool,
    formats: Vec<GuidedFormat>,
}

fn prompt_line(prompt: &str) -> Result<String, String> {
    let mut stdout = io::stdout();
    write!(stdout, "{}", prompt).map_err(|e| format!("failed to write prompt: {e}"))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush prompt: {e}"))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("failed to read input: {e}"))?;
    Ok(input.trim().to_string())
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool, String> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        let answer = prompt_line(&format!("{} {} ", prompt, suffix))?;
        if answer.is_empty() {
            return Ok(default_yes);
        }
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("Please answer 'y' or 'n'."),
        }
    }
}

fn sanitize_domain(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(trimmed)
}

fn prompt_domains() -> Result<Vec<String>, String> {
    let raw = prompt_line(
        "Company domains (comma-separated, up to 3, optional; e.g. corp.internal,example.com): ",
    )?;
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in raw.split(',') {
        let Some(domain) = sanitize_domain(item) else {
            return Err(format!("invalid domain value: '{}'", item.trim()));
        };
        if seen.insert(domain.clone()) {
            out.push(domain);
        }
    }

    if out.len() > 3 {
        return Err("please provide at most 3 domains".into());
    }
    Ok(out)
}

fn prompt_cloud_providers() -> Result<Vec<CloudProvider>, String> {
    eprintln!("Cloud providers in scope:");
    eprintln!("  1) AWS");
    eprintln!("  2) Azure");
    eprintln!("  3) GCP");
    eprintln!("  4) None");
    let raw = prompt_line("Select one or more (comma-separated numbers, default: 4): ")?;
    if raw.trim().is_empty() || raw.trim() == "4" {
        return Ok(vec![]);
    }

    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    for token in raw.split(',').map(|s| s.trim()) {
        let provider = match token {
            "1" => CloudProvider::Aws,
            "2" => CloudProvider::Azure,
            "3" => CloudProvider::Gcp,
            "4" => continue,
            _ => return Err(format!("invalid selection: '{token}'")),
        };
        if seen.insert(provider) {
            selected.push(provider);
        }
    }
    Ok(selected)
}

const ALL_FORMATS: &[GuidedFormat] = &[
    GuidedFormat::YamlJson,
    GuidedFormat::JsonLines,
    GuidedFormat::Env,
    GuidedFormat::Toml,
    GuidedFormat::IniConf,
];

fn prompt_formats() -> Result<Vec<GuidedFormat>, String> {
    eprintln!("Structured file formats to include in profile (controls field-level redaction):");
    eprintln!("  1) YAML / JSON    — k8s manifests, docker-compose, app configs");
    eprintln!("  2) JSON Lines     — NDJSON structured logs (.jsonl, .ndjson)");
    eprintln!("  3) .env files     — twelve-factor app secrets, CI variables");
    eprintln!("  4) TOML           — Rust, Hugo, and other TOML configs");
    eprintln!("  5) INI / conf     — system services, databases, legacy apps");
    eprintln!("  6) All of the above (default)");
    eprintln!("  7) None           — secrets file only, no profile");
    let raw = prompt_line("Select one or more (comma-separated, default: 6): ")?;

    if raw.trim().is_empty() || raw.trim() == "6" {
        return Ok(ALL_FORMATS.to_vec());
    }
    if raw.trim() == "7" {
        return Ok(vec![]);
    }

    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    for token in raw.split(',').map(|s| s.trim()) {
        let fmt = match token {
            "1" => GuidedFormat::YamlJson,
            "2" => GuidedFormat::JsonLines,
            "3" => GuidedFormat::Env,
            "4" => GuidedFormat::Toml,
            "5" => GuidedFormat::IniConf,
            "6" => return Ok(ALL_FORMATS.to_vec()),
            "7" => return Ok(vec![]),
            _ => return Err(format!("invalid selection: '{token}'")),
        };
        if seen.insert(fmt) {
            selected.push(fmt);
        }
    }
    Ok(selected)
}

fn make_regex_entry(pattern: &str, category: &str, label: &str) -> SecretEntry {
    SecretEntry {
        pattern: pattern.to_string(),
        kind: "regex".to_string(),
        category: category.to_string(),
        label: Some(label.to_string()),
        values: vec![],
    }
}

fn build_guided_entries(opts: &GuidedOptions) -> Vec<SecretEntry> {
    let mut entries = vec![
        // Emails — low false-positive, high value across all use cases.
        make_regex_entry(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "email",
            "email",
        ),
        // IPv4 addresses — pods, services, client IPs in logs.
        make_regex_entry(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ipv4", "ipv4"),
        // IPv6 — full form: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        make_regex_entry(
            r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b",
            "ipv6",
            "ipv6_full",
        ),
        // IPv6 — compressed form: fe80::1, ::1, 2001:db8::1, ::ffff:10.0.0.1
        make_regex_entry(
            r"\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{0,4}\b|\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b",
            "ipv6",
            "ipv6_compressed",
        ),
        // UUIDs — request IDs, pod IDs, resource IDs.
        make_regex_entry(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
            "uuid",
            "uuid",
        ),
        // JWTs — service account tokens, OIDC, bearer tokens.
        make_regex_entry(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            "jwt",
            "jwt",
        ),
        // URLs including query strings (may contain tokens or credentials).
        make_regex_entry(r#"https?://[^\s"'<>;]+"#, "url", "url"),
        // Non-HTTP URLs with embedded credentials: postgres://user:pass@host, redis://:pass@host.
        make_regex_entry(
            r#"[a-z][a-z0-9+.-]+://[^:@\s]{1,128}:[^@\s]{1,128}@[^\s"'<>]+"#,
            "url",
            "credential_url",
        ),
        // PEM / private key headers — appears in certs, k8s secrets, CI vars.
        // Near-zero false positives.
        make_regex_entry(
            r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----",
            "auth_token",
            "private_key_header",
        ),
        // Generic secret key=value in any text format.
        // Matches: api_key=..., client_secret: ..., access_token: ..., etc.
        make_regex_entry(
            r#"(?i)(?:api_key|api_secret|access_token|client_secret|private_key|secret_key|auth_key|signing_key|jwt_secret|jwt_key)[\s:="']+[A-Za-z0-9._~+/=-]{16,}"#,
            "auth_token",
            "secret_kv",
        ),
        // Password in key=value / YAML / env form (broader than db_password).
        make_regex_entry(
            r#"(?i)(?:password|passwd|pwd)[\s:="']+[^\s"']{6,}"#,
            "custom:password",
            "password_kv",
        ),
        // File paths that expose usernames (/home/alice, /Users/alice).
        make_regex_entry(
            r"/(?:home|Users)/[A-Za-z0-9_.-]+",
            "file_path",
            "user_home_path",
        ),
        // Docker / OCI image digests (sha256:...) — exact 64-char hex after prefix.
        make_regex_entry(r"\bsha256:[a-f0-9]{64}\b", "container_id", "image_digest"),
        // MAC addresses.
        make_regex_entry(
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            "mac_address",
            "mac_address",
        ),
        // GitHub tokens — personal access (ghp_), OAuth (gho_), user-to-server (ghu_),
        // server-to-server/Actions (ghs_), refresh (ghr_).
        make_regex_entry(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
            "auth_token",
            "github_token",
        ),
        make_regex_entry(
            r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
            "auth_token",
            "github_pat_fine_grained",
        ),
        // GCP API keys — AIza prefix, near-zero false positives.
        make_regex_entry(r"\bAIza[A-Za-z0-9_-]{35}\b", "auth_token", "gcp_api_key"),
        // AWS Access Key IDs — specific prefixes, near-zero false positives.
        // Applies to all workspace types; AWS credentials appear in any log or config.
        make_regex_entry(
            r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b",
            "auth_token",
            "aws_access_key_id",
        ),
        // OpenAI API keys — old format (sk-...) and new project-scoped (sk-proj-...).
        make_regex_entry(
            r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b",
            "auth_token",
            "openai_api_key",
        ),
        // Anthropic API keys.
        make_regex_entry(
            r"\bsk-ant-[A-Za-z0-9_-]{93,}\b",
            "auth_token",
            "anthropic_api_key",
        ),
        // Slack tokens — bot (xoxb-), user (xoxp-), workspace (xoxa-/xoxr-).
        make_regex_entry(
            r"\bxox[bpars]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b",
            "auth_token",
            "slack_token",
        ),
        // npm access tokens.
        make_regex_entry(r"\bnpm_[A-Za-z0-9]{36}\b", "auth_token", "npm_token"),
        // HuggingFace access tokens.
        make_regex_entry(r"\bhf_[A-Za-z0-9]{34}\b", "auth_token", "huggingface_token"),
        // Stripe secret/publishable/restricted keys — live and test.
        make_regex_entry(
            r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b",
            "auth_token",
            "stripe_key",
        ),
        // GitLab personal/project/group access tokens.
        make_regex_entry(r"\bglpat-[A-Za-z0-9_-]{20}\b", "auth_token", "gitlab_token"),
        // SendGrid API keys — two-segment dot-separated format.
        make_regex_entry(
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
            "auth_token",
            "sendgrid_api_key",
        ),
        // Twilio Account SIDs — AC prefix + 32 hex chars.
        make_regex_entry(r"\bAC[a-f0-9]{32}\b", "auth_token", "twilio_account_sid"),
    ];

    // Hostname regex is intentionally NOT in the base set — it matches any
    // dotted word (log.level, db.name, fmt.Println) and creates too much noise
    // in application logs. User-specified domain literals are added below,
    // and cloud-specific host patterns are added per-provider.
    // Enable it explicitly with the Aggressive preset.
    if matches!(opts.preset, GuidedPreset::Aggressive) {
        entries.push(make_regex_entry(
            r"\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.){2,}(?:[a-zA-Z]{2,63})\b",
            "hostname",
            "hostname",
        ));
        // Short container IDs (docker ps short form — 12 hex chars).
        // Aggressive-only because bare 12-hex-char strings appear frequently
        // in hex color codes, version hashes, and other non-container contexts.
        entries.push(make_regex_entry(
            r"\b[a-f0-9]{12}\b",
            "container_id",
            "container_id_short",
        ));
    }

    if matches!(
        opts.preset,
        GuidedPreset::Aggressive
            | GuidedPreset::WebApp
            | GuidedPreset::Kubernetes
            | GuidedPreset::Database
    ) {
        // Catches "Bearer <token>" regardless of surrounding context, including
        // "Authorization: Bearer <token>" HTTP headers.
        entries.push(make_regex_entry(
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b",
            "auth_token",
            "bearer_token",
        ));
        // Catches "authorization: <direct_value>" in configs/env where the value
        // is not prefixed with "Bearer".
        entries.push(make_regex_entry(
            r#"(?i)\bauthorization[\s:="']+[A-Za-z0-9._~+/=-]{16,}\b"#,
            "auth_token",
            "authorization_kv",
        ));
        // 32-char minimum filters most legitimate log identifiers (class names,
        // method names, log fields) while still catching real tokens. 20 chars
        // was too low and fired on common words and identifiers in stack traces.
        entries.push(make_regex_entry(
            r"\b[A-Za-z0-9_\-]{32,}\b",
            "custom:high_entropy_token",
            "high_entropy_token",
        ));
    }

    // Web-app specific: session cookies, OAuth tokens, refresh tokens.
    if matches!(opts.preset, GuidedPreset::WebApp) {
        entries.push(make_regex_entry(
            r"(?i)\bsess(?:ion)?[_-]?(?:id|token|key)[\s:=]+[A-Za-z0-9._~+/=-]{8,}\b",
            "auth_token",
            "session_id",
        ));
        entries.push(make_regex_entry(
            r"(?i)(?:refresh|access)[_-]?token[\s:=]+[A-Za-z0-9._~+/=-]{16,}",
            "auth_token",
            "oauth_token",
        ));
    }

    // Kubernetes specific: service account tokens, namespaces.
    if matches!(opts.preset, GuidedPreset::Kubernetes) {
        entries.push(make_regex_entry(
            r"(?i)token[\s:]+[A-Za-z0-9._~+/=-]{20,}",
            "auth_token",
            "k8s_token",
        ));
        entries.push(make_regex_entry(
            r"\bnamespace[:\s]+[a-z][a-z0-9-]{2,62}\b",
            "custom:k8s_namespace",
            "k8s_namespace",
        ));
        // Full SHA256 image digests in pod specs.
        entries.push(make_regex_entry(
            r"\b[a-f0-9]{64}\b",
            "container_id",
            "k8s_image_sha",
        ));
        // Short container IDs are common in kubectl/docker output; safe to
        // include here because K8s logs heavily feature these 12-char hashes.
        entries.push(make_regex_entry(
            r"\b[a-f0-9]{12}\b",
            "container_id",
            "container_id_short",
        ));
    }

    // Database specific: connection strings with embedded credentials.
    if matches!(opts.preset, GuidedPreset::Database) {
        entries.push(make_regex_entry(
            r#"(?i)(?:postgres|mysql|mongodb|redis|amqp|jdbc:[^:]+)://[^\s"'>]+"#,
            "url",
            "db_connection_string",
        ));
        entries.push(make_regex_entry(
            r#"(?i)(?:user|username|login)[\s:="']+[^\s"']{3,}"#,
            "name",
            "db_username",
        ));
    }

    // User-specified domain literals: email and hostname patterns anchored
    // to the domain, so they only fire on that org's addresses/hosts.
    for domain in &opts.domains {
        let escaped = regex::escape(domain);
        entries.push(make_regex_entry(
            &format!(r"[A-Za-z0-9._%+-]+@{}", escaped),
            "email",
            &format!("email_{}", domain.replace('.', "_")),
        ));
        entries.push(make_regex_entry(
            &format!(r"\b(?:[A-Za-z0-9-]+\.)*{}\b", escaped),
            "hostname",
            &format!("host_{}", domain.replace('.', "_")),
        ));
    }

    let has_aws = opts.providers.contains(&CloudProvider::Aws);
    let has_azure = opts.providers.contains(&CloudProvider::Azure);
    let has_gcp = opts.providers.contains(&CloudProvider::Gcp);

    if has_aws {
        entries.push(make_regex_entry(
            r"\barn:aws:[^\s]+\b",
            "aws_arn",
            "aws_arn",
        ));
        // Access key ID is already in the base set; the AWS provider block adds
        // the secret access key (too noisy without the KV context anchor).
        entries.push(make_regex_entry(
            r#"(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)[\s:="']+[A-Za-z0-9/+=]{40}\b"#,
            "auth_token",
            "aws_secret_access_key",
        ));
        // AWS account IDs in ARNs are already covered; standalone 12-digit
        // numbers are too noisy to match globally.
        entries.push(make_regex_entry(
            r"\bi-[0-9a-f]{8,17}\b",
            "container_id",
            "ec2_instance_id",
        ));
    }
    if has_azure {
        entries.push(make_regex_entry(
            r"/subscriptions/[0-9a-fA-F-]{8,}/resourceGroups/[^\s/]+(?:/providers/[^\s]+)?",
            "azure_resource_id",
            "azure_resource_id",
        ));
    }
    if has_gcp {
        entries.push(make_regex_entry(
            r"\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b",
            "custom:gcp_service_account",
            "gcp_service_account",
        ));
        entries.push(make_regex_entry(
            r"\bprojects/[a-z][a-z0-9-]{4,30}/[A-Za-z0-9/_-]+\b",
            "custom:gcp_resource",
            "gcp_resource",
        ));
    }

    if opts.exclude_noise_ids {
        entries.retain(|entry| entry.label.as_deref() != Some("high_entropy_token"));
    }

    // Common allow entries — included in every preset so the guided wizard
    // writes them to the output secrets file and users start with a sane baseline.
    entries.push(SecretEntry {
        pattern: String::new(),
        kind: "allow".into(),
        category: String::new(),
        label: Some("common_safe_values".into()),
        values: common_allow_patterns(),
    });

    entries
}

/// YAML comment header written at the top of every generated profile file.
const PROFILE_HEADER: &str = "\
# =============================================================================
# sanitize profile — structured field rules
# =============================================================================
#
# PURPOSE
#   This file tells sanitize which fields to redact inside structured files
#   (YAML, JSON, .env, TOML, INI, NDJSON) before sending to an LLM or
#   external service. It works alongside the secrets file: the secrets file
#   covers free-text patterns; this file covers key=value fields.
#
# HOW TO USE
#   sanitize input/ -s secrets.yaml --profile profile.yaml -o output/
#
# SAFE TO COMMIT
#   This file contains no secrets — only field name patterns. Commit it
#   alongside your sanitize secrets file (which you should encrypt).
#
# FIELD REFERENCE
#   processor   string   Required. Processor name: yaml, json, jsonl, env, toml, ini.
#   extensions  list     File extensions this profile applies to.
#   fields      list     Field rules: pattern (glob) + category.
#   options     map      Processor-specific options (e.g. compact, skip_invalid).
#
# WARNING: REVIEW OUTPUT BEFORE SENDING TO AN LLM.
#          Field rules redact exact keys — add regex patterns in secrets.yaml
#          to catch values that appear outside structured fields.
# =============================================================================
";

fn build_guided_profiles(opts: &GuidedOptions) -> Vec<FileTypeProfile> {
    // Shared sensitive field patterns applicable to most structured formats.
    let credential_fields = || -> Vec<FieldRule> {
        vec![
            FieldRule::new("*.password").with_category(Category::Custom("password".into())),
            FieldRule::new("*.passwd").with_category(Category::Custom("password".into())),
            FieldRule::new("*.secret").with_category(Category::AuthToken),
            FieldRule::new("*.secret_key").with_category(Category::AuthToken),
            FieldRule::new("*.api_key").with_category(Category::AuthToken),
            FieldRule::new("*.api_token").with_category(Category::AuthToken),
            FieldRule::new("*.access_token").with_category(Category::AuthToken),
            FieldRule::new("*.auth_token").with_category(Category::AuthToken),
            FieldRule::new("*.token").with_category(Category::AuthToken),
            FieldRule::new("*.private_key").with_category(Category::AuthToken),
            FieldRule::new("*.connection_string").with_category(Category::Url),
            FieldRule::new("*.database_url").with_category(Category::Url),
            FieldRule::new("*.dsn").with_category(Category::Url),
        ]
    };

    let mut profiles = Vec::new();

    for fmt in &opts.formats {
        match fmt {
            GuidedFormat::YamlJson => {
                // YAML — k8s manifests, Helm values, docker-compose, app configs.
                let mut yaml_fields = credential_fields();
                yaml_fields.push(FieldRule::new("*.email").with_category(Category::Email));
                yaml_fields.push(FieldRule::new("*.username").with_category(Category::Name));
                // k8s Secret objects store values under data.* (base64) and
                // stringData.* (plaintext).
                if matches!(opts.preset, GuidedPreset::Kubernetes) {
                    yaml_fields.push(FieldRule::new("data.*").with_category(Category::AuthToken));
                    yaml_fields
                        .push(FieldRule::new("stringData.*").with_category(Category::AuthToken));
                }
                profiles.push(
                    FileTypeProfile::new("yaml", yaml_fields)
                        .with_extension(".yaml")
                        .with_extension(".yml"),
                );

                // JSON — API responses, config files.
                let mut json_fields = credential_fields();
                json_fields.push(FieldRule::new("*.email").with_category(Category::Email));
                json_fields.push(FieldRule::new("*.username").with_category(Category::Name));
                json_fields.push(FieldRule::new("*.ip").with_category(Category::IpV4));
                profiles.push(
                    FileTypeProfile::new("json", json_fields)
                        .with_extension(".json")
                        .with_option("compact", "true"),
                );
            }

            GuidedFormat::JsonLines => {
                // NDJSON / JSON Lines — structured application and system logs.
                let mut fields = credential_fields();
                fields.push(FieldRule::new("*.email").with_category(Category::Email));
                fields.push(FieldRule::new("*.user").with_category(Category::Name));
                fields.push(FieldRule::new("*.username").with_category(Category::Name));
                fields.push(FieldRule::new("*.ip").with_category(Category::IpV4));
                fields.push(FieldRule::new("*.client_ip").with_category(Category::IpV4));
                fields.push(FieldRule::new("*.remote_addr").with_category(Category::IpV4));
                fields.push(FieldRule::new("*.host").with_category(Category::Hostname));
                profiles.push(
                    FileTypeProfile::new("jsonl", fields)
                        .with_extension(".jsonl")
                        .with_extension(".ndjson")
                        // skip_invalid passes non-JSON lines (plain-text
                        // interleaved with structured log lines) through
                        // unchanged rather than failing.
                        .with_option("skip_invalid", "true"),
                );
            }

            GuidedFormat::Env => {
                // .env files — twelve-factor app secrets and CI variables.
                let fields = vec![
                    FieldRule::new("*_PASSWORD").with_category(Category::Custom("password".into())),
                    FieldRule::new("*_PASSWD").with_category(Category::Custom("password".into())),
                    FieldRule::new("*_SECRET").with_category(Category::AuthToken),
                    FieldRule::new("*_KEY").with_category(Category::AuthToken),
                    FieldRule::new("*_TOKEN").with_category(Category::AuthToken),
                    FieldRule::new("*_DSN").with_category(Category::Url),
                    FieldRule::new("*_URL").with_category(Category::Url),
                    FieldRule::new("DATABASE_URL").with_category(Category::Url),
                    FieldRule::new("REDIS_URL").with_category(Category::Url),
                    FieldRule::new("*_EMAIL").with_category(Category::Email),
                    FieldRule::new("*_USER").with_category(Category::Name),
                    FieldRule::new("*_USERNAME").with_category(Category::Name),
                ];
                profiles.push(FileTypeProfile::new("env", fields).with_extension(".env"));
            }

            GuidedFormat::Toml => {
                let mut fields = credential_fields();
                fields.push(FieldRule::new("*.email").with_category(Category::Email));
                fields.push(FieldRule::new("*.username").with_category(Category::Name));
                profiles.push(FileTypeProfile::new("toml", fields).with_extension(".toml"));
            }

            GuidedFormat::IniConf => {
                let fields = vec![
                    FieldRule::new("*.password").with_category(Category::Custom("password".into())),
                    FieldRule::new("*.passwd").with_category(Category::Custom("password".into())),
                    FieldRule::new("*.secret").with_category(Category::AuthToken),
                    FieldRule::new("*.token").with_category(Category::AuthToken),
                    FieldRule::new("*.api_key").with_category(Category::AuthToken),
                    FieldRule::new("*.email").with_category(Category::Email),
                    FieldRule::new("*.username").with_category(Category::Name),
                    FieldRule::new("*.user").with_category(Category::Name),
                ];
                profiles.push(
                    FileTypeProfile::new("ini", fields)
                        .with_extension(".ini")
                        .with_extension(".conf")
                        .with_extension(".cfg"),
                );
            }
        }
    }

    profiles
}

// ---------------------------------------------------------------------------
// Template subcommand
// ---------------------------------------------------------------------------

/// YAML comment header printed at the top of every generated template.
const TEMPLATE_HEADER: &str = "\
# =============================================================================
# sanitize secrets template
# =============================================================================
#
# PURPOSE
#   This file tells sanitize which patterns to detect and replace before
#   you send logs, configs, or other data to an LLM or external service.
#
# RELIABILITY FIRST
#   Every replacement preserves the original byte length so structured
#   formats (JSON, YAML, TOML, …) remain parseable after sanitization.
#   Run `sanitize --force-text` to bypass structured processing entirely.
#
# HOW TO USE
#   1. Edit this file to add your own patterns and literals.
#   2. Encrypt: sanitize encrypt this-file.yaml this-file.yaml.enc
#   3. Sanitize: sanitize input.log -s this-file.yaml.enc -o output.log
#
# FIELD REFERENCE
#   pattern   string  Required. Regex or literal to match.
#   kind      string  \"regex\" (default) or \"literal\".
#   category  string  Controls the replacement style. See docs/categories.md.
#   label     string  Optional. Human-readable name shown in reports.
#
# WARNING: REVIEW OUTPUT BEFORE SENDING TO AN LLM.
#          No automated tool catches everything — always spot-check.
# =============================================================================
";

fn template_body_generic() -> &'static str {
    r#"secrets:
  # --- Tokens & credentials ---
  - pattern: '(?i)\b(?:bearer|token|api[_-]?key|secret)[\s:=]+[A-Za-z0-9._~+/=-]{16,}\b'
    kind: regex
    category: auth_token
    label: auth_token_context

  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: jwt

  # --- Network identifiers ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: ipv4

  - pattern: '\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b'
    kind: regex
    category: ipv6
    label: ipv6

  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: hostname

  - pattern: 'https?://[^\s"''<>]+'
    kind: regex
    category: url
    label: url

  # --- Identifiers ---
  - pattern: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
    kind: regex
    category: uuid
    label: uuid

  - pattern: '\b[a-f0-9]{12,64}\b'
    kind: regex
    category: container_id
    label: container_id

  # --- Add your own literals below ---
  # - pattern: 'my-internal-hostname.corp.example.com'
  #   kind: literal
  #   category: hostname
  #   label: corp_hostname
"#
}

fn template_body_web() -> &'static str {
    r#"secrets:
  # --- JWTs and session tokens ---
  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: jwt

  - pattern: '(?i)\bsess(?:ion)?[_-]?(?:id|token|key)[\s:=]+[A-Za-z0-9._~+/=-]{8,}\b'
    kind: regex
    category: auth_token
    label: session_id

  - pattern: '(?i)(?:refresh|access)[_-]?token[\s:=]+[A-Za-z0-9._~+/=-]{16,}'
    kind: regex
    category: auth_token
    label: oauth_token

  - pattern: '(?i)\b(?:bearer|authorization)[\s:]+[A-Za-z0-9._~+/=-]{16,}\b'
    kind: regex
    category: auth_token
    label: bearer_token

  # --- User identifiers ---
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: client_ip

  # --- URLs (may contain query params with tokens) ---
  - pattern: 'https?://[^\s"''<>]+'
    kind: regex
    category: url
    label: url

  # --- Add domain-specific literals ---
  # - pattern: 'users.myapp.com'
  #   kind: literal
  #   category: hostname
  #   label: app_domain
"#
}

fn template_body_k8s() -> &'static str {
    r#"secrets:
  # --- Service account tokens (base64, JWT) ---
  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: k8s_service_account_jwt

  - pattern: '(?i)token[\s:]+[A-Za-z0-9._~+/=-]{20,}'
    kind: regex
    category: auth_token
    label: k8s_token

  # --- Namespace and pod names ---
  - pattern: '\bnamespace[\s:]+[a-z][a-z0-9-]{2,62}\b'
    kind: regex
    category: custom:k8s_namespace
    label: k8s_namespace

  # --- IPs assigned to pods and services ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: pod_or_svc_ip

  # --- Cluster hostnames / DNS names ---
  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: k8s_dns

  # --- UUIDs (pod IDs, request IDs, etc.) ---
  - pattern: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
    kind: regex
    category: uuid
    label: uid

  # --- Docker / container image digests ---
  - pattern: '\b[a-f0-9]{64}\b'
    kind: regex
    category: container_id
    label: image_digest

  # --- Add your cluster name as a literal ---
  # - pattern: 'prod-cluster-1'
  #   kind: literal
  #   category: hostname
  #   label: cluster_name
"#
}

fn template_body_database() -> &'static str {
    r#"secrets:
  # --- Connection strings (contain embedded credentials) ---
  - pattern: '(?i)(?:postgres|mysql|mongodb|redis|amqp|jdbc:[^:]+)://[^\s"''>]+'
    kind: regex
    category: url
    label: db_connection_string

  # --- Inline passwords / secrets ---
  - pattern: '(?i)(?:password|passwd|pwd)[\s:=]+[^\s"'']{6,}'
    kind: regex
    category: custom:db_password
    label: db_password

  - pattern: '(?i)(?:user|username|login)[\s:=]+[^\s"'']{3,}'
    kind: regex
    category: name
    label: db_username

  # --- Host / IP for database servers ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: db_host_ip

  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: db_hostname

  # --- TLS certificate fingerprints / hashes ---
  - pattern: '\b[a-f0-9]{40}\b'
    kind: regex
    category: container_id
    label: cert_fingerprint

  # --- Add database-specific literals ---
  # - pattern: 'prod-db.internal.example.com'
  #   kind: literal
  #   category: hostname
  #   label: prod_db_host
"#
}

fn template_body_aws() -> &'static str {
    r#"secrets:
  # --- AWS access key IDs ---
  - pattern: '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'
    kind: regex
    category: auth_token
    label: aws_access_key_id

  # --- ARNs (may reveal account IDs, resource names) ---
  - pattern: '\barn:aws:[^\s]+'
    kind: regex
    category: aws_arn
    label: aws_arn

  # --- AWS account IDs (12-digit numbers in ARNs or standalone) ---
  - pattern: '\b\d{12}\b'
    kind: regex
    category: custom:aws_account_id
    label: aws_account_id

  # --- S3 bucket names and keys in URLs ---
  - pattern: 'https://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[^\s"''<>]+'
    kind: regex
    category: url
    label: s3_url

  # --- EC2 / ECS instance IDs ---
  - pattern: '\bi-[0-9a-f]{8,17}\b'
    kind: regex
    category: container_id
    label: ec2_instance_id

  # --- IPs for EC2 instances ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: ec2_ip

  # --- Emails in IAM roles, SES, etc. ---
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  # --- Add your AWS account ID as a literal for exact matching ---
  # - pattern: '123456789012'
  #   kind: literal
  #   category: custom:aws_account_id
  #   label: my_account_id
"#
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
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
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

fn validate_app_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("app name cannot be empty".into());
    }
    if !name.chars().next().unwrap().is_ascii_alphanumeric() {
        return Err(format!(
            "app name '{name}' must start with a letter or digit"
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
    {
        return Err(format!(
            "app name '{name}' contains invalid character '{bad}'; \
             only letters, digits, hyphens, and underscores are allowed"
        ));
    }
    Ok(())
}

fn run_apps(args: &AppsArgs) -> Result<(), (String, i32)> {
    match &args.command {
        None => run_apps_list(),
        Some(AppsSubCommand::Add(a)) => run_apps_add(a),
        Some(AppsSubCommand::Remove(a)) => run_apps_remove(a),
        Some(AppsSubCommand::Edit(a)) => run_apps_edit(a),
        Some(AppsSubCommand::Dir) => run_apps_dir(),
    }
}

fn run_apps_list() -> Result<(), (String, i32)> {
    let overridden: std::collections::HashSet<String> = user_apps_dir()
        .filter(|d| d.is_dir())
        .map(|d| {
            fs::read_dir(&d)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();

    println!("Built-in app bundles (use with --app <name>):\n");
    for app in BUILTIN_APPS {
        if overridden.contains(app.name) {
            println!(
                "  {:<18} {} (overridden by user copy)",
                app.name, app.description
            );
        } else {
            println!("  {:<18} {}", app.name, app.description);
        }
    }

    let apps_dir = user_apps_dir();
    let dir_display = apps_dir
        .as_ref()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "~/.config/sanitize/apps".into());

    if let Some(ref dir) = apps_dir {
        if dir.is_dir() {
            let mut user_apps: Vec<(String, String)> = fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                        .map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            let desc = read_app_description(&e.path());
                            (name, desc)
                        })
                        .collect()
                })
                .unwrap_or_default();
            user_apps.sort_by(|a, b| a.0.cmp(&b.0));

            if !user_apps.is_empty() {
                println!("\nUser-defined apps (from {dir_display}):\n");
                for (name, desc) in &user_apps {
                    if desc.is_empty() {
                        println!("  {name}");
                    } else {
                        println!("  {:<18} {}", name, desc);
                    }
                }
            }
        }
    }

    println!("\nCombine multiple apps:  sanitize file.zip --app gitlab,nginx,postgresql");
    println!(
        "Manage custom apps:     sanitize apps edit <name>        # copy built-in for editing"
    );
    println!("                        sanitize apps add <name> --profile p.yaml --secrets s.yaml");
    println!("                        sanitize apps remove <name> --yes");
    println!("                        sanitize apps dir");
    Ok(())
}

fn run_apps_add(args: &AppsAddArgs) -> Result<(), (String, i32)> {
    validate_app_name(&args.name).map_err(|e| (e, 1))?;

    if args.profile.is_none() && args.secrets.is_none() {
        return Err((
            "at least one of --profile or --secrets must be provided".into(),
            1,
        ));
    }

    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    let target_dir = apps_dir.join(&args.name);

    if target_dir.exists() && !args.overwrite {
        return Err((
            format!(
                "app '{}' already exists at {}.\nUse --overwrite to replace it.",
                args.name,
                target_dir.display()
            ),
            1,
        ));
    }

    // Validate files parse correctly before touching the filesystem.
    if let Some(ref path) = args.profile {
        let _profiles: Vec<FileTypeProfile> =
            parse_yaml_file(path).map_err(|e| (format!("--profile: {e}"), 1))?;
    }
    if let Some(ref path) = args.secrets {
        let _secrets: Vec<SecretEntry> =
            parse_yaml_file(path).map_err(|e| (format!("--secrets: {e}"), 1))?;
    }

    fs::create_dir_all(&target_dir)
        .map_err(|e| (format!("failed to create {}: {e}", target_dir.display()), 1))?;

    if let Some(ref src) = args.profile {
        let dst = target_dir.join("profile.yaml");
        fs::copy(src, &dst).map_err(|e| {
            (
                format!("failed to copy profile to {}: {e}", dst.display()),
                1,
            )
        })?;
    }
    if let Some(ref src) = args.secrets {
        let dst = target_dir.join("secrets.yaml");
        fs::copy(src, &dst).map_err(|e| {
            (
                format!("failed to copy secrets to {}: {e}", dst.display()),
                1,
            )
        })?;
    }

    println!("Installed app '{}' → {}", args.name, target_dir.display());
    if args.profile.is_some() {
        println!("  profile.yaml  ✓");
    }
    if args.secrets.is_some() {
        println!("  secrets.yaml  ✓");
    }
    println!("\nUse it with:  sanitize <file> --app {}", args.name);
    Ok(())
}

fn run_apps_remove(args: &AppsRemoveArgs) -> Result<(), (String, i32)> {
    validate_app_name(&args.name).map_err(|e| (e, 1))?;

    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    let target_dir = apps_dir.join(&args.name);

    // Only a user copy (in the apps dir) can be removed.  Refuse when the
    // name is a built-in AND there is no user copy to revert.
    if !target_dir.is_dir() {
        if BUILTIN_APPS.iter().any(|a| a.name == args.name.as_str()) {
            return Err((
                format!(
                    "'{}' is a built-in app — nothing to remove.\n\
                     Use `sanitize apps edit {}` first to create a local copy.",
                    args.name, args.name
                ),
                1,
            ));
        }
        return Err((
            format!(
                "no custom app '{}' found at {}",
                args.name,
                target_dir.display()
            ),
            1,
        ));
    }

    if !args.yes {
        return Err((
            format!(
                "this will permanently delete {}\nRe-run with --yes to confirm.",
                target_dir.display()
            ),
            1,
        ));
    }

    fs::remove_dir_all(&target_dir)
        .map_err(|e| (format!("failed to remove {}: {e}", target_dir.display()), 1))?;

    let is_builtin = BUILTIN_APPS.iter().any(|a| a.name == args.name.as_str());
    println!("Removed app '{}'  ({})", args.name, target_dir.display());
    if is_builtin {
        println!("Built-in '{}' is now active again.", args.name);
    }
    Ok(())
}

fn run_apps_edit(args: &AppsEditArgs) -> Result<(), (String, i32)> {
    validate_app_name(&args.name).map_err(|e| (e, 1))?;

    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    let target_dir = apps_dir.join(&args.name);

    // Already a user-defined app — just show the path.
    if target_dir.is_dir() {
        println!("'{}' is already in your user apps directory:", args.name);
        println!("  {}", target_dir.display());
        for file in &["profile.yaml", "secrets.yaml"] {
            let p = target_dir.join(file);
            if p.exists() {
                println!("  {}", p.display());
            }
        }
        println!("\nEdits here already override the built-in.");
        println!("To revert:  sanitize apps remove {} --yes", args.name);
        return Ok(());
    }

    // Must be a built-in.
    let entry = BUILTIN_APPS
        .iter()
        .find(|a| a.name == args.name.as_str())
        .ok_or_else(|| {
            format!(
                "unknown app '{}'. Built-in apps: {}.",
                args.name,
                builtin_app_names().join(", ")
            )
        })
        .map_err(|e| (e, 1))?;

    fs::create_dir_all(&target_dir)
        .map_err(|e| (format!("failed to create {}: {e}", target_dir.display()), 1))?;

    let mut wrote: Vec<PathBuf> = vec![];

    if let Some(yaml) = entry.profile_yaml {
        let dst = target_dir.join("profile.yaml");
        fs::write(&dst, yaml)
            .map_err(|e| (format!("failed to write {}: {e}", dst.display()), 1))?;
        wrote.push(dst);
    }
    if let Some(yaml) = entry.secrets_yaml {
        let dst = target_dir.join("secrets.yaml");
        fs::write(&dst, yaml)
            .map_err(|e| (format!("failed to write {}: {e}", dst.display()), 1))?;
        wrote.push(dst);
    }

    println!(
        "Copied built-in '{}' to your user apps directory:",
        args.name
    );
    for path in &wrote {
        println!("  {}", path.display());
    }
    println!(
        "\nEdits here override the built-in — use --app {} as usual.",
        args.name
    );
    println!("To revert:  sanitize apps remove {} --yes", args.name);

    Ok(())
}

fn run_apps_dir() -> Result<(), (String, i32)> {
    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    println!("{}", apps_dir.display());

    if !apps_dir.exists() {
        eprintln!(
            "note: directory does not exist yet — it will be created automatically by `sanitize apps add`"
        );
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
        command: None,
        input: vec![input],
        output,
        secrets_file: Some(secrets_for_run),
        profile: profile_path,
        password: false,
        password_file: None,
        encrypted_secrets: !run_unencrypted,
        format: None,
        dry_run,
        fail_on_match: false,
        report: None,
        strict: false,
        deterministic,
        no_update_secrets: false,
        include_binary: false,
        force_text: false,
        threads: None,
        chunk_size: 1_048_576,
        max_mappings: 10_000_000,
        max_structured_size: DEFAULT_MAX_STRUCTURED_FILE_SIZE,
        max_archive_depth: DEFAULT_ARCHIVE_DEPTH,
        log_format: "human".to_string(),
        progress: None,
        no_progress: false,
        progress_interval_ms: DEFAULT_PROGRESS_INTERVAL_MS,
        extract_context: false,
        context_lines: DEFAULT_CONTEXT_LINES,
        context_keywords: Vec::new(),
        context_keywords_only: false,
        max_context_matches: DEFAULT_MAX_MATCHES,
        context_case_sensitive: false,
        strip_values: false,
        strip_delimiter: "=".to_string(),
        strip_comment_prefix: "#".to_string(),
        llm: None,
        default: false,
        app: vec![],
        allow: vec![],
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
                use zeroize::Zeroizing;
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
fn common_allow_patterns() -> Vec<String> {
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
        // Null UUID — commonly used as a placeholder or uninitialized resource ID.
        "00000000-0000-0000-0000-000000000000".into(),
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
// Built-in app bundles
// ---------------------------------------------------------------------------
//
// Each app lives in  src/bin/apps/<name>/
//   secrets.yaml  — Vec<SecretEntry>  (optional; omit when the app has none)
//   profile.yaml  — Vec<FileTypeProfile> (optional)
//
// User-defined apps follow the same two-file convention in a directory
// specified by the SANITIZE_APPS_DIR environment variable, falling back to
// ~/.config/sanitize/apps  (XDG-compatible).
//
// The first YAML comment line (# ...) in either file is shown as the
// description in  `sanitize apps`.

/// Compiled content loaded from an app bundle directory.
struct AppBundle {
    secrets: Vec<SecretEntry>,
    profiles: Vec<FileTypeProfile>,
}

struct BuiltinApp {
    name: &'static str,
    description: &'static str,
    /// Vec<SecretEntry> YAML; None when the app has no unique secrets patterns.
    secrets_yaml: Option<&'static str>,
    /// Vec<FileTypeProfile> YAML; None when the app has no profile rules.
    profile_yaml: Option<&'static str>,
}

const BUILTIN_APPS: &[BuiltinApp] = &[
    BuiltinApp {
        name: "ansible",
        description: "Ansible — group_vars, host_vars, vault credentials",
        secrets_yaml: Some(include_str!("../../apps/ansible/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/ansible/profile.yaml")),
    },
    BuiltinApp {
        name: "aws-cli",
        description: "AWS CLI — ~/.aws/credentials, ~/.aws/config access keys",
        secrets_yaml: Some(include_str!("../../apps/aws-cli/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/aws-cli/profile.yaml")),
    },
    BuiltinApp {
        name: "circleci",
        description: "CircleCI — .circleci/config.yml job/step environment variables, docker auth",
        secrets_yaml: Some(include_str!("../../apps/circleci/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/circleci/profile.yaml")),
    },
    BuiltinApp {
        name: "django",
        description: "Django — .env files, SECRET_KEY, database credentials, third-party API keys",
        secrets_yaml: Some(include_str!("../../apps/django/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/django/profile.yaml")),
    },
    BuiltinApp {
        name: "docker-compose",
        description: "Docker Compose — compose.yml environment variables, image credentials",
        secrets_yaml: Some(include_str!("../../apps/docker-compose/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/docker-compose/profile.yaml")),
    },
    BuiltinApp {
        name: "elasticsearch",
        description: "Elasticsearch — elasticsearch.yml, Kibana/Logstash credentials",
        secrets_yaml: Some(include_str!("../../apps/elasticsearch/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/elasticsearch/profile.yaml")),
    },
    BuiltinApp {
        name: "fstab",
        description: "fstab — /etc/fstab CIFS/SMB credentials, NFS and iSCSI server addresses",
        secrets_yaml: Some(include_str!("../../apps/fstab/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/fstab/profile.yaml")),
    },
    BuiltinApp {
        name: "github-actions",
        description: "GitHub Actions — workflow env vars, step inputs, container registry credentials",
        secrets_yaml: Some(include_str!("../../apps/github-actions/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/github-actions/profile.yaml")),
    },
    BuiltinApp {
        name: "gitlab",
        description: "GitLab — CI/CD logs, runner output, .gitlab-ci.yml variables",
        secrets_yaml: Some(include_str!("../../apps/gitlab/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/gitlab/profile.yaml")),
    },
    BuiltinApp {
        name: "grafana",
        description: "Grafana — grafana.ini admin credentials, provisioning datasource secrets",
        secrets_yaml: Some(include_str!("../../apps/grafana/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/grafana/profile.yaml")),
    },
    BuiltinApp {
        name: "heroku",
        description: "Heroku — app.json env values, add-on credentials (Postgres, Redis, SendGrid, Mailgun, Cloudinary…)",
        secrets_yaml: Some(include_str!("../../apps/heroku/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/heroku/profile.yaml")),
    },
    BuiltinApp {
        name: "kubernetes",
        description: "Kubernetes — kubeconfig credentials, Secret manifests, Helm values",
        secrets_yaml: Some(include_str!("../../apps/kubernetes/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/kubernetes/profile.yaml")),
    },
    BuiltinApp {
        name: "laravel",
        description: "Laravel — .env files, APP_KEY, Pusher, Passport, Stripe secrets",
        secrets_yaml: Some(include_str!("../../apps/laravel/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/laravel/profile.yaml")),
    },
    BuiltinApp {
        name: "mongodb",
        description: "MongoDB — mongod.conf TLS passwords, .env connection strings",
        secrets_yaml: Some(include_str!("../../apps/mongodb/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/mongodb/profile.yaml")),
    },
    BuiltinApp {
        name: "mysql",
        description: "MySQL / MariaDB — my.cnf credentials, .env DATABASE_URL",
        secrets_yaml: Some(include_str!("../../apps/mysql/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/mysql/profile.yaml")),
    },
    BuiltinApp {
        name: "nginx",
        description: "Nginx — nginx.conf virtual hosts, proxy upstreams, access/error logs",
        secrets_yaml: Some(include_str!("../../apps/nginx/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/nginx/profile.yaml")),
    },
    BuiltinApp {
        name: "postgresql",
        description: "PostgreSQL — postgresql.conf, connection strings, pg logs",
        secrets_yaml: Some(include_str!("../../apps/postgresql/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/postgresql/profile.yaml")),
    },
    BuiltinApp {
        name: "rails",
        description: "Ruby on Rails — database.yml, .env, config/secrets.yml",
        secrets_yaml: Some(include_str!("../../apps/rails/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/rails/profile.yaml")),
    },
    BuiltinApp {
        name: "redis",
        description: "Redis — redis.conf requirepass/masterauth, .env credentials",
        secrets_yaml: Some(include_str!("../../apps/redis/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/redis/profile.yaml")),
    },
    BuiltinApp {
        name: "splunk",
        description: "Splunk — outputs.conf, inputs.conf, authentication.conf credentials",
        secrets_yaml: Some(include_str!("../../apps/splunk/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/splunk/profile.yaml")),
    },
    BuiltinApp {
        name: "spring-boot",
        description:
            "Spring Boot — application.yml, application.properties, datasource credentials",
        secrets_yaml: Some(include_str!("../../apps/spring-boot/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/spring-boot/profile.yaml")),
    },
    BuiltinApp {
        name: "terraform",
        description: "Terraform — *.tfvars variable files, terraform.tfstate sensitive outputs",
        secrets_yaml: Some(include_str!("../../apps/terraform/secrets.yaml")),
        profile_yaml: Some(include_str!("../../apps/terraform/profile.yaml")),
    },
];

/// Return a sorted list of all built-in app names.
fn builtin_app_names() -> Vec<&'static str> {
    BUILTIN_APPS.iter().map(|a| a.name).collect()
}

/// Resolve the user-defined apps directory.
///
/// Checks `SANITIZE_APPS_DIR` first, then falls back to
/// `~/.config/sanitize/apps` (XDG base directory convention).
fn user_apps_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("SANITIZE_APPS_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    std::env::var("HOME").ok().map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("sanitize")
            .join("apps")
    })
}

/// Parse a YAML file as `T`, returning a clear error on failure.
fn parse_yaml_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_yaml_ng::from_str(&content)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

/// Read the first `# description` comment line from a YAML file, if present.
fn read_app_description(app_dir: &Path) -> String {
    for filename in &["secrets.yaml", "profile.yaml"] {
        let path = app_dir.join(filename);
        if let Ok(content) = fs::read_to_string(&path) {
            if let Some(line) = content.lines().next() {
                if let Some(rest) = line.strip_prefix('#') {
                    let desc = rest.trim().to_string();
                    if !desc.is_empty() {
                        return desc;
                    }
                }
            }
        }
    }
    String::new()
}

/// Load an app bundle by name.
///
/// Resolution order:
///   1. User apps directory (`SANITIZE_APPS_DIR` or `~/.config/sanitize/apps/<name>/`)
///   2. Built-in apps embedded in the binary
fn load_app_bundle(name: &str) -> Result<AppBundle, String> {
    // 1. User-defined app takes precedence over built-in.
    if let Some(apps_dir) = user_apps_dir() {
        let app_dir = apps_dir.join(name);
        if app_dir.is_dir() {
            let secrets_path = app_dir.join("secrets.yaml");
            let profile_path = app_dir.join("profile.yaml");

            let secrets: Vec<SecretEntry> = if secrets_path.exists() {
                parse_yaml_file(&secrets_path)?
            } else {
                vec![]
            };
            let profiles: Vec<FileTypeProfile> = if profile_path.exists() {
                parse_yaml_file(&profile_path)?
            } else {
                vec![]
            };
            return Ok(AppBundle { secrets, profiles });
        }
    }

    // 2. Built-in app.
    let entry = BUILTIN_APPS
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| {
            format!(
                "unknown app '{}'. Built-in apps: {}. \
                 Add a custom app at $SANITIZE_APPS_DIR/{} (secrets.yaml / profile.yaml).",
                name,
                builtin_app_names().join(", "),
                name,
            )
        })?;

    let secrets: Vec<SecretEntry> = match entry.secrets_yaml {
        Some(yaml) => serde_yaml_ng::from_str(yaml)
            .map_err(|e| format!("failed to parse built-in secrets for '{}': {e}", name))?,
        None => vec![],
    };
    let profiles: Vec<FileTypeProfile> = match entry.profile_yaml {
        Some(yaml) => serde_yaml_ng::from_str(yaml)
            .map_err(|e| format!("failed to parse built-in profile for '{}': {e}", name))?,
        None => vec![],
    };

    Ok(AppBundle { secrets, profiles })
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
        if s.len() < 4 {
            continue; // too short — high false-positive risk
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
fn init_logging(log_format: &str) {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_env("SANITIZE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

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

#[cfg(not(unix))]
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

fn plan_input_targets(cli: &Cli) -> Result<Vec<InputTarget>, String> {
    let explicit_stdin_count = cli.input.iter().filter(|p| p.as_os_str() == "-").count();

    if explicit_stdin_count > 1 {
        return Err("stdin marker '-' can be specified at most once".into());
    }

    // Implicit stdin: no positional inputs at all, OR stdin is a pipe/redirect
    // with no explicit '-' marker (e.g. `cat file | sanitize other.json`).
    let has_piped_stdin = explicit_stdin_count == 0 && stdin_is_pipe();

    let mut units = Vec::new();

    // No file inputs — stdin only. Output goes to --output if given, else stdout.
    if cli.input.is_empty() {
        units.push(InputTarget::Stdin {
            output: cli.output.clone(),
        });
        return Ok(units);
    }

    let input_count = cli.input.len();
    let multi_input = input_count > 1;
    let mut used_outputs = HashSet::new();

    let output_dir = if multi_input {
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

    for input in &cli.input {
        if input.as_os_str() == "-" {
            let stdin_output = if multi_input {
                Some(
                    output_dir
                        .as_ref()
                        .map(|d| d.join("input-sanitized.txt"))
                        .unwrap_or_else(|| PathBuf::from("input-sanitized.txt")),
                )
            } else {
                cli.output
                    .clone()
                    .or_else(|| Some(PathBuf::from("input-sanitized.txt")))
            };
            units.push(InputTarget::Stdin {
                output: stdin_output,
            });
            continue;
        }

        let format = ArchiveFormat::from_path(&input.to_string_lossy());
        let default_out = match format {
            Some(fmt) => default_archive_output(input, fmt),
            None => default_plain_output(input),
        };

        let planned_out = if multi_input {
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
        } else if let Some(out) = &cli.output {
            out.clone()
        } else {
            default_out
        };

        units.push(InputTarget::File {
            input: input.clone(),
            output: planned_out,
        });
    }

    // Piped stdin alongside file inputs: add a stdin target last so it is
    // processed after all file targets (profile discovery benefits from this).
    if has_piped_stdin {
        let stdin_out = output_dir
            .as_ref()
            .map(|d| d.join("input-sanitized.txt"))
            .unwrap_or_else(|| PathBuf::from("input-sanitized.txt"));
        units.push(InputTarget::Stdin {
            output: Some(stdin_out),
        });
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
            return Err(format!("input file not found: {}", input.display()));
        }
        if !input.is_file() {
            return Err(format!(
                "input path is not a regular file: {}",
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

    if !matches!(cli.log_format.as_str(), "human" | "json") {
        return Err(format!(
            "invalid --log-format '{}': must be 'human' or 'json'",
            cli.log_format
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
        // --llm writes the prompt to stdout; --output would be silently ignored.
        if cli.output.is_some() {
            return Err(
                "--llm and --output cannot be combined: --llm writes the formatted \
                 prompt to stdout and the sanitized bytes are not written to a file.\n\
                 Remove --output, or omit --llm to write sanitized output normally."
                    .into(),
            );
        }

        // --dry-run produces no output, so the prompt content would be empty.
        if cli.dry_run {
            return Err(
                "--llm and --dry-run cannot be combined: dry-run does not produce \
                 sanitized output, so the generated prompt would have no content."
                    .into(),
            );
        }

        // Validate custom template path early so the error surfaces before processing.
        let known = matches!(template.as_str(), "troubleshoot" | "review-config");
        if !known {
            let path = Path::new(template);
            if !path.exists() {
                return Err(format!(
                    "--llm template '{}' is not a known template name and the path \
                     does not exist.\n\
                     Built-in templates: troubleshoot, review-config\n\
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

// ---------------------------------------------------------------------------
// Processing helpers
// ---------------------------------------------------------------------------

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
                report_builder,
                progress,
                llm_collector,
            );
        }

        let store_len_before = store.len();
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
                Some(Ok(structured_bytes)) => {
                    // Double-pass: run the streaming scanner on the structured
                    // output to catch anything missed by field-rule gaps.
                    let (output_bytes, scan_stats) = scanner_fallback(scanner, &structured_bytes)?;
                    let method = format!("structured+scan:{ext}");
                    let structured_reps = store.len().saturating_sub(store_len_before) as u64;
                    let total_replacements = structured_reps + scan_stats.replacements_applied;
                    if total_replacements > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = report_builder {
                        let stats = ScanStats {
                            matches_found: total_replacements,
                            replacements_applied: total_replacements,
                            bytes_processed: input_bytes.len() as u64,
                            bytes_output: output_bytes.len() as u64,
                            ..Default::default()
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

            let (output_bytes, stats) = scanner_fallback(scanner, &input_bytes)?;
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
        report_builder,
        progress,
        llm_collector,
    )
}

/// Stream stdin through the scanner, writing to output (stdout or file).
fn process_stdin_streaming<R: io::Read>(
    reader: BufReader<R>,
    output_path: Option<&Path>,
    cli: &Cli,
    scanner: &Arc<StreamScanner>,
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
    llm_collector: Option<&LlmCollector>,
) -> Result<bool, String> {
    let label = if cli.dry_run {
        "Scanning stdin (dry-run)"
    } else {
        "Scanning stdin"
    };

    with_progress_scope(progress, label, |progress| {
        let mut had_matches = false;

        if cli.dry_run {
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    io::sink(),
                    None,
                    make_scan_callback(progress.clone(), label),
                )
                .map_err(|e| format!("scanner error: {e}"))?;
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
            info!(
                matches = stats.matches_found,
                replacements = stats.replacements_applied,
                "dry-run complete"
            );
            return Ok(had_matches);
        }

        // Buffer when extract-context or llm are active; streaming otherwise.
        let needs_buffer = cli.extract_context || llm_collector.is_some();

        if let Some(out_path) = output_path {
            if needs_buffer {
                let mut buf: Vec<u8> = Vec::new();
                let stats = scanner
                    .scan_reader_with_progress(
                        reader,
                        &mut buf,
                        None,
                        make_scan_callback(progress.clone(), label),
                    )
                    .map_err(|e| format!("scanner error: {e}"))?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
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

                let stats = scanner
                    .scan_reader_with_progress(
                        reader,
                        &mut atomic_writer,
                        None,
                        make_scan_callback(progress.clone(), label),
                    )
                    .map_err(|e| format!("scanner error: {e}"))?;

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
                    rb.record_file(FileReport::from_scan_stats(
                        "<stdin>".to_string(),
                        &stats,
                        "scanner",
                    ));
                }
            }
        } else if needs_buffer {
            let mut buf: Vec<u8> = Vec::new();
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    &mut buf,
                    None,
                    make_scan_callback(progress.clone(), label),
                )
                .map_err(|e| format!("scanner error: {e}"))?;
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
            maybe_extract_context(&buf, "<stdin>", cli, report_builder);
            if let Some(c) = llm_collector {
                maybe_collect_for_llm(&buf, "<stdin>", Some(c));
            } else {
                let stdout = io::stdout();
                stdout
                    .lock()
                    .write_all(&buf)
                    .map_err(|e| format!("failed to write to stdout: {e}"))?;
            }
        } else {
            let stdout = io::stdout();
            let writer = BufWriter::new(stdout.lock());
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    writer,
                    None,
                    make_scan_callback(progress.clone(), label),
                )
                .map_err(|e| format!("scanner error: {e}"))?;
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
                    let stats = per_file_scanner
                        .scan_reader_with_progress(
                            reader,
                            io::sink(),
                            Some(sz),
                            make_scan_callback(progress.clone(), &progress_label),
                        )
                        .map_err(|e| format!("scan error: {e}"))?;
                    if stats.matches_found > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = report_builder {
                        rb.record_file(FileReport::from_scan_stats(
                            input.display().to_string(),
                            &stats,
                            &method,
                        ));
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
                        let stats = per_file_scanner
                            .scan_reader_with_progress(
                                reader,
                                &mut buf,
                                Some(sz),
                                make_scan_callback(progress.clone(), &progress_label),
                            )
                            .map_err(|e| format!("scanner error: {e}"))?;
                        if is_interrupted() {
                            return Err("interrupted — partial output discarded".into());
                        }
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = report_builder {
                            rb.record_file(FileReport::from_scan_stats(
                                input.display().to_string(),
                                &stats,
                                &method,
                            ));
                        }
                        maybe_extract_context(
                            &buf,
                            &input.display().to_string(),
                            cli,
                            report_builder,
                        );
                        maybe_collect_for_llm(&buf, &input.display().to_string(), llm_opt.as_ref());
                    } else {
                        let reader = BufReader::new(
                            fs::File::open(input)
                                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                        );
                        let mut atomic_writer = AtomicFileWriter::new(out_path)
                            .map_err(|e| format!("failed to create output: {e}"))?;
                        let stats = per_file_scanner
                            .scan_reader_with_progress(
                                reader,
                                &mut atomic_writer,
                                Some(sz),
                                make_scan_callback(progress.clone(), &progress_label),
                            )
                            .map_err(|e| format!("scanner error: {e}"))?;
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
                            rb.record_file(FileReport::from_scan_stats(
                                input.display().to_string(),
                                &stats,
                                &method,
                            ));
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
                        let stats = per_file_scanner
                            .scan_reader_with_progress(
                                reader,
                                &mut buf,
                                Some(sz),
                                make_scan_callback(progress.clone(), &progress_label),
                            )
                            .map_err(|e| format!("scanner error: {e}"))?;
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = report_builder {
                            rb.record_file(FileReport::from_scan_stats(
                                input.display().to_string(),
                                &stats,
                                &method,
                            ));
                        }
                        maybe_extract_context(
                            &buf,
                            &input.display().to_string(),
                            cli,
                            report_builder,
                        );
                        if llm_opt.is_some() {
                            maybe_collect_for_llm(
                                &buf,
                                &input.display().to_string(),
                                llm_opt.as_ref(),
                            );
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
                        let stats = per_file_scanner
                            .scan_reader_with_progress(
                                reader,
                                writer,
                                Some(sz),
                                make_scan_callback(progress.clone(), &progress_label),
                            )
                            .map_err(|e| format!("scanner error: {e}"))?;
                        if stats.matches_found > 0 {
                            had_matches = true;
                        }
                        if let Some(rb) = report_builder {
                            rb.record_file(FileReport::from_scan_stats(
                                input.display().to_string(),
                                &stats,
                                &method,
                            ));
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
                        let stats = ScanStats {
                            matches_found: replacements,
                            replacements_applied: replacements,
                            bytes_processed: input_bytes.len() as u64,
                            bytes_output: output_bytes.len() as u64,
                            ..Default::default()
                        };
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

    if cli.dry_run {
        let label = format!("Scanning {} (dry-run)", input.display());
        let progress_label = label.clone();
        with_progress_scope(progress, &label, move |progress| {
            let reader = BufReader::new(
                fs::File::open(input)
                    .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
            );
            let progress_for_scan = progress.clone();
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    io::sink(),
                    Some(file_size(input)?),
                    make_scan_callback(progress_for_scan, &progress_label),
                )
                .map_err(|e| format!("scan error: {e}"))?;
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    input.display().to_string(),
                    &stats,
                    method,
                ));
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
        with_progress_scope(progress, &label, move |progress| {
            if llm_opt.is_some() {
                // Buffer for LLM collection instead of writing to file.
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut buf: Vec<u8> = Vec::new();
                let progress_for_scan = progress.clone();
                let stats = scanner
                    .scan_reader_with_progress(
                        reader,
                        &mut buf,
                        Some(file_size(input)?),
                        make_scan_callback(progress_for_scan, &progress_label),
                    )
                    .map_err(|e| format!("scanner error: {e}"))?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(FileReport::from_scan_stats(
                        input.display().to_string(),
                        &stats,
                        method,
                    ));
                }
                maybe_extract_context(&buf, &input.display().to_string(), cli, report_builder);
                maybe_collect_for_llm(&buf, &input.display().to_string(), llm_opt.as_ref());
            } else {
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(out_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;

                let progress_for_scan = progress.clone();
                let stats = scanner
                    .scan_reader_with_progress(
                        reader,
                        &mut atomic_writer,
                        Some(file_size(input)?),
                        make_scan_callback(progress_for_scan, &progress_label),
                    )
                    .map_err(|e| format!("scanner error: {e}"))?;

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
                    rb.record_file(FileReport::from_scan_stats(
                        input.display().to_string(),
                        &stats,
                        method,
                    ));
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
        with_progress_scope(progress, &label, move |progress| {
            let sz = file_size(input)?;
            let needs_buffer =
                (cli.extract_context || llm_opt.is_some()) && sz <= MAX_CONTEXT_BUFFER_BYTES;
            if needs_buffer {
                let reader = BufReader::new(
                    fs::File::open(input)
                        .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
                );
                let mut buf: Vec<u8> = Vec::new();
                let progress_for_scan = progress.clone();
                let stats = scanner
                    .scan_reader_with_progress(
                        reader,
                        &mut buf,
                        Some(sz),
                        make_scan_callback(progress_for_scan, &progress_label),
                    )
                    .map_err(|e| format!("scanner error: {e}"))?;
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(FileReport::from_scan_stats(
                        input.display().to_string(),
                        &stats,
                        method,
                    ));
                }
                maybe_extract_context(&buf, &input.display().to_string(), cli, report_builder);
                if llm_opt.is_some() {
                    maybe_collect_for_llm(&buf, &input.display().to_string(), llm_opt.as_ref());
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
                let stats = scanner
                    .scan_reader_with_progress(
                        reader,
                        writer,
                        Some(sz),
                        make_scan_callback(progress_for_scan, &progress_label),
                    )
                    .map_err(|e| format!("scanner error: {e}"))?;
                if stats.matches_found > 0 {
                    had_matches = true;
                }
                if let Some(rb) = report_builder {
                    rb.record_file(FileReport::from_scan_stats(
                        input.display().to_string(),
                        &stats,
                        method,
                    ));
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
/// - Values shorter than 4 bytes are skipped (too short → high false-positive risk).
/// - Entries whose `pattern` already appears in the file are skipped.
fn save_discovered_secrets(
    store: &Arc<MappingStore>,
    path: &Path,
) -> std::result::Result<usize, String> {
    // Collect discovered (original, category) pairs from the store.
    let mut new_entries: Vec<SecretEntry> = store
        .iter()
        .filter(|(_, original, _)| original.len() >= 4)
        .map(|(category, original, _)| SecretEntry {
            pattern: original.to_string(),
            kind: "literal".into(),
            category: category.to_string(),
            label: Some("discovered".into()),
            values: vec![],
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

/// Fall back to the streaming scanner for raw bytes.
fn scanner_fallback(scanner: &StreamScanner, input: &[u8]) -> Result<(Vec<u8>, ScanStats), String> {
    let (output, stats) = scanner
        .scan_bytes(input)
        .map_err(|e| format!("scanner error: {e}"))?;
    Ok((output, stats))
}

/// A `Write + Seek` sink that discards all bytes.
///
/// Used for dry-run zip processing: `ZipWriter` requires `Seek` to finalize
/// the central directory, so `io::sink()` alone is insufficient.
struct NullSeekWriter {
    pos: u64,
    len: u64,
}

impl io::Write for NullSeekWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len() as u64;
        self.pos += n;
        if self.pos > self.len {
            self.len = self.pos;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Seek for NullSeekWriter {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        let new_pos: u64 = match from {
            io::SeekFrom::Start(n) => n,
            io::SeekFrom::Current(n) => {
                if n >= 0 {
                    self.pos.saturating_add(n as u64)
                } else {
                    self.pos.saturating_sub((-n) as u64)
                }
            }
            io::SeekFrom::End(n) => {
                if n >= 0 {
                    self.len.saturating_add(n as u64)
                } else {
                    self.len.saturating_sub((-n) as u64)
                }
            }
        };
        self.pos = new_pos;
        if new_pos > self.len {
            self.len = new_pos;
        }
        Ok(self.pos)
    }
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
        config = if cli.context_keywords_only {
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
        .format
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
    if let Some(fmt) = args.format {
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
    init_logging(&cli.log_format);

    // --- dispatch subcommands -----------------------------------------------
    match &cli.command {
        Some(SubCommand::Encrypt(args)) => return run_encrypt(args),
        Some(SubCommand::Decrypt(args)) => return run_decrypt(args),
        Some(SubCommand::Apps(args)) => return run_apps(args),
        Some(SubCommand::Guided) => return run_guided(),
        Some(SubCommand::Template(args)) => return run_template(args),
        Some(SubCommand::AllowTest(args)) => return run_allow_test(args),
        None => {} // fall through to default sanitize mode
    }

    run_sanitize(cli, None, filter_map)
}

fn run_sanitize(
    cli: Cli,
    pre_resolved_password: Option<Zeroizing<String>>,
    filter_map: HashMap<PathBuf, ArchiveFilter>,
) -> Result<(), (String, i32)> {
    // --- install signal handler (graceful shutdown) --------------------------
    if let Err(e) = ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }) {
        eprintln!("warning: failed to install signal handler: {e}");
    }

    // --- validate -----------------------------------------------------------
    validate_args(&cli).map_err(|e| (e, 1))?;

    let progress_mode = cli.effective_progress_mode();
    let progress_context = ProgressContext::detect(&cli.log_format);
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
    // All sources (--secrets-file, --default, --app) contribute to a single
    // Vec<ScanPattern> that is reused by both the initial scanner and the
    // Phase 2 augmented scanner (which appends profile-discovered literals).
    let mut base_patterns: Vec<ScanPattern> = vec![];
    // Allow patterns accumulate from secrets file + --allow CLI values and are
    // used to build the AllowlistMatcher before constructing the store.
    let mut all_allow_patterns: Vec<String> = cli.allow.clone();

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

    if let Some(ref raw_bytes) = secrets_raw_bytes {
        let (((patterns, warnings), allow_from_secrets), was_encrypted) =
            sanitize_engine::secrets::load_secrets_auto(
                raw_bytes,
                effective_password.as_ref().map(|s| s.as_str()),
                None,
                !cli.encrypted_secrets,
            )
            .map_err(|e| (format!("failed to load secrets: {e}"), 1))?;

        let secrets_display = cli
            .secrets_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
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
    }

    // 2. From --default or implicitly when --app is used without --secrets-file.
    //    --app is designed to be zero-setup: users don't need to also add
    //    --default to get email, IP, JWT, and common token patterns.
    //    Common allow patterns are added here — before the allowlist is built —
    //    so the store is aware of them from the first matched value.
    let load_defaults =
        cli.default || (!cli.app.is_empty() && cli.secrets_file.is_none()) || cli.profile.is_some();
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
        if cli.default {
            info!(
                patterns = default_patterns.len(),
                "loaded built-in balanced patterns (--default)"
            );
        } else {
            info!(
                patterns = default_patterns.len(),
                "loaded built-in balanced patterns (auto, via --app)"
            );
        }
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
        warn!("no --secrets-file, --default, or --app provided; only structured processing will apply");
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
    let profiles: Vec<sanitize_engine::processor::FileTypeProfile> = {
        let mut merged = app_profiles;
        merged.extend(file_profiles);
        merged
    };

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
    // Force report building when --llm is active so we can include the
    // sanitization summary in the generated prompt.
    let report_enabled = cli.report.is_some() || cli.llm.is_some();
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
            secrets_file: if cli.default {
                Some("<built-in:balanced>".into())
            } else {
                cli.secrets_file.as_ref().map(|p| p.display().to_string())
            },
        }))
    } else {
        None
    };

    // --- LLM collector (only allocated when --llm is active) ----------------
    let llm_collector: Option<LlmCollector> = if cli.llm.is_some() {
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
    // When a profile is active, append literal values found by structured scanning to
    // the secrets file by default so future runs can match them everywhere they appear.
    // Pass --no-update-secrets to suppress this write.
    if !cli.no_update_secrets && !profiles.is_empty() {
        let save_path = cli
            .secrets_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("sanitize-discovered.yaml"));
        match save_discovered_secrets(&store, &save_path) {
            Ok(0) => {}
            Ok(n) => info!(
                path = %save_path.display(),
                added = n,
                "saved discovered literals to secrets file"
            ),
            Err(e) => warn!("could not save discovered secrets: {e}"),
        }
    }

    // --- write report / LLM prompt -----------------------------------------
    if let Some(builder) = report_builder {
        let report = builder.finish();

        // --- LLM prompt (--llm) ---
        if let Some(ref template_name) = cli.llm {
            let entries = llm_collector
                .as_ref()
                .and_then(|c| c.lock().ok())
                .map(|g| g.clone())
                .unwrap_or_default();
            let prompt =
                format_llm_prompt(template_name, &entries, Some(&report)).map_err(|e| (e, 1))?;
            let stdout = io::stdout();
            stdout
                .lock()
                .write_all(prompt.as_bytes())
                .map_err(|e| (format!("failed to write LLM prompt: {e}"), 1))?;
        }

        // --- JSON report (--report) ---
        if cli.report.is_some() {
            let json = report
                .to_json_pretty()
                .map_err(|e| (format!("failed to serialize report: {e}"), 1))?;

            match cli.report.as_ref().unwrap() {
                Some(path) if path.to_string_lossy() == "-" => {
                    println!("{json}");
                }
                Some(path) => {
                    atomic_write(path, json.as_bytes()).map_err(|e| {
                        (
                            format!("failed to write report to {}: {e}", path.display()),
                            1,
                        )
                    })?;
                    info!(report = %path.display(), "report written");
                }
                None => {
                    eprintln!("{json}");
                }
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
        cli.log_format = "xml".into();
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
    fn validate_args_rejects_llm_with_output() {
        let mut cli = real_file_cli();
        cli.llm = Some("troubleshoot".into());
        cli.output = Some(PathBuf::from("/tmp/out.txt"));
        let err = validate_args(&cli).unwrap_err();
        assert!(
            err.contains("--llm and --output cannot be combined"),
            "got: {err}"
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
        for name in ["troubleshoot", "review-config"] {
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
    fn cli_parses_default_flag() {
        let cli = Cli::try_parse_from(["sanitize", "--default", "app.log"]).unwrap();
        assert!(cli.default);
        assert!(cli.secrets_file.is_none());
    }

    #[test]
    fn cli_default_conflicts_with_secrets_file() {
        // clap enforces conflicts_with at parse time.
        let result = Cli::try_parse_from(["sanitize", "--default", "--secrets-file", "s.yaml"]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cannot be used with"),
            "expected conflict error, got: {msg}"
        );
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
}
