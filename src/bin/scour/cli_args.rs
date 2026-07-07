use crate::progress::ProgressMode;
use clap::{Parser, Subcommand, ValueEnum};
use scour_secrets::secrets::SecretsFormat;
use scour_secrets::{DEFAULT_ARCHIVE_DEPTH, DEFAULT_CONTEXT_LINES, DEFAULT_MAX_MATCHES};
use std::path::PathBuf;

pub(crate) const DEFAULT_MAX_STRUCTURED_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB
pub(crate) const DEFAULT_PROGRESS_INTERVAL_MS: u64 = 200;

// ---------------------------------------------------------------------------
// Report format
// ---------------------------------------------------------------------------

/// Output format for `--report`.
#[derive(Debug, Clone, PartialEq, Default, clap::ValueEnum)]
pub(crate) enum ReportFormat {
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
/// Use `scour-secrets encrypt` / `scour-secrets decrypt` to manage encrypted secrets
/// files, or omit the subcommand to sanitize data.
#[derive(Parser, Debug)]
#[command(
    name = "scour-secrets",
    version,
    about = "One-way data sanitization tool",
    long_about = "Deterministic one-way data sanitization tool.\n\n\
        Scans files and archives for sensitive data described in a secrets file \
        (plaintext by default) and replaces every match with a category-aware substitute.\n\
        Replacements are ONE-WAY — no mapping file is stored and there is no \
        restore mode.\n\n\
        Use `scour-secrets encrypt` / `scour-secrets decrypt` to manage encrypted secrets files.",
    after_help = "\
EXAMPLES:\n  \
  scour-secrets data.log -s secrets.yaml\n  \
  scour-secrets data.log -s secrets.yaml -o clean.log\n  \
  grep \"error\" log.txt | scour-secrets -s secrets.yaml\n\n  \
  # Encrypted secrets:\n  \
  scour-secrets data.log -s s.enc --encrypted-secrets -p\n  \
  SCOUR_SECRETS_PASSWORD=hunter2 scour-secrets data.log -s s.enc --encrypted-secrets\n\n  \
  # Extract notable log events into a report:\n  \
  scour-secrets app.log -s secrets.yaml --extract-context\n  \
  scour-secrets app.log -s secrets.yaml --extract-context --context-keywords timeout,oomkilled\n\n  \
  # LLM prompt (file inputs write sanitized files to disk + list paths in prompt):\n  \
  scour-secrets app.log -s secrets.yaml --llm | pbcopy\n  \
  scour-secrets nginx.conf --app nginx --llm review-security\n  \
  scour-secrets logs/ -s s.yaml --llm review-security --output /tmp/sanitized/\n\n  \
  # Strip values to generate a profile template:\n  \
  scour-secrets gitlab.rb --strip-values -o gitlab.rb.template\n\nDOCS:\n  \
  https://docs.rs/scour-secrets"
)]
pub(crate) struct Cli {
    /// Subcommand: encrypt, decrypt, or omit for default sanitize mode.
    #[command(subcommand)]
    pub(crate) command: Option<SubCommand>,

    /// Path(s) to files or archives to sanitize. When omitted, reads
    /// from stdin. Use "-" to include stdin alongside file paths.
    #[arg(value_name = "INPUT")]
    pub(crate) input: Vec<PathBuf>,

    /// Output path. For a single input stream, writes to this file.
    /// For multiple inputs, this is treated as an output directory.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,

    /// Path to a secrets file. Plaintext JSON / YAML / TOML files are
    /// loaded directly by default. Use `--encrypted-secrets` to decrypt
    /// an AES-256-GCM encrypted file.
    #[arg(short = 's', long = "secrets-file", value_name = "FILE")]
    pub(crate) secrets_file: Option<PathBuf>,

    /// File-type profile (JSON/YAML) for structured field sanitization. Requires --secrets-file.
    #[arg(long = "profile", value_name = "FILE")]
    pub(crate) profile: Option<PathBuf>,

    /// Interactive password prompt for `--encrypted-secrets` (masked input).
    #[arg(short = 'p', long)]
    pub(crate) password: bool,

    /// Read decryption password from a file (must be 0600/0400). Requires `--encrypted-secrets`.
    #[arg(short = 'P', long = "password-file", value_name = "FILE")]
    pub(crate) password_file: Option<PathBuf>,

    /// Treat the secrets file as AES-256-GCM encrypted. Requires a password via
    /// `-p`, `--password-file`, or `SCOUR_SECRETS_PASSWORD`.
    #[arg(long)]
    pub(crate) encrypted_secrets: bool,

    /// Force input format for stdin and for inputs that aren't otherwise
    /// typeable (e.g. an extensionless file). Required when reading structured
    /// data from stdin. A file whose own extension already maps to a structured
    /// format keeps that format, so this never forces an accompanying
    /// `.yaml`/`.csv`/… file to be misparsed as the stdin format.
    /// Values: text, json, jsonl, yaml, xml, csv, key-value, toml, env, ini, log.
    #[arg(short = 'f', long, value_name = "FMT")]
    pub(crate) format: Option<String>,

    /// Scan and report matches without writing output.
    #[arg(short = 'n', long)]
    pub(crate) dry_run: bool,

    /// Exit 2 if any matches are found. Useful in CI to fail on detected secrets.
    #[arg(long)]
    pub(crate) fail_on_match: bool,

    /// Write a report to PATH (auto-derived when omitted). See --report-format.
    #[arg(short = 'r', long, value_name = "PATH")]
    pub(crate) report: Option<Option<PathBuf>>,

    /// Report format: json (default), sarif, or html.
    #[arg(
        long,
        value_name = "FORMAT",
        default_value = "json",
        hide_possible_values = true
    )]
    pub(crate) report_format: ReportFormat,

    /// Abort on the first error instead of skipping and continuing.
    #[arg(long)]
    pub(crate) strict: bool,

    /// HMAC-deterministic replacements — identical inputs produce identical outputs across runs.
    #[arg(short = 'd', long)]
    pub(crate) deterministic: bool,

    /// File holding the deterministic seed salt (SHA-256-normalized, then used as
    /// the Argon2id seed salt).
    /// Overrides the per-install salt and the SCOUR_SECRETS_SEED_SALT env var. Share this
    /// file across machines to reproduce identical deterministic output for a team.
    #[arg(long, value_name = "PATH")]
    pub(crate) seed_salt_file: Option<PathBuf>,

    /// Draw each replacement's length independently of the original instead of
    /// preserving it. Output stays type-valid (a number stays digits, an email
    /// stays an email) but the length no longer leaks the original's length.
    /// Preserved substrings (email domain, file extension, ARN/Azure segments)
    /// are unaffected. Composes with `--deterministic`.
    #[arg(long)]
    pub(crate) randomize_length: bool,

    /// Suppress writing newly-discovered field values back to the secrets file.
    #[arg(long)]
    pub(crate) no_structured_handoff: bool,

    /// Disable automatic entropy-based flagging of sensitive-named fields (password, token, …).
    #[arg(long)]
    pub(crate) no_field_signal: bool,

    /// Do not add the built-in baseline detectors (email, IP, UUID, home path, common tokens).
    /// These are composed under the app/profile rules by default; pass this for app-only precision.
    #[arg(long)]
    pub(crate) no_baseline: bool,

    /// Process entries that appear to be binary data (default: skip).
    #[arg(long)]
    pub(crate) include_binary: bool,

    /// Walk hidden files/directories during directory input (VCS dirs always skipped).
    #[arg(long)]
    pub(crate) hidden: bool,

    /// Flag high-entropy tokens ≥ THRESHOLD bits/char (e.g. 4.5). Off by default.
    #[arg(long, value_name = "THRESHOLD")]
    pub(crate) entropy_threshold: Option<f64>,

    /// Exclude paths matching GLOB. Repeatable. Merged with `.scour-secrets.toml` excludes.
    #[arg(long, value_name = "GLOB", num_args = 1)]
    pub(crate) exclude_path: Vec<String>,

    /// Only process paths matching GLOB during directory walks. Exclusion wins on conflict.
    #[arg(long, value_name = "GLOB", num_args = 1)]
    pub(crate) include_path: Vec<String>,

    /// Skip structured processors; scan every byte with the streaming scanner only.
    #[arg(long)]
    pub(crate) force_text: bool,

    /// Worker thread count (default: logical CPU count).
    #[arg(long, value_name = "N")]
    pub(crate) threads: Option<usize>,

    /// Chunk size in bytes for the streaming scanner (default: 1 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 1_048_576, hide = true)]
    pub(crate) chunk_size: usize,

    /// Maximum number of unique replacement mappings to keep in memory.
    /// Guards against memory exhaustion when inputs contain huge numbers
    /// of unique matches.  Use 0 for unlimited (not recommended).
    #[arg(long, value_name = "N", default_value_t = 10_000_000, hide = true)]
    pub(crate) max_mappings: usize,

    /// Maximum structured file size in bytes. Files exceeding this limit
    /// fall back to streaming scanner instead of structured processing.
    /// Prevents unbounded memory usage from large structured files (F-03 fix).
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_STRUCTURED_FILE_SIZE, hide = true)]
    pub(crate) max_structured_size: u64,

    /// Maximum nesting depth for recursive archive processing.
    /// Nested archives (e.g. a .tar.gz inside a .zip) are extracted and
    /// sanitized recursively up to this depth. Exceeding the limit is an
    /// error. Maximum allowed value is 10 (each level may buffer up to
    /// 256 MiB).
    #[arg(long, value_name = "N", default_value_t = DEFAULT_ARCHIVE_DEPTH, hide = true)]
    pub(crate) max_archive_depth: u32,

    /// Log output format: "human" (default) or "json" (for SIEM ingestion).
    #[arg(long, value_name = "FMT")]
    pub(crate) log_format: Option<String>,

    /// Log level: off, error, warn (default), info, debug, or trace.
    /// Overrides SCOUR_SECRETS_LOG when both are set.
    #[arg(long, value_name = "LEVEL")]
    pub(crate) log_level: Option<String>,

    /// Progress display mode: auto (default), on, or off.
    #[arg(long, value_enum, value_name = "MODE")]
    pub(crate) progress: Option<ProgressMode>,

    /// Disable live progress output. Deprecated: use `--progress off` instead.
    #[arg(long, hide = true)]
    pub(crate) no_progress: bool,

    /// Suppress the post-run summary and all decorative stderr output.
    #[arg(long)]
    pub(crate) quiet: bool,

    /// Minimum interval between live progress refreshes.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_PROGRESS_INTERVAL_MS, hide = true)]
    pub(crate) progress_interval_ms: u64,

    /// Write per-file findings as NDJSON to PATH (stdout when omitted). Compatible with `jq` / SIEMs.
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "-")]
    pub(crate) findings: Option<PathBuf>,

    /// Extract error/warning lines with surrounding context into the report.
    #[arg(long)]
    pub(crate) extract_context: bool,

    /// Lines of context before and after each keyword match. Default: 10.
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub(crate) context_lines: usize,

    /// Extra keywords for `--extract-context` (comma-separated, merged with built-ins).
    #[arg(long, value_name = "KEYWORDS", value_delimiter = ',')]
    pub(crate) context_keywords: Vec<String>,

    /// Use only `--context-keywords`; replace the built-in keyword list entirely.
    #[arg(long)]
    pub(crate) context_keywords_replace: bool,

    /// Max keyword matches per file for `--extract-context` (default: 50).
    #[arg(long, value_name = "N", default_value_t = 50)]
    pub(crate) max_context_matches: usize,

    /// Max match locations recorded per file in the report (default: 500; 0 to disable).
    #[arg(long, value_name = "N", default_value_t = 500)]
    pub(crate) max_match_locations: usize,

    /// Case-sensitive keyword matching for `--extract-context` (default: case-insensitive).
    #[arg(long)]
    pub(crate) context_case_sensitive: bool,

    /// Emit only keys/structure (no values). Useful for generating profile templates.
    #[arg(long)]
    pub(crate) strip_values: bool,

    /// Key-value delimiter used by `--strip-values` (default: `=`).
    #[arg(
        long,
        value_name = "DELIM",
        default_value = "=",
        requires = "strip_values"
    )]
    pub(crate) strip_delimiter: String,

    /// Comment-line prefix used by `--strip-values` (default: `#`).
    #[arg(
        long,
        value_name = "PREFIX",
        default_value = "#",
        requires = "strip_values"
    )]
    pub(crate) strip_comment_prefix: String,

    /// Format sanitized output as an LLM-ready prompt on stdout.
    /// TEMPLATE: troubleshoot (default), review-config, review-security, or a path.
    /// File inputs write sanitized files to disk and list paths in the prompt.
    /// Stdin-only inputs embed content inline.
    #[arg(long, value_name = "TEMPLATE", default_missing_value = "troubleshoot", num_args = 0..=1)]
    pub(crate) llm: Option<String>,

    /// Send the --llm prompt to an OpenAI-compatible endpoint instead of printing to stdout.
    /// Requires --llm. Env: SCOUR_SECRETS_LLM_ENDPOINT.
    /// Example: http://localhost:11434/v1  (Ollama)
    #[arg(
        long,
        value_name = "URL",
        env = "SCOUR_SECRETS_LLM_ENDPOINT",
        requires = "llm"
    )]
    pub(crate) llm_endpoint: Option<String>,

    /// Model name for --llm-endpoint (e.g. phi4-mini, gpt-4o). Env: SCOUR_SECRETS_LLM_MODEL.
    #[arg(
        long,
        value_name = "MODEL",
        env = "SCOUR_SECRETS_LLM_MODEL",
        requires = "llm_endpoint"
    )]
    pub(crate) llm_model: Option<String>,

    /// API key for --llm-endpoint. Prefer SCOUR_SECRETS_LLM_KEY env var for real keys;
    /// passing the value as a flag exposes it in process listings (ps, /proc).
    /// Local models (Ollama, LM Studio) accept any non-empty value.
    #[arg(long, value_name = "KEY", env = "SCOUR_SECRETS_LLM_KEY")]
    pub(crate) llm_key: Option<String>,

    /// Load built-in patterns/profiles for an app (comma-separated). Run `scour-secrets apps` for names.
    #[arg(long, value_delimiter = ',', value_name = "APPS")]
    pub(crate) app: Vec<String>,

    /// Allow a value unchanged. Supports exact, glob (`*`), or `regex:` prefix. Repeatable.
    #[arg(long = "allow", value_name = "PATTERN")]
    pub(crate) allow: Vec<String>,

    /// Add one-off literal or regex patterns for this run only (comma-separated).
    /// Prefix with `regex:` for a regex pattern; bare values are treated as literals.
    /// To match a literal that contains a comma, repeat the flag: --quick a --quick b,c
    /// Replacements use the auth_token format (__SANITIZED_…__) regardless of value shape.
    /// Example: --quick "tok-abc123,regex:sk-[A-Za-z0-9]{40}"
    #[arg(long, value_delimiter = ',', value_name = "PATTERN")]
    pub(crate) quick: Vec<String>,
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
            seed_salt_file: None,
            randomize_length: false,
            no_structured_handoff: false,
            no_field_signal: false,
            no_baseline: false,
            include_binary: false,
            hidden: false,
            force_text: false,
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
            llm_endpoint: None,
            llm_model: None,
            llm_key: None,
            app: vec![],
            allow: vec![],
            quick: vec![],
            exclude_path: vec![],
            include_path: vec![],
            entropy_threshold: None,
        }
    }
}

impl Cli {
    pub(crate) fn effective_progress_mode(&self) -> ProgressMode {
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

    pub(crate) fn effective_log_format(&self) -> &str {
        self.log_format.as_deref().unwrap_or("human")
    }

    pub(crate) fn effective_log_level(&self) -> &str {
        self.log_level.as_deref().unwrap_or("warn")
    }
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub(crate) enum SubCommand {
    /// Encrypt a plaintext secrets file for use with the sanitizer.
    ///
    /// Uses AES-256-GCM authenticated encryption with a key derived via
    /// Argon2id (19 MiB memory, 2 passes).
    #[command(after_help = "\
EXAMPLES:\n  \
  scour-secrets encrypt secrets.json secrets.json.enc --password \"my-password\"\n  \
  SCOUR_SECRETS_PASSWORD=hunter2 scour-secrets encrypt secrets.yaml secrets.yaml.enc\n  \
  scour-secrets encrypt secrets.toml secrets.toml.enc  # interactive prompt")]
    Encrypt(EncryptArgs),

    /// Decrypt an encrypted secrets file back to plaintext.
    ///
    /// Useful for editing secrets before re-encrypting.
    #[command(after_help = "\
EXAMPLES:\n  \
  scour-secrets decrypt secrets.json.enc secrets.json --password \"my-password\"\n  \
  scour-secrets decrypt secrets.enc out.yaml --password-file /run/secrets/pw")]
    Decrypt(DecryptArgs),

    /// Manage app bundles: list, add, remove, or show the user apps directory.
    ///
    /// Run `scour-secrets apps` with no subcommand to list all available bundles.
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
  scour-secrets allow-test --allow '*.internal' db.internal github.com\n  \
  scour-secrets allow-test --allow localhost --allow '*.internal' --allow '192.168.1.*' db.internal 192.168.1.5 8.8.8.8\n  \
  scour-secrets allow-test --allow 'regex:^10\\.[0-9]+\\.[0-9]+\\.[0-9]+$' 10.0.0.1 192.168.1.1\n  \
  echo -e 'db.internal\\ngithub.com\\n192.168.1.5' | scour-secrets allow-test --allow '*.internal' --allow '192.168.1.*'\n  \
  scour-secrets allow-test --allow '*.internal' db.internal --json"
    )]
    AllowTest(AllowTestArgs),

    /// Generate a starter secrets-template YAML file for a given use case.
    ///
    /// Templates include commented-out examples and common patterns so
    /// support engineers, sysadmins, and DevOps teams can get started
    /// quickly before sending logs or configs to an LLM.
    #[command(after_help = "\
PRESETS\n  \
  balanced    All well-known token formats; matches the runtime defaults (default)\n  \
  aggressive  Balanced + entropy detection + broad token patterns\n  \
  generic     Minimal template: tokens, emails, IPs, hostnames\n  \
  web         Web-app logs: JWTs, sessions, emails, URLs\n  \
  k8s         Kubernetes configs: service-accounts, tokens, namespaces\n  \
  database    Database configs: passwords, connection strings, usernames\n  \
  aws         AWS: access keys, ARNs, account IDs\n\n\
EXAMPLES:\n  \
  scour-secrets template                     # balanced → secrets.template.balanced.yaml\n  \
  scour-secrets template aggressive          # aggressive preset\n  \
  scour-secrets template k8s -o k8s.yaml    # k8s preset with custom output path")]
    Template(TemplateArgs),

    /// Install a git hook that scans (or sanitizes) staged files before each commit.
    ///
    /// Detects husky and falls back to a raw .git/hooks/ script. Use --global
    /// to apply to every repository on this machine.
    ///
    /// The installed script is plain POSIX sh and can be inspected or edited
    /// directly. Remove it with --remove or by deleting the hook file.
    ///
    /// Run `scour-secrets init-hook` first to create the global settings file and
    /// install a hook in the current repository.
    #[command(
        name = "install-hook",
        after_help = "\
EXAMPLES:\n  \
  scour-secrets install-hook                              # scan with auto-loaded default secrets\n  \
  scour-secrets install-hook --app gitlab,kubernetes      # scan with app bundles\n  \
  scour-secrets install-hook -s secrets.yaml              # scan with custom secrets file\n  \
  scour-secrets install-hook --mode sanitize              # sanitize staged files in place\n  \
  scour-secrets install-hook --hook pre-push              # install a pre-push hook\n  \
  scour-secrets install-hook --global                     # apply to all repos on this machine\n  \
  scour-secrets install-hook --remove                     # remove the installed hook\n  \
  scour-secrets install-hook --dry-run                    # preview without writing"
    )]
    InstallHook(InstallHookArgs),

    /// Show the effective configuration that will be applied on the next run.
    ///
    /// Prints the paths and active values from `~/.config/scour-secrets/settings.yaml`
    /// and reports whether the default secrets file is present. Useful for
    /// debugging unexpected behaviour or verifying CI setup.
    #[command(name = "show-config")]
    ShowConfig,

    /// One-time repo setup: create the global settings file and install a git
    /// hook for the current repository.
    ///
    /// The settings file is written to ~/.config/scour-secrets/settings.yaml
    /// (or $XDG_CONFIG_HOME/scour/settings.yaml) and lets you set persistent
    /// flag defaults. The global secrets file is created automatically on the
    /// first plain `scour-secrets` run — no explicit setup needed.
    #[command(
        name = "init-hook",
        after_help = "\
EXAMPLES:\n  \
  scour-secrets init-hook                        # create settings file + pre-commit hook\n  \
  scour-secrets init-hook --mode sanitize        # hook sanitizes files in place\n  \
  scour-secrets init-hook --hook pre-push        # hook runs on push instead\n  \
  scour-secrets init-hook --global               # apply hook to all repos on this machine"
    )]
    InitHook(InitArgs),

    /// Scan files for secrets without modifying them. Exits 2 if any are found.
    ///
    /// Equivalent to running the default sanitize mode with --dry-run and
    /// --fail-on-match, but discoverable as a dedicated subcommand. Designed
    /// for CI pipelines where you want detection without rewriting files.
    #[command(after_help = "\
EXAMPLES:\n  \
  scour-secrets scan app.log -s secrets.yaml              # scan a log file\n  \
  scour-secrets scan ./logs/ -s secrets.yaml              # scan a directory\n  \
  scour-secrets scan app.log --app gitlab                 # scan using an app bundle\n  \
  scour-secrets scan . --exclude-path tests/fixtures/      # skip test fixtures\n  \
  git diff HEAD | scour-secrets scan                      # scan a patch from stdin\n  \
  scour-secrets scan app.log -s s.enc --encrypted-secrets -p  # encrypted secrets")]
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
  scour-secrets test-pattern --pattern 'ghp_[A-Za-z0-9_]{36}' 'ghp_abc123'\n  \
  scour-secrets test-pattern -s secrets.yaml 'my-secret-value' 'safe-value'\n  \
  scour-secrets test-pattern --app gitlab 'glpat-abc123'\n  \
  echo 'AKIA1234567890ABCDEF' | scour-secrets test-pattern --app aws\n  \
  scour-secrets test-pattern -s secrets.yaml --json 'value1' 'value2'"
    )]
    TestPattern(TestPatternArgs),
}

#[derive(Parser, Debug)]
pub(crate) struct EncryptArgs {
    /// Path to plaintext secrets file (.json, .yaml, .yml, .toml).
    #[arg(value_name = "INPUT")]
    pub(crate) input: PathBuf,

    /// Path for encrypted output file (.enc).
    #[arg(value_name = "OUTPUT")]
    pub(crate) output: PathBuf,

    /// Prompt interactively for the encryption password. The password is
    /// never echoed. For non-interactive automation use --password-file or
    /// the SCOUR_SECRETS_PASSWORD environment variable instead.
    #[arg(long)]
    pub(crate) password: bool,

    /// Read the password from a file (must have 0600 or 0400 permissions).
    #[arg(long = "password-file", value_name = "FILE")]
    pub(crate) password_file: Option<PathBuf>,

    /// Force secrets file format (json, yaml, toml). Default: auto-detect from
    /// file extension.
    #[arg(long, value_parser = parse_format)]
    pub(crate) secrets_format: Option<SecretsFormat>,

    /// Parse the plaintext before encrypting and report any errors.
    /// Enabled by default; use --no-validate to skip.
    #[arg(long, overrides_with = "_no_validate", default_value_t = true)]
    pub(crate) validate: bool,

    /// Skip pre-encryption validation.
    #[arg(long = "no-validate", hide = true)]
    pub(crate) _no_validate: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct DecryptArgs {
    /// Path to encrypted secrets file (.enc).
    #[arg(value_name = "INPUT")]
    pub(crate) input: PathBuf,

    /// Path for decrypted plaintext output.
    #[arg(value_name = "OUTPUT")]
    pub(crate) output: PathBuf,

    /// Prompt interactively for the decryption password. The password is
    /// never echoed. For non-interactive automation use --password-file or
    /// the SCOUR_SECRETS_PASSWORD environment variable instead.
    #[arg(long)]
    pub(crate) password: bool,

    /// Read the password from a file (must have 0600 or 0400 permissions).
    #[arg(long = "password-file", value_name = "FILE")]
    pub(crate) password_file: Option<PathBuf>,

    /// Validate decrypted content as secrets in this format (json, yaml,
    /// toml). If omitted, the raw decrypted bytes are written as-is.
    #[arg(long, value_parser = parse_format)]
    pub(crate) secrets_format: Option<SecretsFormat>,
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
pub(crate) struct TemplateArgs {
    /// Preset to generate. Choices: balanced (default), aggressive, generic, web, k8s, database, aws.
    #[arg(value_name = "PRESET", default_value = "balanced")]
    pub(crate) preset: String,

    /// Output path for the generated YAML template.
    ///
    /// Default: `secrets.template.<preset>.yaml`
    #[arg(long, short = 'o', value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,

    /// Overwrite the output file if it already exists.
    #[arg(long)]
    pub(crate) overwrite: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct AllowTestArgs {
    /// Allowlist patterns to test. Supports exact strings, * glob wildcards,
    /// and regex: prefix patterns. Repeatable.
    #[arg(long = "allow", value_name = "PATTERN", required = true)]
    pub(crate) allow: Vec<String>,

    /// Values to test against the patterns. If omitted, values are read from
    /// stdin one per line.
    #[arg(value_name = "VALUE")]
    pub(crate) values: Vec<String>,

    /// Output results as JSON instead of human-readable text.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct ScanArgs {
    /// Files, directories, or archives to scan. Omit to read from stdin.
    /// Use "-" to include stdin alongside file paths.
    #[arg(value_name = "INPUT")]
    pub(crate) input: Vec<PathBuf>,

    /// Path to a secrets file (JSON / YAML / TOML, or encrypted with --encrypted-secrets).
    #[arg(short = 's', long = "secrets-file", value_name = "FILE")]
    pub(crate) secrets_file: Option<PathBuf>,

    /// Treat the secrets file as AES-256-GCM encrypted.
    #[arg(long)]
    pub(crate) encrypted_secrets: bool,

    /// Prompt interactively for the decryption password.
    #[arg(short = 'p', long)]
    pub(crate) password: bool,

    /// Read the decryption password from a file (must be 0600/0400).
    #[arg(short = 'P', long = "password-file", value_name = "FILE")]
    pub(crate) password_file: Option<PathBuf>,

    /// App bundle(s) to load. Comma-separated. Repeatable.
    #[arg(long, value_name = "APPS", value_delimiter = ',')]
    pub(crate) app: Vec<String>,

    /// Allow values through unchanged. Supports * glob patterns. Repeatable.
    #[arg(long, value_name = "PATTERN")]
    pub(crate) allow: Vec<String>,

    /// Field-level profile for structured files.
    #[arg(long = "profile", value_name = "FILE")]
    pub(crate) profile: Option<PathBuf>,

    /// Also walk hidden files and directories (names starting with `.`).
    #[arg(long)]
    pub(crate) hidden: bool,

    /// Exclude paths matching these glob patterns. A trailing `/` prunes the
    /// whole subtree. Merged with `exclude` in `.scour-secrets.toml`.
    #[arg(long, value_name = "GLOB", num_args = 1)]
    pub(crate) exclude_path: Vec<String>,

    /// Only scan files matching these glob patterns during directory walks.
    /// When both --include-path and --exclude-path match, exclusion wins.
    /// Has no effect on explicitly named file arguments.
    #[arg(long, value_name = "GLOB", num_args = 1)]
    pub(crate) include_path: Vec<String>,

    /// Write a report to this path (or stderr when no path given).
    #[arg(short = 'r', long, value_name = "PATH")]
    pub(crate) report: Option<Option<PathBuf>>,

    /// Output format for --report: json (default), sarif, or html.
    #[arg(long, value_name = "FORMAT", default_value = "json")]
    pub(crate) report_format: ReportFormat,

    /// Number of worker threads (default: auto-detect).
    #[arg(long, value_name = "N")]
    pub(crate) threads: Option<usize>,

    /// Log format: "human" (default) or "json".
    #[arg(long, value_name = "FMT")]
    pub(crate) log_format: Option<String>,

    /// Log level: off, error, warn (default), info, debug, or trace.
    #[arg(long, value_name = "LEVEL")]
    pub(crate) log_level: Option<String>,

    /// Disable progress output. Deprecated: use `--progress off` instead.
    #[arg(long, hide = true)]
    pub(crate) no_progress: bool,

    /// Write findings as NDJSON to stdout instead of human-readable log output.
    /// One JSON object per file, plus a summary line. Implies --progress off.
    /// Pipe into `jq`, `wc -l`, SIEM tools, etc.
    #[arg(long)]
    pub(crate) findings: bool,

    /// Enable Shannon entropy detection with this threshold (bits/char, e.g. 4.5).
    #[arg(long, value_name = "THRESHOLD")]
    pub(crate) entropy_threshold: Option<f64>,
}

#[derive(Parser, Debug)]
pub(crate) struct TestPatternArgs {
    /// Inline regex pattern to test. Repeatable — multiple patterns are all
    /// tested and each match is attributed to its pattern. Cannot be combined
    /// with --secrets-file or --app when used alone, but all three sources
    /// are additive if provided together.
    #[arg(long = "pattern", short = 'P', value_name = "REGEX")]
    pub(crate) patterns: Vec<String>,

    /// Secrets file whose patterns to test (JSON / YAML / TOML).
    #[arg(short = 's', long = "secrets-file", value_name = "FILE")]
    pub(crate) secrets_file: Option<PathBuf>,

    /// App bundle(s) whose patterns to test. Comma-separated. Repeatable.
    #[arg(long, value_name = "APPS", value_delimiter = ',')]
    pub(crate) app: Vec<String>,

    /// Example values to test against the patterns. If omitted, values are
    /// read from stdin one per line.
    #[arg(value_name = "VALUE")]
    pub(crate) values: Vec<String>,

    /// Output results as JSON instead of human-readable text.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct AppsArgs {
    #[command(subcommand)]
    pub(crate) command: Option<AppsSubCommand>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum AppsSubCommand {
    /// Install a custom app bundle from local YAML files.
    ///
    /// Copies the supplied profile and/or secrets files into the user apps
    /// directory so the bundle is available via `--app <name>`.
    #[command(after_help = "\
EXAMPLES:\n  \
  scour-secrets apps add elastic --profile elastic.profile.yaml --secrets-file elastic.secrets.yaml\n  \
  scour-secrets apps add myapp --profile myapp.profile.yaml\n  \
  scour-secrets apps add myapp --secrets-file myapp.secrets.yaml --overwrite")]
    Add(AppsAddArgs),

    /// Remove a custom app bundle from the user apps directory.
    ///
    /// Built-in bundles cannot be removed.
    #[command(after_help = "\
EXAMPLES:\n  \
  scour-secrets apps remove elastic --yes\n  \
  scour-secrets apps remove myapp -y")]
    Remove(AppsRemoveArgs),

    /// Copy a built-in app bundle to the user apps directory for editing.
    ///
    /// For built-in apps, copies profile.yaml and/or secrets.yaml into
    /// `~/.config/scour-secrets/apps/<name>/` so they can be customised. The local
    /// copy takes precedence over the built-in automatically — no extra flags
    /// needed. For user-defined apps the existing directory path is printed.
    ///
    /// To revert to the built-in, run `scour-secrets apps remove <name> --yes`.
    #[command(after_help = "\
EXAMPLES:\n  \
  scour-secrets apps edit rails\n  \
  scour-secrets apps edit kubernetes\n  \
  scour-secrets apps edit gitlab")]
    Edit(AppsEditArgs),

    /// Print the user apps directory path.
    ///
    /// Custom app bundles are stored here. You can also drop directories
    /// manually instead of using `scour-secrets apps add`.
    Dir,
}

#[derive(Parser, Debug)]
pub(crate) struct AppsAddArgs {
    /// Name for the new app bundle (used with `--app <name>`).
    ///
    /// Only letters, digits, hyphens, and underscores are allowed.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,

    /// Path to a profile YAML file (`Vec<FileTypeProfile>`).
    #[arg(long, value_name = "FILE")]
    pub(crate) profile: Option<PathBuf>,

    /// Path to a secrets YAML file (`Vec<SecretEntry>`).
    #[arg(long, value_name = "FILE")]
    pub(crate) secrets_file: Option<PathBuf>,

    /// Overwrite an existing custom app bundle with the same name.
    #[arg(long)]
    pub(crate) overwrite: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct AppsRemoveArgs {
    /// Name of the custom app bundle to remove.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,

    /// Confirm removal without an interactive prompt.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct AppsEditArgs {
    /// Name of the app bundle to edit.
    ///
    /// For built-in apps this copies the files to the user apps directory.
    /// For user-defined apps this prints the existing directory path.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
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
  The hook calls `scour-secrets` from PATH at commit time — the binary must be\n  \
  installed on every machine that will run the hook. If `scour-secrets` is not\n  \
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

    /// Remove the hook previously installed by `scour-secrets install-hook`.
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
