//! Encrypted secrets management.
//!
//! This module provides **in-memory-only** decryption of user-supplied
//! secrets files. Secrets are never written to disk in plaintext form;
//! they are loaded from an Argon2id + AES-256-GCM encrypted `.enc` file, decrypted
//! into memory, parsed, and converted directly into [`ScanPattern`]s
//! for the streaming scanner.
//!
//! # Encryption Format
//!
//! ```text
//! ┌───────────┬───────────┬─────────────┬──────────────┬──────────────────────────┐
//! │ Magic (5B)│ Ver (1 B) │ Salt (32 B) │ Nonce (12 B) │  AES-256-GCM Ciphertext  │
//! └───────────┴───────────┴─────────────┴──────────────┴──────────────────────────┘
//! ```
//!
//! - **Magic** (`SCOUR`) + **version** (`1`): identify the format exactly, so a
//!   plaintext secrets file is never mistaken for ciphertext and vice versa.
//! - **Salt** (32 bytes): random, used for the Argon2id-derived key.
//! - **Nonce** (12 bytes): random, for AES-256-GCM.
//! - **Ciphertext**: authenticated encryption of the plaintext secrets
//!   file (JSON / YAML / TOML).
//!
//! The 256-bit AES key is derived from the user password using Argon2id
//! (memory-hard; 19 MiB / 2 passes / 1 lane), the current OWASP recommendation.
//! There is no legacy headerless format — version 1 is the first release.
//!
//! # Key Derivation
//!
//! ```text
//! key = Argon2id(password, salt, m=19 MiB, t=2, p=1, dkLen=32)
//! ```
//!
//! # Secrets File Schema
//!
//! The plaintext secrets file (before encryption) must deserialize to
//! `Vec<SecretEntry>`:
//!
//! ```json
//! [
//!   {
//!     "pattern": "alice@corp\\.com",
//!     "kind": "regex",
//!     "category": "email",
//!     "label": "alice_email"
//!   },
//!   {
//!     "pattern": "sk-proj-abc123secret",
//!     "kind": "literal",
//!     "category": "custom:api_key",
//!     "label": "openai_key"
//!   }
//! ]
//! ```
//!
//! # Thread Safety
//!
//! All public types are `Send + Sync`. Decrypted secrets use
//! [`zeroize::Zeroizing`] to scrub plaintext from memory on drop.
//!
//! # Security Considerations
//!
//! - AES-256-GCM provides both confidentiality and integrity (AEAD).
//! - Argon2id is memory-hard, resisting GPU/ASIC-accelerated offline
//!   brute-force far better than an iterated PBKDF2.
//! - Decrypted plaintext is held in [`Zeroizing<Vec<u8>>`] and zeroed
//!   on drop.
//! - The plaintext secrets file is never written to disk by this crate.
//! - Nonce and salt are generated with OS CSPRNG (`rand`).

use crate::category::Category;
use crate::error::{Result, SanitizeError};
use crate::scanner::ScanPattern;

/// Result of compiling secret entries into patterns.
/// Contains successfully compiled patterns and a list of (index, error) for failures.
pub type PatternCompileResult = (Vec<ScanPattern>, Vec<(usize, SanitizeError)>);

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// File magic identifying a scour encrypted secrets blob. A plaintext
/// secrets file (JSON / YAML / TOML) never begins with these bytes followed
/// by a version byte, so the header is an exact discriminator — no content
/// heuristic is needed.
const MAGIC: &[u8; 5] = b"SCOUR";

/// Encrypted-format version. Version 1 denotes Argon2id (see [`ARGON2_M_COST`]
/// and siblings) plus AES-256-GCM. A future parameter or algorithm change bumps
/// this byte without changing the magic.
const FORMAT_VERSION: u8 = 1;

/// Header length: magic + 1-byte version.
const HEADER_LEN: usize = MAGIC.len() + 1;

/// Salt length for key derivation (bytes).
const SALT_LEN: usize = 32;

/// AES-GCM nonce length (bytes). Must be 12 for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// Argon2id memory cost in KiB (19 MiB — OWASP 2023 baseline).
const ARGON2_M_COST: u32 = 19 * 1024;
/// Argon2id time cost (iterations).
const ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism (lanes).
const ARGON2_P_COST: u32 = 1;

/// Minimum blob size: header + salt + nonce + at least a 16-byte AES-GCM tag.
const MIN_ENCRYPTED_LEN: usize = HEADER_LEN + SALT_LEN + NONCE_LEN + 16;

/// Maximum size of a plaintext secrets file accepted by [`parse_secrets`].
/// Prevents OOM from accidentally passing a large binary or log file as secrets.
const MAX_SECRETS_PLAINTEXT_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

// ---------------------------------------------------------------------------
// Secrets file schema
// ---------------------------------------------------------------------------

/// A single secret entry as stored in the (plaintext) secrets file.
///
/// After decryption the entries are parsed from JSON, YAML, or TOML and
/// converted into [`ScanPattern`]s.
///
/// Implements [`Drop`] via [`Zeroize`] to scrub sensitive pattern data
/// from memory when no longer needed (S-1 fix).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SecretEntry {
    /// The pattern string (regex or literal text).
    ///
    /// For `kind: allow` entries this is the single allowlist pattern.
    /// Omit when using [`values`](Self::values) instead.
    #[serde(default)]
    pub pattern: String,

    /// `"regex"`, `"literal"`, `"allow"`, `"entropy"`, or `"field-name"`.
    ///
    /// `"field-name"` entries are not compiled into scanner patterns — they
    /// are extracted separately and injected into structured-processor profiles
    /// as field-name signals.  The `pattern` field is a case-insensitive
    /// regex matched against bare field/key names; `threshold` controls the
    /// entropy gate (defaults to `3.5` bits/char when omitted).
    #[serde(default = "default_kind")]
    pub kind: String,

    /// Category string. Supported values:
    /// `email`, `name`, `phone`, `ipv4`, `ipv6`, `credit_card`, `ssn`,
    /// `hostname`, `mac_address`, `container_id`, `uuid`, `jwt`,
    /// `auth_token`, `file_path`, `windows_sid`, `url`, `aws_arn`,
    /// `azure_resource_id`, or `custom:<tag>`.
    #[serde(default = "default_category")]
    pub category: String,

    /// Human-readable label for stats reporting (appears in the redaction
    /// summary, findings, and reports). When omitted: a `regex` pattern defaults
    /// to a truncated form of its (non-secret) pattern text; a `literal` pattern
    /// — whose text *is* the secret value — defaults to `literal:<category>` so
    /// the value is never exposed in reporting output.
    #[serde(default)]
    pub label: Option<String>,

    /// Multiple allowlist patterns for `kind: allow` entries.
    ///
    /// When non-empty, used instead of `pattern`. Allows a single entry to
    /// allowlist many values compactly:
    ///
    /// ```toml
    /// [[secrets]]
    /// kind = "allow"
    /// values = ["localhost", "true", "false", "null", "0.0.0.0"]
    /// ```
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,

    // ── Entropy-detection fields (only used when kind = "entropy") ──────────
    /// Minimum token length to consider (default: 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,

    /// Maximum token length to consider (default: 200).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,

    /// Shannon entropy threshold in bits per character (default: 4.5).
    /// Tokens whose entropy is at or above this value are flagged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,

    /// Character set the token must consist of exclusively.
    /// `"alphanumeric"` (default), `"base64"`, `"hex"`, or `"any"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
}

impl SecretEntry {
    /// Create an entry with the given pattern, kind, and category; all other
    /// fields take their serde defaults. The struct is `#[non_exhaustive]`, so
    /// this (or deserialization) is how entries are built outside the crate.
    #[must_use]
    pub fn new(
        pattern: impl Into<String>,
        kind: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        Self {
            pattern: pattern.into(),
            kind: kind.into(),
            category: category.into(),
            label: None,
            values: Vec::new(),
            min_length: None,
            max_length: None,
            threshold: None,
            charset: None,
        }
    }

    /// Set the reporting label (builder style).
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the multi-value allowlist patterns (builder style).
    #[must_use]
    pub fn with_values(mut self, values: Vec<String>) -> Self {
        self.values = values;
        self
    }

    /// Set the match-length bounds (builder style). Pass `None` to leave a
    /// bound at its default.
    #[must_use]
    pub fn with_length_bounds(mut self, min: Option<usize>, max: Option<usize>) -> Self {
        self.min_length = min;
        self.max_length = max;
        self
    }

    /// Set the entropy threshold (builder style; `kind: entropy` /
    /// `kind: field-name` entries).
    #[must_use]
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Set the entropy charset (builder style; `kind: entropy` entries).
    #[must_use]
    pub fn with_charset(mut self, charset: impl Into<String>) -> Self {
        self.charset = Some(charset.into());
        self
    }
}

impl Drop for SecretEntry {
    fn drop(&mut self) {
        self.pattern.zeroize();
        self.kind.zeroize();
        self.category.zeroize();
        if let Some(ref mut l) = self.label {
            l.zeroize();
        }
        for v in &mut self.values {
            v.zeroize();
        }
        if let Some(ref mut s) = self.charset {
            s.zeroize();
        }
    }
}

fn default_kind() -> String {
    "literal".into()
}

fn default_category() -> String {
    "custom:secret".into()
}

/// Supported plaintext file formats for secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretsFormat {
    Json,
    Yaml,
    Toml,
}

impl SecretsFormat {
    /// Detect format from file extension.
    pub fn from_extension(path: &str) -> Option<Self> {
        // Strip .enc suffix first if present.
        let base = path.strip_suffix(".enc").unwrap_or(path);
        let ext = std::path::Path::new(base).extension();
        if ext.is_some_and(|e| e.eq_ignore_ascii_case("json")) {
            Some(Self::Json)
        } else if ext
            .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
        {
            Some(Self::Yaml)
        } else if ext.is_some_and(|e| e.eq_ignore_ascii_case("toml")) {
            Some(Self::Toml)
        } else {
            None
        }
    }

    /// Try to auto-detect format from content.
    pub fn detect(content: &[u8]) -> Self {
        let s = String::from_utf8_lossy(content);
        // Skip leading comment lines — both YAML and TOML use `#`, so a file
        // that opens with comments must be scanned further to find the first
        // meaningful token.
        let first_meaningful = s
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .unwrap_or("");
        if first_meaningful.starts_with('[') || first_meaningful.starts_with('{') {
            // `[` is ambiguous: JSON arrays and TOML table headers both start
            // with it. We pick JSON here because our secrets files are never
            // bare TOML tables, and a wrong guess produces a clear parse error.
            Self::Json
        } else if first_meaningful.starts_with('-') || first_meaningful.starts_with("---") {
            Self::Yaml
        } else {
            // Fallback: assume TOML
            Self::Toml
        }
    }
}

// ---------------------------------------------------------------------------
// TOML wrapper — serde_toml expects a top-level table
// ---------------------------------------------------------------------------

/// Wrapper for TOML deserialization: `secrets = [...]`
#[derive(Deserialize)]
struct TomlSecrets {
    secrets: Vec<SecretEntry>,
}

/// Wrapper for TOML serialization.
#[derive(Serialize)]
struct TomlSecretsRef<'a> {
    secrets: &'a [SecretEntry],
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 256-bit key from a password and salt using Argon2id.
///
/// Shared by the encrypted secrets-file key (this module) and the
/// deterministic-generator seed (the CLI's `scanner_builder`), so both use one
/// memory-hard KDF with identical parameters (19 MiB memory, 2 passes, 1 lane).
///
/// `salt` must be at least 8 bytes (an Argon2 requirement). Callers that accept
/// arbitrary user-supplied salts (e.g. a deterministic seed salt) must normalize
/// short input to a fixed-length salt before calling.
///
/// # Errors
///
/// Returns [`SanitizeError::SecretsCipherError`] if the parameters or salt are
/// rejected by the Argon2 implementation.
pub fn derive_key_argon2(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| SanitizeError::SecretsCipherError(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| SanitizeError::SecretsCipherError(format!("argon2 kdf: {e}")))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt a plaintext secrets file.
///
/// Returns the encrypted blob:
/// `magic (5) || version (1) || salt (32) || nonce (12) || ciphertext`.
///
/// # Arguments
///
/// - `plaintext` — raw bytes of the secrets file (JSON / YAML / TOML).
/// - `password` — user-supplied password.
///
/// # Errors
///
/// Returns [`SanitizeError::SecretsEmptyPassword`] if the password is empty, or
/// [`SanitizeError::SecretsCipherError`] if key derivation or encryption fails.
///
/// # Security
///
/// - Salt and nonce are generated with CSPRNG.
/// - Key is derived with Argon2id (memory-hard; see [`derive_key_argon2`]).
/// - AES-256-GCM provides authenticated encryption.
pub fn encrypt_secrets(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(SanitizeError::SecretsEmptyPassword);
    }

    let mut rng = rand::rng();

    // Generate random salt and nonce.
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Derive key.
    let key = derive_key_argon2(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| SanitizeError::SecretsCipherError(format!("cipher init: {}", e)))?;

    // Encrypt.
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SanitizeError::SecretsCipherError(format!("encryption: {}", e)))?;

    // Assemble: magic || version || salt || nonce || ciphertext
    let mut output = Vec::with_capacity(HEADER_LEN + SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(FORMAT_VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// Decrypt an encrypted secrets blob in memory.
///
/// Returns the plaintext wrapped in [`Zeroizing`] so it is scrubbed on drop.
///
/// # Arguments
///
/// - `encrypted` — `magic (5) || version (1) || salt (32) || nonce (12) || ciphertext`.
/// - `password` — user-supplied password.
///
/// # Errors
///
/// - [`SanitizeError::SecretsTooShort`] if the blob is too short.
/// - [`SanitizeError::SecretsUnrecognizedFormat`] if the magic is absent or the
///   version is unsupported (there is no legacy headerless format).
/// - [`SanitizeError::SecretsDecryptFailed`] if the password is wrong or the
///   ciphertext has been tampered with.
pub fn decrypt_secrets(encrypted: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted.len() < MIN_ENCRYPTED_LEN {
        return Err(SanitizeError::SecretsTooShort);
    }
    if &encrypted[..MAGIC.len()] != MAGIC || encrypted[MAGIC.len()] != FORMAT_VERSION {
        return Err(SanitizeError::SecretsUnrecognizedFormat);
    }

    let body = &encrypted[HEADER_LEN..];
    let salt = &body[..SALT_LEN];
    let nonce_bytes = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

    let nonce = Nonce::from_slice(nonce_bytes);

    let key = derive_key_argon2(password.as_bytes(), salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| SanitizeError::SecretsCipherError(format!("cipher init: {}", e)))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SanitizeError::SecretsDecryptFailed)?;

    Ok(Zeroizing::new(plaintext))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a decrypted plaintext into secret entries.
///
/// Supports JSON, YAML, and TOML. Format is auto-detected if `format`
/// is `None`.
///
/// # Errors
///
/// Returns [`SanitizeError::SecretsInvalidUtf8`] if the plaintext is not
/// valid UTF-8, [`SanitizeError::SecretsFormatError`] if it cannot be parsed
/// in the specified format or if the file exceeds the size limit.
pub fn parse_secrets(plaintext: &[u8], format: Option<SecretsFormat>) -> Result<Vec<SecretEntry>> {
    if plaintext.len() > MAX_SECRETS_PLAINTEXT_BYTES {
        return Err(SanitizeError::SecretsFormatError {
            format: "secrets file".into(),
            message: format!(
                "file is {} bytes, exceeding the {} byte limit — \
                 secrets files should be small YAML/JSON/TOML pattern lists",
                plaintext.len(),
                MAX_SECRETS_PLAINTEXT_BYTES,
            ),
        });
    }
    let fmt = format.unwrap_or_else(|| SecretsFormat::detect(plaintext));
    let text = std::str::from_utf8(plaintext)
        .map_err(|e| SanitizeError::SecretsInvalidUtf8(e.to_string()))?;

    // Parser error messages are deliberately reduced to a location: a secrets
    // file's content is secret by definition, and both serde data errors
    // (`invalid type: string "…"`) and toml's snippet rendering echo source
    // text verbatim — straight into stderr, CI logs, and scrollback.
    match fmt {
        SecretsFormat::Json => serde_json::from_str(text).map_err(|e| {
            let loc = (e.line() > 0).then(|| (e.line(), e.column()));
            secrets_parse_error("JSON", loc)
        }),
        SecretsFormat::Yaml => serde_yaml_ng::from_str(text)
            .map_err(|e| secrets_parse_error("YAML", e.location().map(|l| (l.line(), l.column())))),
        SecretsFormat::Toml => {
            let wrapper: TomlSecrets = toml::from_str(text).map_err(|e| {
                secrets_parse_error("TOML", e.span().map(|s| line_col_at(text, s.start)))
            })?;
            Ok(wrapper.secrets)
        }
    }
}

/// Build a location-only secrets parse error. The parser's own message is
/// never included — see the comment in [`parse_secrets`].
fn secrets_parse_error(format: &str, location: Option<(usize, usize)>) -> SanitizeError {
    let loc = location.map_or_else(String::new, |(line, col)| {
        format!(" at line {line}, column {col}")
    });
    SanitizeError::SecretsFormatError {
        format: format.into(),
        message: format!(
            "invalid secrets file{loc} \
             (parser details withheld — secrets file content is never echoed)"
        ),
    }
}

/// 1-based (line, column) of a byte offset within `text`. Columns count bytes
/// since the last newline, which is exact for the ASCII syntax around a TOML
/// error and close enough for an error pointer otherwise.
pub(crate) fn line_col_at(text: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(text.len());
    let before = &text.as_bytes()[..offset];
    let line = bytecount::count(before, b'\n') + 1;
    let col = offset
        - before
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |p| p + 1)
        + 1;
    (line, col)
}

/// Serialize secret entries back into a plaintext format.
///
/// Used by the encryption helper CLI.
///
/// # Errors
///
/// Returns [`SanitizeError::SecretsFormatError`] if serialization fails.
pub fn serialize_secrets(entries: &[SecretEntry], format: SecretsFormat) -> Result<Vec<u8>> {
    match format {
        SecretsFormat::Json => {
            serde_json::to_vec_pretty(entries).map_err(|e| SanitizeError::SecretsFormatError {
                format: "JSON-serialize".into(),
                message: e.to_string(),
            })
        }
        SecretsFormat::Yaml => serde_yaml_ng::to_string(entries)
            .map(|s| s.into_bytes())
            .map_err(|e| SanitizeError::SecretsFormatError {
                format: "YAML-serialize".into(),
                message: e.to_string(),
            }),
        SecretsFormat::Toml => {
            let wrapper = TomlSecretsRef { secrets: entries };
            toml::to_string_pretty(&wrapper)
                .map(|s| s.into_bytes())
                .map_err(|e| SanitizeError::SecretsFormatError {
                    format: "TOML-serialize".into(),
                    message: e.to_string(),
                })
        }
    }
}

// ---------------------------------------------------------------------------
// Category parsing
// ---------------------------------------------------------------------------

/// Parse a category string into a [`Category`].
///
/// Accepted values: `email`, `name`, `phone`, `ipv4`, `ipv6`,
/// `credit_card`, `ssn`, `hostname`, `mac_address`, `container_id`,
/// `uuid`, `jwt`, `auth_token`, `file_path`, `windows_sid`, `url`,
/// `aws_arn`, `azure_resource_id`, or `custom:<tag>`.
pub fn parse_category(s: &str) -> Category {
    match s {
        "email" => Category::Email,
        "name" => Category::Name,
        "phone" => Category::Phone,
        "ipv4" => Category::IpV4,
        "ipv6" => Category::IpV6,
        "credit_card" => Category::CreditCard,
        "ssn" => Category::Ssn,
        "hostname" => Category::Hostname,
        "mac_address" => Category::MacAddress,
        "container_id" => Category::ContainerId,
        "uuid" => Category::Uuid,
        "jwt" => Category::Jwt,
        "auth_token" => Category::AuthToken,
        "file_path" => Category::FilePath,
        "windows_sid" => Category::WindowsSid,
        "url" => Category::Url,
        "aws_arn" => Category::AwsArn,
        "azure_resource_id" => Category::AzureResourceId,
        other => {
            let tag = if let Some(tag) = other.strip_prefix("custom:") {
                tag
            } else {
                // A bare unknown string is more often a typo of a built-in
                // ("emial") than an intentional custom tag; the contract
                // stays "never errors", but surface it.
                tracing::warn!(
                    category = other,
                    "unknown category — treated as custom:{}; use the \
                     `custom:` prefix to silence this warning",
                    other
                );
                other
            };
            Category::Custom(tag.into())
        }
    }
}

// ---------------------------------------------------------------------------
// Conversion to ScanPatterns
// ---------------------------------------------------------------------------

/// Extract allowlist patterns from a set of entries.
///
/// Entries with `kind: allow` are returned as raw pattern strings to be
/// compiled into an [`AllowlistMatcher`](crate::allowlist::AllowlistMatcher). They are skipped by
/// [`entries_to_patterns`].
///
/// Each entry contributes either its `values` list (when non-empty) or its
/// `pattern` field (when `values` is absent), so both forms are supported:
///
/// ```toml
/// # single pattern
/// [[secrets]]
/// kind = "allow"
/// pattern = "localhost"
///
/// # compact multi-value form
/// [[secrets]]
/// kind = "allow"
/// values = ["true", "false", "null", "0.0.0.0"]
/// ```
pub fn extract_allow_patterns(entries: &[SecretEntry]) -> Vec<String> {
    let mut patterns = Vec::new();
    for entry in entries.iter().filter(|e| e.kind == "allow") {
        if !entry.values.is_empty() {
            patterns.extend(entry.values.iter().cloned());
        } else if !entry.pattern.is_empty() {
            patterns.push(entry.pattern.clone());
        }
    }
    patterns
}

/// Convert parsed [`SecretEntry`]s into compiled [`ScanPattern`]s.
///
/// Entries with `kind: allow` are silently skipped — they are handled by
/// [`extract_allow_patterns`] instead.
///
/// Invalid entries (e.g. bad regex) are collected as errors and
/// returned alongside the successfully compiled patterns.
pub fn entries_to_patterns(entries: &[SecretEntry]) -> PatternCompileResult {
    let mut patterns = Vec::with_capacity(entries.len());
    let mut errors = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        if entry.kind == "allow"
            || entry.kind == "entropy"
            || entry.kind == "field-name"
            || entry.pattern.is_empty()
        {
            continue;
        }
        let category = parse_category(&entry.category);
        // A `literal` pattern's text IS the secret value, and labels surface in
        // the redaction summary, findings, reports, and logs — so a literal must
        // never default its label to its own pattern (that leaks the secret).
        // Fall back to the category instead. A `regex` pattern is not itself a
        // secret, so its (truncated) text remains a safe, informative default.
        let label = entry.label.clone().unwrap_or_else(|| {
            if entry.kind == "literal" {
                format!("literal:{}", entry.category)
            } else {
                truncate_label(&entry.pattern)
            }
        });

        let result = match entry.kind.as_str() {
            "regex" => ScanPattern::from_regex(&entry.pattern, category, label),
            "literal" => ScanPattern::from_literal(&entry.pattern, category, label),
            other => {
                errors.push((
                    i,
                    SanitizeError::InvalidConfig(format!(
                        "unknown kind {:?} — expected \"literal\", \"regex\", \"allow\", \"entropy\", or \"field-name\"",
                        other
                    )),
                ));
                continue;
            }
        };

        match result {
            Ok(pat) => {
                // Apply the entry's optional match-length bounds. Unset bounds
                // keep the pattern's defaults (min 0 for regex / literal length
                // for literals, max unbounded).
                let min = entry.min_length.unwrap_or(pat.min_length);
                let max = entry.max_length.unwrap_or(pat.max_length);
                patterns.push(pat.with_length_bounds(min, max));
            }
            Err(e) => errors.push((i, e)),
        }
    }

    (patterns, errors)
}

const MAX_LABEL_CHARS: usize = 32;

/// Truncate to a maximum label length.
fn truncate_label(s: &str) -> String {
    if s.len() <= MAX_LABEL_CHARS {
        s.to_string()
    } else {
        // Find a char boundary just before the limit to avoid panicking on
        // multi-byte UTF-8 characters (e.g. Unicode in user-supplied patterns).
        let cut = s
            .char_indices()
            .nth(MAX_LABEL_CHARS - 1)
            .map_or(s.len(), |(i, _)| i);
        format!("{}…", &s[..cut])
    }
}

// ---------------------------------------------------------------------------
// High-level: load encrypted secrets → ScanPatterns
// ---------------------------------------------------------------------------

/// Load, decrypt, parse, and compile an encrypted secrets file into
/// [`ScanPattern`]s ready for the streaming scanner.
///
/// This is the primary entry point for CLI integration.
///
/// # Arguments
///
/// - `encrypted_bytes` — raw bytes of the `.enc` file.
/// - `password` — user-supplied password.
/// - `format` — optional explicit format override.
///
/// # Returns
///
/// `(patterns, warnings)` where `warnings` contains indices and errors
/// for entries that failed to compile.
///
/// # Security
///
/// The decrypted plaintext is held in zeroizing memory and dropped
/// immediately after parsing.
///
/// # Errors
///
/// Returns a secrets-related [`SanitizeError`] if decryption or parsing fails.
pub fn load_encrypted_secrets(
    encrypted_bytes: &[u8],
    password: &str,
    format: Option<SecretsFormat>,
) -> Result<(PatternCompileResult, Vec<String>)> {
    let plaintext = decrypt_secrets(encrypted_bytes, password)?;
    let entries = parse_secrets(&plaintext, format)?;
    let allow = extract_allow_patterns(&entries);
    let result = entries_to_patterns(&entries);
    // SecretEntry implements Drop with explicit zeroize() calls, so dropping
    // the Vec is sufficient to scrub sensitive pattern data from heap memory.
    drop(entries);
    Ok((result, allow))
}

/// Load and parse a plaintext secrets file into [`ScanPattern`]s.
///
/// This function mirrors [`load_encrypted_secrets`] but skips
/// AES decryption and password prompts entirely. It preserves
/// memory hygiene by zeroizing parsed entries after compilation.
///
/// # Arguments
///
/// - `plaintext` — raw bytes of the secrets file (JSON / YAML / TOML).
/// - `format` — optional explicit format override.
///
/// # Security
///
/// Even for unencrypted secrets, entries are zeroized after pattern
/// compilation to minimise the window during which sensitive values
/// reside in memory.
///
/// # Errors
///
/// Returns a secrets-related [`SanitizeError`] if parsing or pattern
/// compilation fails.
pub fn load_plaintext_secrets(
    plaintext: &[u8],
    format: Option<SecretsFormat>,
) -> Result<(PatternCompileResult, Vec<String>)> {
    let entries = parse_secrets(plaintext, format)?;
    let allow = extract_allow_patterns(&entries);
    let result = entries_to_patterns(&entries);
    // SecretEntry implements Drop with explicit zeroize() calls, so dropping
    // the Vec is sufficient to scrub sensitive pattern data from heap memory.
    drop(entries);
    Ok((result, allow))
}

/// Detect whether raw file bytes are a scour encrypted secrets blob.
///
/// Returns `true` iff the content begins with the format header
/// (`MAGIC || FORMAT_VERSION`). Because a plaintext secrets file
/// (JSON / YAML / TOML) never starts with those bytes, this is an exact
/// discriminator — unlike the pre-1.0 content heuristic it cannot misclassify
/// a plaintext file whose first token happens to be a bare key.
#[must_use]
pub fn looks_encrypted(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN && &data[..MAGIC.len()] == MAGIC && data[MAGIC.len()] == FORMAT_VERSION
}

/// Unified loader: auto-detect encrypted vs plaintext and load
/// secret patterns accordingly.
///
/// When `force_plaintext` is `true`, decryption is skipped regardless
/// of file content. When `false`, the function uses [`looks_encrypted`]
/// to choose the path automatically.
///
/// # Arguments
///
/// - `data` — raw bytes read from the secrets file.
/// - `password` — password for decryption (ignored when plaintext).
/// - `format` — optional format override.
/// - `force_plaintext` — if `true`, always treat as plaintext.
///
/// # Errors
///
/// Returns a secrets-related [`SanitizeError`] if decryption or parsing
/// fails, or if a password is required but not provided.
pub fn load_secrets_auto(
    data: &[u8],
    password: Option<&str>,
    format: Option<SecretsFormat>,
    force_plaintext: bool,
) -> Result<AutoLoadedSecrets> {
    let (result, allow_patterns, was_encrypted) = if force_plaintext || !looks_encrypted(data) {
        let (result, allow) = load_plaintext_secrets(data, format)?;
        (result, allow, false)
    } else {
        let pw = password.ok_or(SanitizeError::SecretsPasswordRequired)?;
        let (result, allow) = load_encrypted_secrets(data, pw, format)?;
        (result, allow, true)
    };
    let (patterns, warnings) = result;
    Ok(AutoLoadedSecrets {
        patterns,
        warnings,
        allow_patterns,
        was_encrypted,
    })
}

/// Result of [`load_secrets_auto`]: compiled patterns plus everything the
/// caller needs to finish wiring a scanner.
///
/// `allow_patterns` are the raw strings from `kind: allow` entries in the
/// secrets file — combine these with any CLI-provided allow values and pass
/// the merged list to
/// [`AllowlistMatcher::new`](crate::allowlist::AllowlistMatcher::new).
/// A non-empty `warnings` list means some entries failed to compile and the
/// scanner covers less than the full file.
#[derive(Debug)]
#[non_exhaustive]
pub struct AutoLoadedSecrets {
    /// Successfully compiled scan patterns.
    pub patterns: Vec<ScanPattern>,
    /// Entries that failed pattern compilation: `(index_in_file, error)`.
    pub warnings: Vec<(usize, SanitizeError)>,
    /// Raw `kind: allow` pattern strings.
    pub allow_patterns: Vec<String>,
    /// Whether the input bytes were AES-256-GCM encrypted.
    pub was_encrypted: bool,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"[
            {
                "pattern": "alice@corp\\.com",
                "kind": "regex",
                "category": "email",
                "label": "alice_email"
            },
            {
                "pattern": "sk-proj-abc123secret",
                "kind": "literal",
                "category": "custom:api_key",
                "label": "openai_key"
            }
        ]"#
    }

    fn sample_yaml() -> &'static str {
        r#"- pattern: "alice@corp\\.com"
  kind: regex
  category: email
  label: alice_email
- pattern: sk-proj-abc123secret
  kind: literal
  category: "custom:api_key"
  label: openai_key
"#
    }

    fn sample_toml() -> &'static str {
        r#"[[secrets]]
pattern = "alice@corp\\.com"
kind = "regex"
category = "email"
label = "alice_email"

[[secrets]]
pattern = "sk-proj-abc123secret"
kind = "literal"
category = "custom:api_key"
label = "openai_key"
"#
    }

    // ---- Parsing ----

    #[test]
    fn parse_json_entries() {
        let entries = parse_secrets(sample_json().as_bytes(), Some(SecretsFormat::Json)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, "regex");
        assert_eq!(entries[0].category, "email");
        assert_eq!(entries[1].kind, "literal");
    }

    #[test]
    fn parse_yaml_entries() {
        let entries = parse_secrets(sample_yaml().as_bytes(), Some(SecretsFormat::Yaml)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].label, Some("alice_email".into()));
    }

    #[test]
    fn parse_toml_entries() {
        let entries = parse_secrets(sample_toml().as_bytes(), Some(SecretsFormat::Toml)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].pattern, "sk-proj-abc123secret");
    }

    #[test]
    fn parse_auto_detect_json() {
        let entries = parse_secrets(sample_json().as_bytes(), None).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parse_auto_detect_yaml() {
        let entries = parse_secrets(sample_yaml().as_bytes(), None).unwrap();
        assert_eq!(entries.len(), 2);
    }

    // ---- Category parsing ----

    #[test]
    fn parse_builtin_categories() {
        assert_eq!(parse_category("email"), Category::Email);
        assert_eq!(parse_category("ipv4"), Category::IpV4);
        assert_eq!(parse_category("ssn"), Category::Ssn);
    }

    #[test]
    fn parse_custom_category() {
        match parse_category("custom:api_key") {
            Category::Custom(tag) => assert_eq!(tag.as_str(), "api_key"),
            other => panic!("expected Custom, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_category_becomes_custom() {
        match parse_category("foobar") {
            Category::Custom(tag) => assert_eq!(tag.as_str(), "foobar"),
            other => panic!("expected Custom, got {:?}", other),
        }
    }

    // ---- Entries to patterns ----

    #[test]
    fn entries_to_patterns_success() {
        let entries = parse_secrets(sample_json().as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let (patterns, errors) = entries_to_patterns(&entries);
        assert_eq!(patterns.len(), 2);
        assert!(errors.is_empty());
    }

    #[test]
    fn entries_to_patterns_applies_length_bounds() {
        let json = r#"[
            {"pattern": "[0-9]+", "kind": "regex", "category": "custom:num",
             "min_length": 4, "max_length": 8},
            {"pattern": "[a-z]+", "kind": "regex", "category": "custom:word"}
        ]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let (patterns, errors) = entries_to_patterns(&entries);
        assert!(errors.is_empty());
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0].min_length, 4);
        assert_eq!(patterns[0].max_length, 8);
        // Unset bounds keep regex defaults (0 / unbounded).
        assert_eq!(patterns[1].min_length, 0);
        assert_eq!(patterns[1].max_length, usize::MAX);
    }

    #[test]
    fn entries_to_patterns_bad_regex() {
        let json = r#"[{"pattern": "[invalid(", "kind": "regex", "category": "email"}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let (patterns, errors) = entries_to_patterns(&entries);
        assert!(patterns.is_empty());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, 0);
    }

    // ---- Encrypt / Decrypt round-trip ----

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = sample_json().as_bytes();
        let password = "test-password-42";

        let encrypted = encrypt_secrets(plaintext, password).unwrap();

        // Encrypted blob must be larger than plaintext (salt + nonce + tag).
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt_secrets(&encrypted, password).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn decrypt_wrong_password_fails() {
        let plaintext = b"hello";
        let encrypted = encrypt_secrets(plaintext, "correct").unwrap();
        let result = decrypt_secrets(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_truncated_blob_fails() {
        let result = decrypt_secrets(&[0u8; 10], "any");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_blob_fails() {
        let plaintext = b"hello world";
        let mut encrypted = encrypt_secrets(plaintext, "pw").unwrap();
        // Flip a byte in the ciphertext portion.
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        let result = decrypt_secrets(&encrypted, "pw");
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_empty_password_rejected() {
        let result = encrypt_secrets(b"hello", "");
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_emits_magic_and_version_header() {
        let encrypted = encrypt_secrets(b"hello", "pw").unwrap();
        assert_eq!(&encrypted[..MAGIC.len()], MAGIC, "magic prefix");
        assert_eq!(encrypted[MAGIC.len()], FORMAT_VERSION, "version byte");
    }

    #[test]
    fn decrypt_rejects_missing_magic() {
        // A blob of the right length but without the header (e.g. the pre-1.0
        // headerless format, or random bytes) must be rejected as unrecognized
        // — never attempted as ciphertext with a legacy layout.
        let blob = vec![0u8; MIN_ENCRYPTED_LEN + 4];
        match decrypt_secrets(&blob, "pw") {
            Err(SanitizeError::SecretsUnrecognizedFormat) => {}
            other => panic!("expected SecretsUnrecognizedFormat, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_unsupported_version() {
        let mut encrypted = encrypt_secrets(b"hello", "pw").unwrap();
        encrypted[MAGIC.len()] = FORMAT_VERSION.wrapping_add(1);
        match decrypt_secrets(&encrypted, "pw") {
            Err(SanitizeError::SecretsUnrecognizedFormat) => {}
            other => panic!("expected SecretsUnrecognizedFormat, got {other:?}"),
        }
    }

    #[test]
    fn looks_encrypted_requires_header() {
        // Plaintext whose first token merely starts with "SCOUR" is not
        // encrypted: byte 5 is not the version byte. The old content heuristic
        // could misclassify such files; the header check cannot.
        assert!(!looks_encrypted(b"SCOUR_KEY = \"value\"\n"));
        assert!(!looks_encrypted(&[0u8; MIN_ENCRYPTED_LEN]));
    }

    #[test]
    fn derive_key_argon2_is_deterministic_and_salt_sensitive() {
        let salt_a = [7u8; SALT_LEN];
        let salt_b = [9u8; SALT_LEN];
        let k1 = derive_key_argon2(b"password", &salt_a).unwrap();
        let k2 = derive_key_argon2(b"password", &salt_a).unwrap();
        let k3 = derive_key_argon2(b"password", &salt_b).unwrap();
        assert_eq!(*k1, *k2, "same password+salt must yield the same key");
        assert_ne!(*k1, *k3, "different salt must yield a different key");
    }

    #[test]
    fn derive_key_argon2_rejects_short_salt() {
        // Argon2 requires a salt of at least 8 bytes; callers with arbitrary
        // salts must normalize first (the seed path SHA-256s the salt).
        assert!(derive_key_argon2(b"password", b"tiny").is_err());
    }

    // ---- Full pipeline: encrypt → decrypt → parse → patterns ----

    #[test]
    fn full_pipeline_json() {
        let plaintext = sample_json().as_bytes();
        let password = "pipeline-test";

        let encrypted = encrypt_secrets(plaintext, password).unwrap();
        let ((patterns, errors), _allow) =
            load_encrypted_secrets(&encrypted, password, Some(SecretsFormat::Json)).unwrap();

        assert_eq!(patterns.len(), 2);
        assert!(errors.is_empty());
        assert_eq!(patterns[0].label(), "alice_email");
        assert_eq!(patterns[1].label(), "openai_key");
    }

    #[test]
    fn full_pipeline_yaml() {
        let plaintext = sample_yaml().as_bytes();
        let password = "yaml-test";

        let encrypted = encrypt_secrets(plaintext, password).unwrap();
        let ((patterns, errors), _allow) =
            load_encrypted_secrets(&encrypted, password, Some(SecretsFormat::Yaml)).unwrap();

        assert_eq!(patterns.len(), 2);
        assert!(errors.is_empty());
    }

    #[test]
    fn full_pipeline_toml() {
        let plaintext = sample_toml().as_bytes();
        let password = "toml-test";

        let encrypted = encrypt_secrets(plaintext, password).unwrap();
        let ((patterns, errors), _allow) =
            load_encrypted_secrets(&encrypted, password, Some(SecretsFormat::Toml)).unwrap();

        assert_eq!(patterns.len(), 2);
        assert!(errors.is_empty());
    }

    // ---- Plaintext loader ----

    #[test]
    fn load_plaintext_secrets_works() {
        let ((patterns, errors), _allow) =
            load_plaintext_secrets(sample_json().as_bytes(), Some(SecretsFormat::Json)).unwrap();
        assert_eq!(patterns.len(), 2);
        assert!(errors.is_empty());
    }

    // ---- Serialization round-trip ----

    #[test]
    fn serialize_roundtrip_json() {
        let entries = parse_secrets(sample_json().as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let serialized = serialize_secrets(&entries, SecretsFormat::Json).unwrap();
        let reparsed = parse_secrets(&serialized, Some(SecretsFormat::Json)).unwrap();
        assert_eq!(entries.len(), reparsed.len());
        assert_eq!(entries[0].pattern, reparsed[0].pattern);
    }

    // ---- Format detection ----

    #[test]
    fn format_from_extension() {
        assert_eq!(
            SecretsFormat::from_extension("secrets.json"),
            Some(SecretsFormat::Json)
        );
        assert_eq!(
            SecretsFormat::from_extension("secrets.json.enc"),
            Some(SecretsFormat::Json)
        );
        assert_eq!(
            SecretsFormat::from_extension("secrets.yaml"),
            Some(SecretsFormat::Yaml)
        );
        assert_eq!(
            SecretsFormat::from_extension("secrets.yml.enc"),
            Some(SecretsFormat::Yaml)
        );
        assert_eq!(
            SecretsFormat::from_extension("secrets.toml"),
            Some(SecretsFormat::Toml)
        );
        assert_eq!(SecretsFormat::from_extension("secrets.txt"), None);
    }

    #[test]
    fn detect_yaml_with_leading_comment_header() {
        // Regression: the auto-provisioned global secrets file opens with '#'
        // comment lines. Before the fix, detect() saw '#' first, fell through
        // to the TOML fallback, and failed to parse valid YAML.
        let content = "# Global scour-secrets allowlist — add patterns here.\n# Auto-loaded on every plain run.\n\n- pattern: foo\n  kind: allow\n";
        assert_eq!(
            SecretsFormat::detect(content.as_bytes()),
            SecretsFormat::Yaml
        );
    }

    #[test]
    fn detect_yaml_comment_header_parses_correctly() {
        // Round-trip: same shape as the auto-provisioned file must load without error.
        let content = "# Global scour-secrets allowlist — add patterns or kind:regex entries here.\n# Auto-loaded on every plain run. Edit freely; deleted values take effect immediately.\n\n- pattern: ''\n  kind: allow\n  category: ''\n  values:\n  - localhost\n  - 127.0.0.1\n";
        let entries = parse_secrets(content.as_bytes(), None)
            .expect("auto-provisioned secrets file with comment header must parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "allow");
        assert!(entries[0].values.contains(&"localhost".to_string()));
    }

    #[test]
    fn detect_json_array() {
        assert_eq!(
            SecretsFormat::detect(b"[{\"pattern\": \"foo\"}]"),
            SecretsFormat::Json
        );
    }

    #[test]
    fn detect_toml_fallback() {
        // TOML that doesn't open with '[' or '{' — must not be mistaken for YAML.
        assert_eq!(
            SecretsFormat::detect(b"# toml comment\nkey = \"value\""),
            SecretsFormat::Toml
        );
    }

    // ---- Defaults ----

    #[test]
    fn default_kind_is_literal() {
        let json = r#"[{"pattern": "foo"}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        assert_eq!(entries[0].kind, "literal");
    }

    #[test]
    fn default_category_is_custom_secret() {
        let json = r#"[{"pattern": "foo"}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        assert_eq!(entries[0].category, "custom:secret");
    }

    #[test]
    fn literal_default_label_is_category_not_value() {
        // A `literal` pattern's text IS the secret value, and labels surface in
        // summaries / reports / logs — so the default label must be the
        // category, never the value.
        let json = r#"[{"pattern": "short"}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let (patterns, _) = entries_to_patterns(&entries);
        assert_eq!(patterns[0].label(), "literal:custom:secret");
        assert!(!patterns[0].label().contains("short"));
    }

    #[test]
    fn regex_default_label_is_pattern() {
        // A regex pattern is not itself a secret, so its text remains the
        // informative default label.
        let json = r#"[{"pattern": "ab[0-9]+", "kind": "regex"}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let (patterns, _) = entries_to_patterns(&entries);
        assert_eq!(patterns[0].label(), "ab[0-9]+");
    }

    // ---- looks_encrypted ----

    #[test]
    fn looks_encrypted_json_plaintext() {
        assert!(!looks_encrypted(sample_json().as_bytes()));
    }

    #[test]
    fn looks_encrypted_yaml_plaintext() {
        assert!(!looks_encrypted(sample_yaml().as_bytes()));
    }

    #[test]
    fn looks_encrypted_toml_plaintext() {
        assert!(!looks_encrypted(sample_toml().as_bytes()));
    }

    #[test]
    fn looks_encrypted_actual_encrypted() {
        let encrypted = encrypt_secrets(sample_json().as_bytes(), "pw").unwrap();
        assert!(looks_encrypted(&encrypted));
    }

    #[test]
    fn looks_encrypted_too_short() {
        assert!(!looks_encrypted(&[0u8; 10]));
    }

    // ---- load_secrets_auto ----

    #[test]
    fn auto_load_plaintext_json() {
        let data = sample_json().as_bytes();
        let loaded = load_secrets_auto(data, None, Some(SecretsFormat::Json), false).unwrap();
        assert!(!loaded.was_encrypted);
        assert_eq!(loaded.patterns.len(), 2);
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn auto_load_encrypted_json() {
        let encrypted = encrypt_secrets(sample_json().as_bytes(), "pw").unwrap();
        let loaded =
            load_secrets_auto(&encrypted, Some("pw"), Some(SecretsFormat::Json), false).unwrap();
        assert!(loaded.was_encrypted);
        assert_eq!(loaded.patterns.len(), 2);
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn auto_load_force_plaintext() {
        let data = sample_json().as_bytes();
        let loaded = load_secrets_auto(data, None, Some(SecretsFormat::Json), true).unwrap();
        assert!(!loaded.was_encrypted);
        assert_eq!(loaded.patterns.len(), 2);
    }

    #[test]
    fn auto_load_encrypted_no_password_fails() {
        let encrypted = encrypt_secrets(sample_json().as_bytes(), "pw").unwrap();
        let result = load_secrets_auto(&encrypted, None, None, false);
        assert!(result.is_err());
    }

    // ---- Parse errors never echo file content (S1) ----

    /// Marker standing in for a secret value inside a malformed secrets file.
    const LEAK_MARKER: &str = "SEKRET-MARKER-0xD34DB33F";

    #[track_caller]
    fn assert_error_omits_marker(result: Result<Vec<SecretEntry>>) {
        let msg = result
            .expect_err("malformed input must fail to parse")
            .to_string();
        assert!(
            !msg.contains(LEAK_MARKER),
            "parse error echoed secrets file content: {msg}"
        );
        assert!(msg.contains("line"), "expected location info, got: {msg}");
    }

    #[test]
    fn toml_syntax_error_omits_content() {
        // Unclosed inline table — toml's Display normally renders the whole
        // offending line with a caret.
        let bad = format!("secrets = [\n{{ pattern = \"{LEAK_MARKER}\", kind = }}\n]");
        assert_error_omits_marker(parse_secrets(bad.as_bytes(), Some(SecretsFormat::Toml)));
    }

    #[test]
    fn json_data_error_omits_content() {
        // Type mismatch — serde_json's message embeds the value verbatim:
        // `invalid type: string "SEKRET-…", expected usize`.
        let bad = format!(r#"[{{"pattern": "p", "min_length": "{LEAK_MARKER}"}}]"#);
        assert_error_omits_marker(parse_secrets(bad.as_bytes(), Some(SecretsFormat::Json)));
    }

    #[test]
    fn yaml_data_error_omits_content() {
        let bad = format!("- pattern: p\n  min_length: {LEAK_MARKER}\n");
        assert_error_omits_marker(parse_secrets(bad.as_bytes(), Some(SecretsFormat::Yaml)));
    }

    #[test]
    fn yaml_syntax_error_omits_content() {
        // Unterminated quoted scalar spanning the marker.
        let bad = format!("- pattern: \"{LEAK_MARKER}\n  kind: literal\n");
        assert_error_omits_marker(parse_secrets(bad.as_bytes(), Some(SecretsFormat::Yaml)));
    }

    #[test]
    fn line_col_at_positions() {
        let text = "ab\ncd\nef";
        assert_eq!(line_col_at(text, 0), (1, 1));
        assert_eq!(line_col_at(text, 4), (2, 2));
        assert_eq!(line_col_at(text, 6), (3, 1));
        // Clamped past the end.
        assert_eq!(line_col_at(text, 100), (3, 3));
    }

    #[test]
    fn parse_secrets_rejects_oversized_input() {
        // Construct input just over the 10 MiB cap.
        let oversized = vec![b' '; MAX_SECRETS_PLAINTEXT_BYTES + 1];
        let result = parse_secrets(&oversized, None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("exceeding") || msg.contains("limit"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn parse_secrets_accepts_input_at_limit() {
        // Valid JSON just at the cap boundary — should succeed or fail on
        // parse, not on the size check. We use a tiny valid payload here
        // to confirm the size gate does not block small files.
        let tiny = b"[]";
        let result = parse_secrets(tiny, Some(SecretsFormat::Json));
        assert!(
            result.is_ok(),
            "unexpected error: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn truncate_label_at_boundary() {
        let short = "a".repeat(32);
        assert_eq!(truncate_label(&short), short);

        let long = "a".repeat(33);
        let truncated = truncate_label(&long);
        assert!(truncated.ends_with('…'), "expected ellipsis: {truncated}");
        // Character count (not byte count) must be within the limit.
        // The trailing '…' is 1 char; the rest must be < MAX_LABEL_CHARS.
        assert!(
            truncated.chars().count() <= MAX_LABEL_CHARS,
            "char count {} exceeds limit: {truncated}",
            truncated.chars().count()
        );
    }

    // ---- Multi-value allow entries ----

    #[test]
    fn allow_single_pattern_field() {
        let json = r#"[{"kind":"allow","pattern":"localhost"}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let patterns = extract_allow_patterns(&entries);
        assert_eq!(patterns, vec!["localhost"]);
    }

    #[test]
    fn allow_values_list_used_instead_of_pattern() {
        let json = r#"[{"kind":"allow","values":["localhost","true","false","null"]}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let patterns = extract_allow_patterns(&entries);
        assert_eq!(patterns, vec!["localhost", "true", "false", "null"]);
    }

    #[test]
    fn allow_values_list_yaml() {
        let yaml =
            "- kind: allow\n  values:\n    - localhost\n    - \"127.0.0.1\"\n    - \"0.0.0.0\"\n";
        let entries = parse_secrets(yaml.as_bytes(), Some(SecretsFormat::Yaml)).unwrap();
        let patterns = extract_allow_patterns(&entries);
        assert_eq!(patterns, vec!["localhost", "127.0.0.1", "0.0.0.0"]);
    }

    #[test]
    fn allow_values_list_toml() {
        let toml = "[[secrets]]\nkind = \"allow\"\nvalues = [\"localhost\", \"true\", \"false\"]\n";
        let entries = parse_secrets(toml.as_bytes(), Some(SecretsFormat::Toml)).unwrap();
        let patterns = extract_allow_patterns(&entries);
        assert_eq!(patterns, vec!["localhost", "true", "false"]);
    }

    #[test]
    fn allow_mixed_single_and_multi_value_entries() {
        let json = r#"[
            {"kind":"allow","pattern":"localhost"},
            {"kind":"allow","values":["true","false","null"]},
            {"kind":"allow","pattern":"*.internal"}
        ]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let patterns = extract_allow_patterns(&entries);
        assert_eq!(
            patterns,
            vec!["localhost", "true", "false", "null", "*.internal"]
        );
    }

    #[test]
    fn allow_entries_skipped_by_entries_to_patterns() {
        let json = r#"[
            {"pattern":"secret","kind":"literal"},
            {"kind":"allow","values":["localhost","true"]}
        ]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let (patterns, errors) = entries_to_patterns(&entries);
        assert_eq!(patterns.len(), 1);
        assert!(errors.is_empty());
        assert_eq!(patterns[0].label(), "literal:custom:secret");
    }

    #[test]
    fn allow_empty_values_falls_back_to_pattern() {
        // An entry with an empty `values` list should still use `pattern`.
        let json = r#"[{"kind":"allow","pattern":"localhost","values":[]}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let patterns = extract_allow_patterns(&entries);
        assert_eq!(patterns, vec!["localhost"]);
    }

    // ── kind: field-name ─────────────────────────────────────────────────────

    #[test]
    fn field_name_entries_skipped_by_entries_to_patterns() {
        // kind:field-name entries must not produce ScanPatterns — they are
        // handled separately as FieldNameSignals injected into profiles.
        let json = r#"[
            {"pattern":"secret","kind":"literal"},
            {"pattern":"^password$","kind":"field-name","threshold":3.0}
        ]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let (patterns, errors) = entries_to_patterns(&entries);
        assert_eq!(
            patterns.len(),
            1,
            "only the literal entry should produce a pattern"
        );
        assert!(errors.is_empty());
        assert_eq!(patterns[0].label(), "literal:custom:secret");
    }

    #[test]
    fn field_name_entry_parses_correctly() {
        let yaml = "- kind: field-name\n  pattern: \"^(password|secret)$\"\n  threshold: 3.0\n  label: my-signal\n";
        let entries = parse_secrets(yaml.as_bytes(), Some(SecretsFormat::Yaml)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "field-name");
        assert_eq!(entries[0].pattern, "^(password|secret)$");
        assert_eq!(entries[0].threshold, Some(3.0));
        assert_eq!(entries[0].label, Some("my-signal".into()));
    }

    #[test]
    fn field_name_entry_not_extracted_as_allow_pattern() {
        // kind:field-name entries must not bleed into the allowlist.
        let json = r#"[{"pattern":"^password$","kind":"field-name"}]"#;
        let entries = parse_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
        let allow = extract_allow_patterns(&entries);
        assert!(allow.is_empty());
    }
}
