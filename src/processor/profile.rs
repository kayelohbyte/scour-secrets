//! File-type profiles for structured processors.
//!
//! A [`FileTypeProfile`] tells the processing pipeline which processor
//! to use and which fields/keys within the file should be sanitized.

use crate::category::Category;
use glob::Pattern;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FieldNameSignal
// ---------------------------------------------------------------------------

/// Default Shannon entropy threshold (bits per character) for built-in field-name signals.
///
/// Values whose entropy is **below** this threshold are left unchanged even
/// when their key name matches a sensitive keyword, preventing false positives
/// on enum-like values such as `token_type: Bearer` or `auth: basic`.
///
/// Override per signal in the secrets file with `threshold: <f64>`, or disable
/// the heuristic entirely with `--no-field-signal`:
///
/// ```yaml
/// # Lower threshold: catch more, including weaker secrets
/// - kind: field-name
///   pattern: "^(password|secret)$"
///   threshold: 3.0
///
/// # Higher threshold: only flag high-entropy tokens
/// - kind: field-name
///   pattern: "^(token|key)$"
///   threshold: 4.0
/// ```
pub const DEFAULT_FIELD_SIGNAL_THRESHOLD: f64 = 3.5;

/// A field-name–based heuristic signal used during structured processing.
///
/// When no explicit [`FieldRule`] covers a key, the processor checks the bare
/// key name against all active signals.  If a signal matches **and** the
/// value's Shannon entropy meets or exceeds `threshold`, the value is replaced
/// using `category` — as if an explicit rule had been defined.
///
/// # Entropy threshold guidance
///
/// | Threshold | Behaviour |
/// |-----------|-----------|
/// | **3.0** | Catches most secrets including moderately weak ones; recommended for high-confidence keywords (`password`, `secret`) |
/// | **3.5** | Balanced default — skips plain enum values like `Bearer`, `basic`, `true` |
/// | **4.0** | Conservative — only high-entropy tokens; use when false-positive rate matters |
///
/// # Configuring via secrets file
///
/// Add `kind: field-name` entries to your secrets file.  The `pattern` field
/// is a case-insensitive regex matched against the **bare key name** (not the
/// full dot-path).  `threshold` defaults to [`DEFAULT_FIELD_SIGNAL_THRESHOLD`]
/// when omitted.
///
/// ```yaml
/// # Strong signal: flag any `password`/`secret`/`private_key` with entropy ≥ 3.0
/// - kind: field-name
///   pattern: "^(password|passwd|secret|private_key|client_secret)$"
///   category: custom:credential
///   label: my-strong-signals
///   threshold: 3.0
///
/// # Medium signal: flag `token`/`api_key` only when value looks like a real token
/// - kind: field-name
///   pattern: "^(token|api_key|access_key)$"
///   category: custom:credential
///   threshold: 3.5
/// ```
///
/// Suppress false positives on specific values with `kind: allow`:
///
/// ```yaml
/// - kind: allow
///   values: ["Bearer", "basic", "oauth2", "true", "false"]
/// ```
///
/// # Built-in defaults
///
/// When default patterns or `--app` is active, two built-in signals are
/// injected automatically (unless `--no-field-signal` is passed):
///
/// - **Strong** (`threshold: 3.0`): `password`, `passwd`, `secret`,
///   `private_key`, `api_secret`, `client_secret`
/// - **Medium** (`threshold: 3.5`): `api_key`, `access_key`, `auth_token`,
///   `token`, `signing_key`, `encryption_key`, `credential`, `cert`
#[derive(Debug, Clone)]
pub struct FieldNameSignal {
    /// Original pattern string — shown in error messages and log output.
    pub key_pattern: String,
    /// Case-insensitive regex compiled from `key_pattern`.
    pub(crate) key_regex: Regex,
    /// Replacement category applied to values that pass the entropy gate.
    pub category: Category,
    /// Label used in findings and reports.
    /// Defaults to `"field-signal:<key_pattern>"`.
    pub label: String,
    /// Shannon entropy threshold in bits per character.
    ///
    /// Values **below** this threshold are left unchanged.
    /// See the table above and [`DEFAULT_FIELD_SIGNAL_THRESHOLD`].
    pub threshold: f64,
}

impl FieldNameSignal {
    /// Construct a new signal, compiling `key_pattern` as a case-insensitive regex.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string if `key_pattern` is not a valid regex.
    pub fn new(
        key_pattern: impl Into<String>,
        category: Category,
        label: Option<String>,
        threshold: f64,
    ) -> Result<Self, String> {
        let key_pattern = key_pattern.into();
        let key_regex = regex::RegexBuilder::new(&key_pattern)
            .case_insensitive(true)
            .build()
            .map_err(|e| format!("field-name signal pattern {:?}: {e}", key_pattern))?;
        let label = label.unwrap_or_else(|| format!("field-signal:{}", key_pattern));
        Ok(Self {
            key_pattern,
            key_regex,
            category,
            label,
            threshold,
        })
    }

    /// Returns `true` if `key` (bare field name, not a dot-path) matches this signal.
    #[inline]
    #[must_use]
    pub fn matches_key(&self, key: &str) -> bool {
        self.key_regex.is_match(key)
    }
}

// ---------------------------------------------------------------------------
// FieldRule
// ---------------------------------------------------------------------------

/// A rule describing a single field/key to sanitize.
///
/// # Pattern Syntax
///
/// - Exact key: `"password"`, `"db_host"`.
/// - Dotted path: `"database.password"`, `"smtp.user"`.
/// - Glob suffix: `"*.password"` — matches any key ending in `.password`.
/// - Glob prefix: `"db.*"` — matches any key starting with `db.`.
/// - Wildcard: `"*"` — matches every field.
///
/// # Sub-processor
///
/// When a field's value is itself a structured document (e.g. YAML embedded
/// in a Ruby heredoc), set `sub_processor` to the processor name and provide
/// `sub_fields` with rules for the nested content. The parent processor
/// extracts the value and delegates it to the named sub-processor.
///
/// ```yaml
/// - pattern: "*['ldap_servers']"
///   sub_processor: yaml
///   sub_fields:
///     - pattern: "*.password"
///       category: custom:password
///     - pattern: "*.bind_dn"
///       category: custom:dn
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    /// Key pattern to match (see Pattern Syntax above).
    pub pattern: String,

    /// Category for replacement generation. Defaults to `Custom("field")`
    /// if not specified. Ignored when `sub_processor` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,

    /// Optional human-readable label for reporting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Minimum byte length a value must reach before it is replaced.
    ///
    /// Values shorter than this threshold pass through unchanged. Use this
    /// to avoid redacting obviously non-secret values matched by broad glob
    /// patterns (e.g. `"false"`, `"0"`, `"nil"` matched by `*secret*`).
    ///
    /// A value of `8` is a reasonable default for token/password fields.
    /// Omit (or set to `0`) to replace all matching values regardless of length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,

    /// Name of the processor to use for the field's value when it contains
    /// an embedded structured document (e.g. `"yaml"`, `"json"`, `"toml"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_processor: Option<String>,

    /// Field rules applied by `sub_processor` to the nested content.
    /// Ignored when `sub_processor` is `None`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_fields: Vec<FieldRule>,
}

impl FieldRule {
    /// Create a new field rule with just a pattern.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            category: None,
            label: None,
            min_length: None,
            sub_processor: None,
            sub_fields: Vec::new(),
        }
    }

    /// Set the minimum value length required for replacement.
    #[must_use]
    pub fn with_min_length(mut self, min: usize) -> Self {
        self.min_length = Some(min);
        self
    }

    /// Set the category for this rule.
    #[must_use]
    pub fn with_category(mut self, category: Category) -> Self {
        self.category = Some(category);
        self
    }

    /// Set the label for this rule.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the sub-processor name for embedded structured content.
    #[must_use]
    pub fn with_sub_processor(mut self, name: impl Into<String>) -> Self {
        self.sub_processor = Some(name.into());
        self
    }

    /// Set the field rules applied by the sub-processor.
    #[must_use]
    pub fn with_sub_fields(mut self, fields: Vec<FieldRule>) -> Self {
        self.sub_fields = fields;
        self
    }
}

// ---------------------------------------------------------------------------
// FileTypeProfile
// ---------------------------------------------------------------------------

/// Specifies which processor to use and what fields to sanitize.
///
/// # File matching
///
/// A file is processed by this profile when **all** of the following hold:
///
/// 1. Its name ends with one of the `extensions` (required — an empty list
///    matches nothing).
/// 2. If `include` is non-empty, the filename matches **at least one** of
///    those glob patterns.
/// 3. The filename does **not** match any `exclude` glob pattern.
///
/// Glob patterns use `*` (any chars within a path component) and `**`
/// (any chars including path separators).
///
/// # Example (YAML)
///
/// ```yaml
/// - processor: json
///   extensions: [".json"]
///   # Only apply to files whose names start with "config"
///   include: ["config*.json"]
///   # Never apply to log files
///   exclude: ["*.log.json", "logs/**"]
///   fields:
///     - pattern: "*.password"
///       category: "custom:password"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypeProfile {
    /// Name of the processor to use (e.g. `"key_value"`, `"json"`).
    pub processor: String,

    /// File extensions this profile applies to (e.g. `[".rb", ".conf"]`).
    #[serde(default)]
    pub extensions: Vec<String>,

    /// If non-empty, the filename must match at least one of these glob
    /// patterns in addition to the extension check.
    #[serde(default)]
    pub include: Vec<String>,

    /// Filenames matching any of these glob patterns are excluded from
    /// structured processing even if they match the extension (and include).
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Field rules: which keys/paths to sanitize.
    pub fields: Vec<FieldRule>,

    /// Free-form options passed to the processor (e.g. delimiter, comment chars).
    #[serde(default)]
    pub options: std::collections::HashMap<String, String>,

    /// Field-name signals injected at runtime from `kind: field-name` secrets
    /// entries and from built-in defaults when default patterns or `--app` is
    /// active.  Never serialized to or deserialized from the profile file on
    /// disk — configure signals in your secrets file instead.
    #[serde(skip)]
    pub field_name_signals: Vec<FieldNameSignal>,
}

impl FileTypeProfile {
    /// Create a minimal profile for a given processor.
    #[must_use]
    pub fn new(processor: impl Into<String>, fields: Vec<FieldRule>) -> Self {
        Self {
            processor: processor.into(),
            extensions: Vec::new(),
            include: Vec::new(),
            exclude: Vec::new(),
            fields,
            options: std::collections::HashMap::new(),
            field_name_signals: Vec::new(),
        }
    }

    /// Add an extension to this profile.
    #[must_use]
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extensions.push(ext.into());
        self
    }

    /// Add a free-form option.
    #[must_use]
    pub fn with_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }

    /// Check whether a filename should be processed by this profile.
    ///
    /// Returns `true` when all three conditions hold:
    ///
    /// 1. The filename ends with one of `extensions` (an empty list → `false`).
    /// 2. If `include` is non-empty, the filename matches at least one glob.
    /// 3. The filename does **not** match any `exclude` glob.
    ///
    /// Invalid glob patterns in `include`/`exclude` are silently skipped.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_sanitize::processor::profile::FieldRule;
    /// use rust_sanitize::processor::profile::FileTypeProfile;
    ///
    /// let profile = FileTypeProfile::new("json", vec![])
    ///     .with_extension(".json");
    ///
    /// assert!(profile.matches_filename("config.json"));
    /// assert!(profile.matches_filename("logs/app.json"));
    /// assert!(!profile.matches_filename("config.yml"));
    ///
    /// // Exclude log-formatted JSON files.
    /// let profile = FileTypeProfile::new("json", vec![])
    ///     .with_extension(".json")
    ///     .with_exclude("*.log.json")
    ///     .with_exclude("logs/**");
    ///
    /// assert!(profile.matches_filename("config.json"));
    /// assert!(!profile.matches_filename("app.log.json"));
    /// assert!(!profile.matches_filename("logs/events.json"));
    ///
    /// // Include only config files.
    /// let profile = FileTypeProfile::new("json", vec![])
    ///     .with_extension(".json")
    ///     .with_include("config*.json");
    ///
    /// assert!(profile.matches_filename("config.json"));
    /// assert!(profile.matches_filename("config-prod.json"));
    /// assert!(!profile.matches_filename("events.json"));
    /// ```
    pub fn matches_filename(&self, filename: &str) -> bool {
        // 1. Extension must match.
        if self.extensions.is_empty() {
            return false;
        }
        if !self
            .extensions
            .iter()
            .any(|ext| filename.ends_with(ext.as_str()))
        {
            return false;
        }

        // Extract the basename for patterns that don't contain a path separator.
        // This lets users write `config*.json` and have it match
        // `/any/path/config-prod.json` without needing a `**/` prefix.
        let basename: &str = std::path::Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(filename);

        let glob_matches =
            |pat: &str| Pattern::new(pat).is_ok_and(|p| p.matches(filename) || p.matches(basename));

        // 2. Include filter (opt-in narrowing): must match at least one pattern.
        if !self.include.is_empty() && !self.include.iter().any(|pat| glob_matches(pat)) {
            return false;
        }

        // 3. Exclude filter: must not match any pattern.
        if self.exclude.iter().any(|pat| glob_matches(pat)) {
            return false;
        }

        true
    }

    /// Add a glob pattern to the `include` list.
    #[must_use]
    pub fn with_include(mut self, pat: impl Into<String>) -> Self {
        self.include.push(pat.into());
        self
    }

    /// Add a glob pattern to the `exclude` list.
    #[must_use]
    pub fn with_exclude(mut self, pat: impl Into<String>) -> Self {
        self.exclude.push(pat.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Serde support for Category (as string)
// ---------------------------------------------------------------------------

impl Serialize for Category {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Category {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
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
                let tag = other.strip_prefix("custom:").unwrap_or(other);
                Category::Custom(tag.into())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- FieldRule builders ----

    #[test]
    fn field_rule_with_min_length() {
        let rule = FieldRule::new("*.password").with_min_length(8);
        assert_eq!(rule.min_length, Some(8));
    }

    #[test]
    fn field_rule_with_category() {
        let rule = FieldRule::new("*.email").with_category(Category::Email);
        assert_eq!(rule.category, Some(Category::Email));
    }

    #[test]
    fn field_rule_with_label() {
        let rule = FieldRule::new("*.token").with_label("my-token");
        assert_eq!(rule.label.as_deref(), Some("my-token"));
    }

    // ---- FileTypeProfile builders ----

    #[test]
    fn profile_with_include_narrows_match() {
        let profile = FileTypeProfile::new("json", vec![])
            .with_extension(".json")
            .with_include("config*.json");

        assert!(profile.matches_filename("config.json"));
        assert!(profile.matches_filename("config-prod.json"));
        assert!(!profile.matches_filename("events.json"));
    }

    #[test]
    fn profile_with_exclude_blocks_match() {
        let profile = FileTypeProfile::new("json", vec![])
            .with_extension(".json")
            .with_exclude("*.log.json");

        assert!(profile.matches_filename("config.json"));
        assert!(!profile.matches_filename("server.log.json"));
    }

    #[test]
    fn profile_include_and_exclude_combined() {
        let profile = FileTypeProfile::new("json", vec![])
            .with_extension(".json")
            .with_include("config*.json")
            .with_exclude("config-secret.json");

        assert!(profile.matches_filename("config-prod.json"));
        assert!(!profile.matches_filename("config-secret.json"));
        assert!(!profile.matches_filename("events.json"));
    }

    #[test]
    fn profile_no_extensions_matches_nothing() {
        let profile = FileTypeProfile::new("json", vec![]);
        assert!(!profile.matches_filename("anything.json"));
    }

    // ---- Category serde roundtrip ----

    #[test]
    fn category_serialize_deserialize_roundtrip() {
        let cases: &[(&str, Category)] = &[
            ("email", Category::Email),
            ("ipv4", Category::IpV4),
            ("custom:my_key", Category::Custom("my_key".into())),
        ];
        for (s, expected) in cases {
            let json = format!("\"{}\"", s);
            let got: Category = serde_json::from_str(&json).unwrap();
            assert_eq!(got, *expected, "deserializing {s}");
            let serialized = serde_json::to_string(&got).unwrap();
            assert_eq!(serialized, json, "serializing {s}");
        }
    }
}
