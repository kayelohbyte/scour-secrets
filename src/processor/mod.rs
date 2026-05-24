//! Structured processors for format-aware sanitization.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
//! │  Input bytes     │ ──▶ │ ProcessorRegistry  │ ──▶ │  Output bytes    │
//! │  (file content)  │     │ (profile matching) │     │  (sanitized)     │
//! └──────────────────┘     └────────┬───────────┘     └──────────────────┘
//!                                   │
//!                          ┌────────▼────────┐
//!                          │ dyn Processor    │
//!                          │                  │
//!                          │  KeyValue        │ ← gitlab.rb-style
//!                          │  JsonProcessor   │ ← JSON files
//!                          │  YamlProcessor   │ ← YAML files
//!                          │  XmlProcessor    │ ← XML files
//!                          │  CsvProcessor    │ ← CSV/TSV files
//!                          └────────┬────────┘
//!                                   │
//!                          ┌────────▼────────┐
//!                          │  MappingStore    │
//!                          │  (one-way dedup) │
//!                          └─────────────────┘
//! ```
//!
//! # File-Type Profiles
//!
//! A [`FileTypeProfile`] specifies which processor to use and what
//! fields/keys to sanitize. Users provide profiles to control which
//! parts of a structured file are replaced. If no profile matches,
//! the caller falls back to the streaming scanner.
//!
//! # Extensibility
//!
//! Implement the [`Processor`] trait and register it with the
//! [`ProcessorRegistry`]. The registry matches profiles to processors
//! by name and dispatches processing.

pub mod archive;
pub mod csv_proc;
pub mod env_proc;
pub mod ini_proc;
pub mod json_proc;
pub mod jsonl_proc;
pub mod key_value;
pub(crate) mod limits;
pub mod log_line;
pub mod profile;
pub mod registry;
pub mod toml_proc;
pub mod xml_proc;
pub mod yaml_proc;

// Re-export core types.
pub use profile::{FieldNameSignal, FieldRule, FileTypeProfile, DEFAULT_FIELD_SIGNAL_THRESHOLD};
pub use registry::ProcessorRegistry;

use crate::category::Category;
use crate::error::{Result, SanitizeError};
use crate::store::MappingStore;
use std::io;

// ---------------------------------------------------------------------------
// Processor trait
// ---------------------------------------------------------------------------

/// A structured processor that can sanitize a specific file format while
/// preserving its structure and formatting as much as possible.
///
/// Processors are **stateless** — all mutable state lives in the
/// [`MappingStore`] they receive. This makes processors `Send + Sync`
/// and reusable across files.
///
/// # Contract
///
/// - `name()` must return a unique, lowercase identifier (e.g. `"json"`).
/// - `can_handle()` is a fast heuristic check; it may inspect a few
///   bytes or the file extension but should not fully parse.
/// - `process()` performs the full structured sanitization. It should
///   preserve formatting/whitespace where possible and only replace
///   values in fields matched by the profile's [`FieldRule`]s.
/// - Replacements are **one-way** via the `MappingStore` — no reverse
///   mapping is produced.
pub trait Processor: Send + Sync {
    /// Unique name for this processor (e.g. `"json"`, `"yaml"`, `"key_value"`).
    fn name(&self) -> &'static str;

    /// Quick heuristic: can this processor handle the given content?
    ///
    /// Implementations may check magic bytes, file extension hints in
    /// the profile, or the first few bytes of content. This is called
    /// before `process()` and should be fast.
    fn can_handle(&self, content: &[u8], profile: &FileTypeProfile) -> bool;

    /// Process the content, replacing matched field values one-way.
    ///
    /// # Arguments
    ///
    /// - `content` — raw file bytes.
    /// - `profile` — the user-supplied profile with field rules.
    /// - `store` — the mapping store for dedup-consistent one-way replacements.
    ///
    /// # Returns
    ///
    /// The sanitized content as bytes, preserving structure/formatting
    /// where possible.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] if parsing or replacement generation fails.
    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>>;

    /// Whether this processor supports bounded-memory streaming via
    /// [`process_stream`](Self::process_stream).
    ///
    /// Processors that return `true` here are eligible for the streaming
    /// structured path in the CLI, which opens the file as a reader instead
    /// of reading it fully into memory. The default is `false`.
    fn supports_streaming(&self) -> bool {
        false
    }

    /// Process content from a reader, writing sanitized output to a writer.
    ///
    /// The default implementation reads the entire reader into memory and
    /// delegates to [`process`](Self::process). Processors that return
    /// `true` from [`supports_streaming`](Self::supports_streaming) should
    /// override this to handle data incrementally, keeping memory usage
    /// bounded regardless of input size.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] on read, parse,
    /// or write failure.
    fn process_stream(
        &self,
        reader: &mut dyn io::Read,
        writer: &mut dyn io::Write,
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<()> {
        let mut buf = Vec::new();
        io::Read::read_to_end(reader, &mut buf)?;
        let out = self.process(&buf, profile, store)?;
        io::Write::write_all(writer, &out)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers shared across processors
// ---------------------------------------------------------------------------

/// Replace a value through the mapping store using a field rule's category.
///
/// Returns the original `value` unchanged when it is shorter than
/// `rule.min_length` (if set). This prevents broad glob patterns like
/// `*token*` from redacting obviously non-secret values such as `"false"`,
/// `"0"`, or `"nil"`.
pub(crate) fn replace_value(value: &str, rule: &FieldRule, store: &MappingStore) -> Result<String> {
    if let Some(min) = rule.min_length {
        if value.len() < min {
            return Ok(value.to_string());
        }
    }
    let category = rule
        .category
        .clone()
        .unwrap_or(Category::Custom("field".into()));
    let sanitized = store.get_or_insert(&category, value)?;
    Ok(sanitized.to_string())
}

/// Build a dot-separated key path by appending `key` to `prefix`.
///
/// Returns `key` unchanged when `prefix` is empty.
#[must_use]
pub(crate) fn build_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{}.{}", prefix, key)
    }
}

/// Check whether a single glob `pattern` matches `key_path`.
///
/// `*` is the only wildcard character. It matches any sequence of characters,
/// including empty strings and path separators (`.`, `[`, `]`).
///
/// | Pattern | Matches |
/// |---------|---------|
/// | `"*"` | anything |
/// | `"password"` | `"password"` exactly |
/// | `"*.password"` | `"password"`, `"db.password"`, `"a.b.password"` |
/// | `"db.*"` | `"db.host"`, `"db.port"`, `"db.nested.key"` |
/// | `"*password*"` | any key containing `"password"` as a substring |
/// | `"*['smtp_password']"` | `"gitlab_rails['smtp_password']"` (bracket notation) |
#[must_use]
pub(crate) fn pattern_matches(pattern: &str, key_path: &str) -> bool {
    // Fast path: `*` matches everything.
    if pattern == "*" {
        return true;
    }
    // Fast path: exact match.
    if pattern == key_path {
        return true;
    }
    // Fast path: no wildcards — only the exact match above can succeed.
    if !pattern.contains('*') {
        return false;
    }
    // Dot-path glob: `*.suffix` — requires a dot boundary before the suffix
    // so that `*.password` matches `db.password` but not `dbpassword`.
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if !suffix.contains('*')
            && (key_path == suffix
                || key_path
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.ends_with('.')))
        {
            return true;
        }
    }
    // Dot-path glob: `prefix.*` — `db.*` matches `db.host`, `db.nested.key`.
    if let Some(prefix) = pattern.strip_suffix(".*") {
        if !prefix.contains('*')
            && key_path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('.'))
        {
            return true;
        }
    }
    // General multi-wildcard glob: split on `*` and verify segments appear in
    // order. This handles patterns like `*password*`, `*['key']`, `a*b*c`.
    glob_matches(pattern, key_path)
}

use crate::allowlist::glob_matches;

/// Compute Shannon entropy of `data` in bits per character.
///
/// Returns `0.0` for empty input. Uses a fixed 256-element frequency table
/// so the cost is O(n) time and O(1) space regardless of alphabet size.
#[inline]
#[allow(clippy::cast_precision_loss)]
pub(crate) fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// Return the first [`FieldNameSignal`] whose key pattern matches `key`.
///
/// `key` is the **bare** field name (leaf key only, not the full dot-path).
#[must_use]
pub(crate) fn find_field_signal<'a>(
    key: &str,
    signals: &'a [FieldNameSignal],
) -> Option<&'a FieldNameSignal> {
    signals.iter().find(|sig| sig.matches_key(key))
}

/// Replace `value` via the mapping store when its entropy meets the signal's gate.
///
/// Returns `Some(replacement)` when the value's Shannon entropy is at or above
/// `sig.threshold`, or `None` when the entropy is too low to be a real secret
/// (e.g. `"Bearer"`, `"basic"`, `"true"`).
pub(crate) fn replace_by_signal(
    value: &str,
    sig: &FieldNameSignal,
    store: &MappingStore,
) -> Result<Option<String>> {
    if value.is_empty() {
        return Ok(None);
    }
    if shannon_entropy(value.as_bytes()) < sig.threshold {
        return Ok(None);
    }
    let replaced = store.get_or_insert(&sig.category, value)?;
    Ok(Some(replaced.to_string()))
}

/// Return the first rule in `profile` whose pattern matches `key_path`.
///
/// Supports exact matches and glob patterns — see [`pattern_matches`] for the
/// full pattern syntax including dot-path globs and bracket notation.
#[must_use]
pub(crate) fn find_matching_rule<'a>(
    key_path: &str,
    profile: &'a FileTypeProfile,
) -> Option<&'a FieldRule> {
    profile
        .fields
        .iter()
        .find(|rule| pattern_matches(&rule.pattern, key_path))
}

// ---------------------------------------------------------------------------
// Shared tree walker
// ---------------------------------------------------------------------------

/// Visitor interface over a structured value tree.
///
/// Implemented by [`serde_json::Value`], [`serde_yaml_ng::Value`], and
/// [`toml::Value`] so that [`walk_tree`] can drive sanitization without
/// knowing the format it is operating on.
pub(crate) trait TreeNode {
    /// Call `f(key, child)` for every entry in this map node.
    /// Is a no-op (returns `Ok(())`) if this node is not a map.
    fn for_each_map_entry<F>(&mut self, f: F) -> Result<()>
    where
        F: FnMut(&str, &mut Self) -> Result<()>;

    /// Call `f(item)` for every item in this sequence node.
    /// Is a no-op (returns `Ok(())`) if this node is not a sequence.
    fn for_each_seq_item<F>(&mut self, f: F) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()>;

    /// Mutable access to the inner `String` if this is a string node.
    fn as_str_mut(&mut self) -> Option<&mut String>;

    /// `true` if this is a non-string primitive scalar (number, bool, datetime, …).
    fn is_scalar(&self) -> bool;

    /// String representation used as the replacement input for scalar values.
    fn scalar_to_string(&self) -> String;

    /// Replace this node's content with a string value in-place.
    fn set_string(&mut self, s: String);
}

/// Recursively walk a structured value tree, replacing matched leaf values.
///
/// This is the shared implementation for the JSON, YAML, and TOML processors.
/// Each processor implements [`TreeNode`] for its own value type and wraps
/// this call in a thin format-named function.
pub(crate) fn walk_tree<V: TreeNode>(
    value: &mut V,
    prefix: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    depth: usize,
    format_name: &str,
) -> Result<()> {
    if depth > limits::DEFAULT_DEPTH {
        return Err(SanitizeError::RecursionDepthExceeded(format!(
            "{format_name} recursion depth exceeds limit of {}",
            limits::DEFAULT_DEPTH
        )));
    }
    value.for_each_map_entry(|key, v| {
        let path = build_path(prefix, key);
        if let Some(s) = v.as_str_mut() {
            if let Some(rule) = find_matching_rule(&path, profile) {
                *s = replace_value(s, rule, store)?;
            } else if let Some(sig) = find_field_signal(key, &profile.field_name_signals) {
                if let Some(replaced) = replace_by_signal(s, sig, store)? {
                    *s = replaced;
                }
            }
        } else if v.is_scalar() {
            if let Some(rule) = find_matching_rule(&path, profile) {
                let repr = v.scalar_to_string();
                let replaced = replace_value(&repr, rule, store)?;
                v.set_string(replaced);
            } else if let Some(sig) = find_field_signal(key, &profile.field_name_signals) {
                let repr = v.scalar_to_string();
                if let Some(replaced) = replace_by_signal(&repr, sig, store)? {
                    v.set_string(replaced);
                }
            }
        } else {
            walk_tree(v, &path, profile, store, depth + 1, format_name)?;
        }
        Ok(())
    })?;
    value.for_each_seq_item(|item| walk_tree(item, prefix, profile, store, depth + 1, format_name))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;

    // ── shannon_entropy ──────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::float_cmp)]
    fn entropy_empty_is_zero() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn entropy_single_byte_is_zero() {
        // All characters the same → zero entropy.
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    }

    #[test]
    fn entropy_two_equal_symbols_is_one_bit() {
        // "ab" repeated — 2 equally likely symbols → exactly 1.0 bit.
        assert!((shannon_entropy(b"abababab") - 1.0).abs() < 1e-10);
    }

    #[test]
    fn entropy_high_for_random_hex() {
        // 32-char hex string should be well above 3.5 bits/char.
        let h = shannon_entropy(b"a3f8c2d1e9b7f4a2c8d3e1b9f7a4c2d1");
        assert!(h > 3.5, "expected entropy > 3.5, got {h}");
    }

    #[test]
    fn entropy_low_for_word() {
        // "Bearer" uses only 5 distinct chars, should be below 3.0.
        let h = shannon_entropy(b"Bearer");
        assert!(h < 3.0, "expected entropy < 3.0, got {h}");
    }

    // ── FieldNameSignal::matches_key ─────────────────────────────────────────

    #[test]
    fn signal_matches_exact_key() {
        let sig = FieldNameSignal::new("^password$", Category::AuthToken, None, 3.5).unwrap();
        assert!(sig.matches_key("password"));
        assert!(!sig.matches_key("db_password"));
        assert!(!sig.matches_key("PASSWORD_HASH"));
    }

    #[test]
    fn signal_match_is_case_insensitive() {
        let sig = FieldNameSignal::new("^password$", Category::AuthToken, None, 3.5).unwrap();
        assert!(sig.matches_key("PASSWORD"));
        assert!(sig.matches_key("Password"));
    }

    #[test]
    fn signal_alternation_pattern() {
        let sig =
            FieldNameSignal::new(r"^(password|secret|token)$", Category::AuthToken, None, 3.5)
                .unwrap();
        assert!(sig.matches_key("password"));
        assert!(sig.matches_key("secret"));
        assert!(sig.matches_key("token"));
        assert!(!sig.matches_key("token_type"));
    }

    #[test]
    fn signal_invalid_regex_returns_error() {
        let result = FieldNameSignal::new("[invalid(", Category::AuthToken, None, 3.5);
        assert!(result.is_err());
    }

    #[test]
    fn signal_default_label_derived_from_pattern() {
        let sig = FieldNameSignal::new("^secret$", Category::AuthToken, None, 3.5).unwrap();
        assert_eq!(sig.label, "field-signal:^secret$");
    }

    #[test]
    fn signal_custom_label_preserved() {
        let sig = FieldNameSignal::new(
            "^secret$",
            Category::AuthToken,
            Some("my-label".into()),
            3.5,
        )
        .unwrap();
        assert_eq!(sig.label, "my-label");
    }

    // ── find_field_signal ────────────────────────────────────────────────────

    #[test]
    fn find_returns_none_for_empty_signals() {
        assert!(find_field_signal("password", &[]).is_none());
    }

    #[test]
    fn find_returns_first_matching_signal() {
        let s1 = FieldNameSignal::new("^password$", Category::AuthToken, Some("s1".into()), 3.0)
            .unwrap();
        let s2 =
            FieldNameSignal::new("^token$", Category::AuthToken, Some("s2".into()), 3.5).unwrap();
        let signals = vec![s1, s2];

        let found = find_field_signal("token", &signals).unwrap();
        assert_eq!(found.label, "s2");
    }

    #[test]
    fn find_returns_none_when_no_match() {
        let sig = FieldNameSignal::new("^password$", Category::AuthToken, None, 3.5).unwrap();
        assert!(find_field_signal("hostname", &[sig]).is_none());
    }
}
