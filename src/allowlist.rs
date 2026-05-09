//! Allowlist for suppressing specific values from sanitization.
//!
//! Values matching an allowlist entry pass through the output unchanged and
//! are **not** recorded in the [`MappingStore`](crate::store::MappingStore).
//! This means they also won't propagate to the Phase 2 augmented scanner as
//! discovered literals — a value that is allowed stays allowed everywhere.
//!
//! # Pattern syntax
//!
//! Each entry is either an exact string or a simple glob:
//!
//! | Pattern          | Matches                                      |
//! |------------------|----------------------------------------------|
//! | `localhost`      | Exactly `localhost`                          |
//! | `*.internal`     | Any value ending with `.internal`            |
//! | `192.168.1.*`    | Any value starting with `192.168.1.`         |
//! | `user-*@corp.com`| Prefix `user-`, suffix `@corp.com`           |
//!
//! Only `*` is treated as a wildcard. Patterns are case-sensitive.
//! If a pattern contains regex metacharacters (`^`, `$`, `+`, `(`, `)`)
//! a warning is emitted — those characters are matched literally.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// Compiled allowlist that can be queried concurrently.
///
/// Exact patterns are stored in a [`HashSet`] for O(1) lookup. Glob patterns
/// (those containing `*`) are stored in a [`Vec`] and scanned linearly after
/// the hash check misses. This means allowlists with many exact entries —
/// the common case for common-word lists — pay no linear scan cost.
///
/// # Case sensitivity
///
/// By default the matcher is **case-insensitive**: patterns and query values
/// are both lowercased before comparison. Use [`AllowlistMatcher::new_case_sensitive`]
/// when exact-case matching is required (e.g. allowlisting a known token value
/// that must not match a differently-cased substring).
pub struct AllowlistMatcher {
    exact: HashSet<String>,
    globs: Vec<String>,
    /// When `false` (the default), patterns and query values are lowercased
    /// before comparison.
    case_sensitive: bool,
    /// Number of values passed through as allowed across all `is_allowed` calls.
    seen: AtomicU64,
}

impl AllowlistMatcher {
    /// Build a case-insensitive [`AllowlistMatcher`] from a list of pattern strings.
    ///
    /// This is the default constructor. Patterns and query values are both
    /// lowercased before comparison, so `"Localhost"` matches a pattern of
    /// `"localhost"` and vice-versa.
    ///
    /// Each string is treated as a glob if it contains `*`, otherwise as an
    /// exact match. Patterns that look like regexes (contain `^`, `$`, `+`,
    /// `(`, or `)`) are accepted but a warning message is returned alongside
    /// the matcher so the caller can surface it to the user.
    #[must_use]
    pub fn new(patterns: Vec<String>) -> (Self, Vec<String>) {
        Self::build(patterns, false)
    }

    /// Build a case-sensitive [`AllowlistMatcher`] from a list of pattern strings.
    ///
    /// Use this when exact-case matching is required (e.g. allowlisting a
    /// known token value that must not match differently-cased substrings).
    #[must_use]
    pub fn new_case_sensitive(patterns: Vec<String>) -> (Self, Vec<String>) {
        Self::build(patterns, true)
    }

    fn build(patterns: Vec<String>, case_sensitive: bool) -> (Self, Vec<String>) {
        let mut exact = HashSet::new();
        let mut globs = Vec::new();
        let mut warnings = Vec::new();

        for pat in patterns {
            for ch in ['^', '$', '+', '(', ')'] {
                if pat.contains(ch) {
                    warnings.push(format!(
                        "allowlist pattern '{}' contains regex character '{}'; \
                         it is matched literally — use * for wildcards",
                        pat, ch
                    ));
                    break;
                }
            }
            // Normalize to lowercase for case-insensitive matchers so that
            // both the stored pattern and the query value are in the same case.
            let stored = if case_sensitive {
                pat
            } else {
                pat.to_lowercase()
            };
            if stored.contains('*') {
                globs.push(stored);
            } else {
                exact.insert(stored);
            }
        }

        (
            Self {
                exact,
                globs,
                case_sensitive,
                seen: AtomicU64::new(0),
            },
            warnings,
        )
    }

    /// Returns `true` if `value` matches any allowlist entry.
    ///
    /// Thread-safe; increments an internal counter when a match is found.
    pub fn is_allowed(&self, value: &str) -> bool {
        self.match_pattern(value).is_some()
    }

    /// Returns the pattern that matches `value`, or `None`.
    ///
    /// Exact entries are checked first via hash lookup. Glob entries are
    /// scanned linearly only on a hash miss. Increments the seen counter
    /// when a match is found.
    ///
    /// When the matcher was built with [`new`](Self::new) (case-insensitive),
    /// `value` is lowercased before comparison so the check is case-insensitive.
    pub fn match_pattern<'a>(&'a self, value: &str) -> Option<&'a str> {
        if self.case_sensitive {
            self.match_pattern_inner(value)
        } else {
            let lower = value.to_lowercase();
            self.match_pattern_inner(&lower)
        }
    }

    fn match_pattern_inner<'a>(&'a self, value: &str) -> Option<&'a str> {
        if let Some(s) = self.exact.get(value) {
            self.seen.fetch_add(1, Ordering::Relaxed);
            return Some(s.as_str());
        }
        for pat in &self.globs {
            if glob_matches(pat, value) {
                self.seen.fetch_add(1, Ordering::Relaxed);
                return Some(pat.as_str());
            }
        }
        None
    }

    /// Total number of values that have been allowed through.
    pub fn seen_count(&self) -> u64 {
        self.seen.load(Ordering::Relaxed)
    }

    /// Number of patterns registered (exact + glob).
    pub fn pattern_count(&self) -> usize {
        self.exact.len() + self.globs.len()
    }

    /// `true` if no patterns are registered (allowlist is effectively disabled).
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.globs.is_empty()
    }
}

/// Match `value` against a `*`-glob `pattern`.
///
/// `*` matches any sequence of characters (including empty). Multiple `*`
/// wildcards are supported. Matching is case-sensitive.
fn glob_matches(pattern: &str, value: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let n = parts.len();

    // First segment must be a prefix.
    if !value.starts_with(parts[0]) {
        return false;
    }
    // Last segment must be a suffix.
    if !value.ends_with(parts[n - 1]) {
        return false;
    }
    // For a single `*` these two checks are sufficient.
    if n == 2 {
        // Guard against overlap: e.g. "ab" matching "a*b" is fine, but
        // "a" with prefix "a" and suffix "b" must fail.
        return value.len() >= parts[0].len() + parts[n - 1].len();
    }

    // For multiple wildcards, verify inner segments appear in order.
    let mut pos = parts[0].len();
    let end = value.len().saturating_sub(parts[n - 1].len());
    for part in &parts[1..n - 1] {
        if part.is_empty() {
            continue;
        }
        match value[pos..end].find(part) {
            Some(found) => pos += found + part.len(),
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(pats: &[&str]) -> AllowlistMatcher {
        let (m, _) = AllowlistMatcher::new(pats.iter().map(|s| (*s).to_string()).collect());
        m
    }

    fn matcher_cs(pats: &[&str]) -> AllowlistMatcher {
        let (m, _) =
            AllowlistMatcher::new_case_sensitive(pats.iter().map(|s| (*s).to_string()).collect());
        m
    }

    #[test]
    fn exact_match() {
        // Default: case-insensitive
        let m = matcher(&["localhost", "127.0.0.1"]);
        assert!(m.is_allowed("localhost"));
        assert!(m.is_allowed("127.0.0.1"));
        assert!(m.is_allowed("Localhost"));   // now matches — case-insensitive
        assert!(m.is_allowed("LOCALHOST"));   // now matches
        assert!(!m.is_allowed("localhost2")); // suffix still fails
    }

    #[test]
    fn exact_match_case_sensitive() {
        let m = matcher_cs(&["localhost", "127.0.0.1"]);
        assert!(m.is_allowed("localhost"));
        assert!(!m.is_allowed("Localhost")); // case-sensitive: no match
        assert!(!m.is_allowed("LOCALHOST"));
    }

    #[test]
    fn glob_suffix() {
        let m = matcher(&["*.internal"]);
        assert!(m.is_allowed("db.internal"));
        assert!(m.is_allowed("staging.db.internal"));
        assert!(!m.is_allowed("db.internal.evil"));
        assert!(!m.is_allowed("internal"));
    }

    #[test]
    fn glob_prefix() {
        let m = matcher(&["192.168.1.*"]);
        assert!(m.is_allowed("192.168.1.1"));
        assert!(m.is_allowed("192.168.1.255"));
        assert!(!m.is_allowed("192.168.2.1"));
        // * matches zero or more chars, so trailing-dot form also matches
        assert!(m.is_allowed("192.168.1."));
    }

    #[test]
    fn glob_middle() {
        let m = matcher(&["user-*@corp.com"]);
        assert!(m.is_allowed("user-alice@corp.com"));
        assert!(m.is_allowed("user-bob@corp.com"));
        assert!(!m.is_allowed("admin@corp.com"));
        assert!(!m.is_allowed("user-alice@other.com"));
    }

    #[test]
    fn glob_star_only() {
        let m = matcher(&["*"]);
        assert!(m.is_allowed("anything"));
        assert!(m.is_allowed(""));
    }

    #[test]
    fn seen_counter() {
        let m = matcher(&["ok"]);
        assert_eq!(m.seen_count(), 0);
        m.is_allowed("ok");
        m.is_allowed("ok");
        m.is_allowed("not-ok");
        assert_eq!(m.seen_count(), 2);
    }

    #[test]
    fn regex_char_warning() {
        let (_, warnings) = AllowlistMatcher::new(vec!["^bad$".into()]);
        assert!(!warnings.is_empty());
    }

    #[test]
    fn empty_allowlist_is_empty() {
        let m = matcher(&[]);
        assert!(m.is_empty());
        assert!(!m.is_allowed("anything"));
    }

    // match_pattern

    #[test]
    fn match_pattern_returns_exact_pattern() {
        let m = matcher(&["localhost"]);
        assert_eq!(m.match_pattern("localhost"), Some("localhost"));
        assert_eq!(m.match_pattern("other"), None);
    }

    #[test]
    fn match_pattern_returns_glob_pattern() {
        let m = matcher(&["*.internal"]);
        assert_eq!(m.match_pattern("db.internal"), Some("*.internal"));
        assert_eq!(m.match_pattern("github.com"), None);
    }

    #[test]
    fn match_pattern_returns_first_matching_pattern() {
        let m = matcher(&["*.internal", "db.*"]);
        // "db.internal" matches both; first pattern wins
        assert_eq!(m.match_pattern("db.internal"), Some("*.internal"));
    }

    #[test]
    fn match_pattern_increments_seen_counter() {
        let m = matcher(&["ok"]);
        assert_eq!(m.seen_count(), 0);
        m.match_pattern("ok");
        assert_eq!(m.seen_count(), 1);
        m.match_pattern("not-ok");
        assert_eq!(m.seen_count(), 1);
    }

    #[test]
    fn is_allowed_delegates_to_match_pattern() {
        let m = matcher(&["*.internal"]);
        assert!(m.is_allowed("db.internal"));
        assert!(!m.is_allowed("github.com"));
        // seen counter is shared
        assert_eq!(m.seen_count(), 1);
    }

    // glob edge cases

    #[test]
    fn glob_multiple_wildcards() {
        let m = matcher(&["a*b*c"]);
        assert!(m.is_allowed("abc"));
        assert!(m.is_allowed("aXbYc"));
        assert!(m.is_allowed("aXXXbYYYc"));
        assert!(!m.is_allowed("abX"));
        assert!(!m.is_allowed("Xbc"));
    }

    #[test]
    fn glob_adjacent_wildcards_treated_as_one() {
        let m = matcher(&["a**b"]);
        assert!(m.is_allowed("ab"));
        assert!(m.is_allowed("aXb"));
        assert!(!m.is_allowed("ba"));
    }

    #[test]
    fn glob_empty_value_only_matches_star() {
        let m = matcher(&["*"]);
        assert!(m.is_allowed(""));
        let m2 = matcher(&["a*"]);
        assert!(!m2.is_allowed(""));
    }

    #[test]
    fn glob_prefix_suffix_overlap_rejected() {
        // "a*b" must not match "a" (suffix "b" requires at least one more char)
        let m = matcher(&["a*b"]);
        assert!(!m.is_allowed("a"));
        assert!(!m.is_allowed("b"));
        assert!(m.is_allowed("ab"));
        assert!(m.is_allowed("aXb"));
    }

    #[test]
    fn large_exact_list_all_match() {
        // Verify HashSet lookup works correctly across many entries.
        let words: Vec<String> = (0..500).map(|i| format!("word{i}")).collect();
        let (m, _) = AllowlistMatcher::new(words.clone());
        for w in &words {
            assert!(m.is_allowed(w), "should allow {w}");
        }
        assert!(!m.is_allowed("word500"));
        assert!(!m.is_allowed("notaword"));
    }

    #[test]
    fn exact_and_glob_coexist() {
        let m = matcher(&["localhost", "127.0.0.1", "*.internal"]);
        assert!(m.is_allowed("localhost"));
        assert!(m.is_allowed("127.0.0.1"));
        assert!(m.is_allowed("db.internal"));
        assert!(!m.is_allowed("github.com"));
    }
}
