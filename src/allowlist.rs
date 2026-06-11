//! Allowlist for suppressing specific values from sanitization.
//!
//! Values matching an allowlist entry pass through the output unchanged and
//! are **not** recorded in the [`MappingStore`](crate::store::MappingStore).
//! This means they also won't propagate to the Phase 2 augmented scanner as
//! discovered literals — a value that is allowed stays allowed everywhere.
//!
//! # Pattern syntax
//!
//! Three pattern forms are supported:
//!
//! | Pattern                          | Matches                                        |
//! |----------------------------------|------------------------------------------------|
//! | `localhost`                      | Exactly `localhost`                            |
//! | `*.internal`                     | Any value ending with `.internal` (glob)       |
//! | `192.168.1.*`                    | Any value starting with `192.168.1.` (glob)    |
//! | `user-*@corp.com`                | Prefix + suffix glob                           |
//! | `regex:^192\.168\.[0-9]+\.[0-9]+$` | Full regex match                             |
//!
//! **Glob patterns** use `*` as the only wildcard (matches any sequence of
//! characters). Multiple `*` wildcards are supported. Globs are
//! case-insensitive by default (see [`AllowlistMatcher::new_case_sensitive`]).
//!
//! **Regex patterns** are prefixed with `regex:`. The remainder is compiled as
//! a [`regex::Regex`] and matched against the full value. Regex patterns are
//! always case-sensitive; use the `(?i)` flag inside the pattern for
//! case-insensitive matching. The `regex:` prefix is stripped before
//! compiling, so `regex:^foo$` compiles to `^foo$`.
//!
//! If a regex fails to compile, a warning is returned and the pattern is
//! skipped (the matcher continues without it rather than panicking).
//!
//! If a plain pattern (no `*`, no `regex:` prefix) contains regex
//! metacharacters (`^`, `$`, `+`, `(`, `)`), a warning is emitted suggesting
//! the `regex:` prefix — those characters are still matched literally in the
//! plain form.

use regex::Regex;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// Result of building an [`AllowlistMatcher`].
///
/// Returned by [`AllowlistMatcher::new`] and
/// [`AllowlistMatcher::new_case_sensitive`].
///
/// The `#[must_use]` attribute ensures callers don't silently discard
/// [`warnings`](Self::warnings), which includes failed regex compilations
/// (the pattern is **skipped** — values that should be suppressed will
/// instead be sanitized) and metacharacter hints.
#[must_use = "check .warnings for invalid or suspicious patterns"]
pub struct AllowlistResult {
    /// The compiled matcher, ready for use.
    pub matcher: AllowlistMatcher,
    /// Non-fatal build warnings. Includes:
    /// - `regex:` patterns that failed to compile (pattern was skipped).
    /// - Plain patterns containing regex metacharacters (`^`, `$`, `+`,
    ///   `(`, `)`) that are matched literally; add the `regex:` prefix to
    ///   use them as regexes.
    pub warnings: Vec<String>,
}

/// Compiled allowlist that can be queried concurrently.
///
/// Exact patterns are stored in a [`HashSet`] for O(1) lookup. Glob patterns
/// (those containing `*`) are stored in a [`Vec`] and scanned linearly after
/// the hash check misses. Regex patterns (`regex:` prefix) are stored in a
/// separate [`Vec`] and tried last. This means allowlists with many exact
/// entries — the common case — pay no linear scan cost.
///
/// # Case sensitivity
///
/// By default the matcher is **case-insensitive**: patterns and query values
/// are both lowercased before comparison (applies to exact and glob patterns
/// only). Use [`AllowlistMatcher::new_case_sensitive`] when exact-case
/// matching is required. Regex patterns (`regex:` prefix) are always
/// case-sensitive; use the `(?i)` flag inside the pattern for
/// case-insensitive regex matching.
pub struct AllowlistMatcher {
    exact: HashSet<String>,
    globs: Vec<String>,
    /// `(original_pattern_string, compiled_regex)` pairs from `regex:` entries.
    regexes: Vec<(String, Regex)>,
    /// When `false` (the default), patterns and query values are lowercased
    /// before comparison (exact and glob only; regex patterns are unaffected).
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
    /// `(`, or `)`) are accepted but a warning message is included in
    /// [`AllowlistResult::warnings`] so the caller can surface it to the user.
    ///
    /// Always check [`AllowlistResult::warnings`]: a failed `regex:` pattern
    /// is skipped silently, meaning values that should be suppressed will
    /// instead be sanitized.
    #[allow(clippy::new_ret_no_self)] // intentional: returns AllowlistResult, not Self
    pub fn new(patterns: Vec<String>) -> AllowlistResult {
        let (matcher, warnings) = Self::build(patterns, false);
        AllowlistResult { matcher, warnings }
    }

    /// Build a case-sensitive [`AllowlistMatcher`] from a list of pattern strings.
    ///
    /// Use this when exact-case matching is required (e.g. allowlisting a
    /// known token value that must not match differently-cased substrings).
    ///
    /// Always check [`AllowlistResult::warnings`]: a failed `regex:` pattern
    /// is skipped silently.
    pub fn new_case_sensitive(patterns: Vec<String>) -> AllowlistResult {
        let (matcher, warnings) = Self::build(patterns, true);
        AllowlistResult { matcher, warnings }
    }

    fn build(patterns: Vec<String>, case_sensitive: bool) -> (Self, Vec<String>) {
        let mut exact = HashSet::new();
        let mut globs = Vec::new();
        let mut regexes = Vec::new();
        let mut warnings = Vec::new();

        for pat in patterns {
            if let Some(re_src) = pat.strip_prefix("regex:") {
                match Regex::new(re_src) {
                    Ok(compiled) => regexes.push((pat, compiled)),
                    Err(e) => warnings.push(format!(
                        "allowlist pattern '{pat}' failed to compile: {e} — pattern skipped"
                    )),
                }
                continue;
            }

            for ch in ['^', '$', '+', '(', ')'] {
                // '$' followed by '{' is template-variable syntax (e.g. ${VAR}),
                // not a regex end-anchor — skip the warning for that form.
                if ch == '$' && !pat.replace("${", "").contains('$') {
                    continue;
                }
                if pat.contains(ch) {
                    warnings.push(format!(
                        "allowlist pattern '{pat}' contains regex character '{ch}'; \
                         it is matched literally — use the 'regex:' prefix for regex syntax"
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
                regexes,
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
    /// Lookup order: exact hash → glob scan → regex scan. Increments the seen
    /// counter when a match is found.
    ///
    /// Exact and glob patterns are case-insensitive by default (the matcher
    /// built by [`new`](Self::new) lowercases both patterns and query values
    /// before comparison). Regex patterns (`regex:` prefix) are always matched
    /// against the original, un-lowercased value regardless of the
    /// case-sensitivity setting; use `(?i)` inside the pattern for
    /// case-insensitive regex matching.
    pub fn match_pattern<'a>(&'a self, value: &str) -> Option<&'a str> {
        // Exact + glob: apply case normalization.
        let normalized: std::borrow::Cow<str> = if self.case_sensitive {
            std::borrow::Cow::Borrowed(value)
        } else {
            std::borrow::Cow::Owned(value.to_lowercase())
        };
        if let Some(s) = self.exact.get(normalized.as_ref()) {
            self.seen.fetch_add(1, Ordering::Relaxed);
            return Some(s.as_str());
        }
        for pat in &self.globs {
            if glob_matches(pat, &normalized) {
                self.seen.fetch_add(1, Ordering::Relaxed);
                return Some(pat.as_str());
            }
        }
        // Regex: always match against the original value (regex has (?i) for
        // case-insensitive matching; we must not pre-lowercase the input).
        for (pat_str, re) in &self.regexes {
            if re.is_match(value) {
                self.seen.fetch_add(1, Ordering::Relaxed);
                return Some(pat_str.as_str());
            }
        }
        None
    }

    /// Total number of values that have been allowed through.
    pub fn seen_count(&self) -> u64 {
        self.seen.load(Ordering::Relaxed)
    }

    /// Number of patterns registered (exact + glob + regex).
    pub fn pattern_count(&self) -> usize {
        self.exact.len() + self.globs.len() + self.regexes.len()
    }

    /// `true` if no patterns are registered (allowlist is effectively disabled).
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.globs.is_empty() && self.regexes.is_empty()
    }
}

/// Match `value` against a `*`-glob `pattern`.
///
/// `*` matches any sequence of characters (including empty). Multiple `*`
/// wildcards are supported. Matching is case-sensitive.
pub(crate) fn glob_matches(pattern: &str, value: &str) -> bool {
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
        AllowlistMatcher::new(pats.iter().map(|s| (*s).to_string()).collect()).matcher
    }

    fn matcher_cs(pats: &[&str]) -> AllowlistMatcher {
        AllowlistMatcher::new_case_sensitive(pats.iter().map(|s| (*s).to_string()).collect())
            .matcher
    }

    #[test]
    fn exact_match() {
        // Default: case-insensitive
        let m = matcher(&["localhost", "127.0.0.1"]);
        assert!(m.is_allowed("localhost"));
        assert!(m.is_allowed("127.0.0.1"));
        assert!(m.is_allowed("Localhost")); // now matches — case-insensitive
        assert!(m.is_allowed("LOCALHOST")); // now matches
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
        let result = AllowlistMatcher::new(vec!["^bad$".into()]);
        assert!(!result.warnings.is_empty());
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
        let m = AllowlistMatcher::new(words.clone()).matcher;
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

    // ── regex: prefix ──────────────────────────────────────────────────────

    #[test]
    fn regex_basic_match() {
        let m = matcher(&["regex:^192\\.168\\.[0-9]+\\.[0-9]+$"]);
        assert!(m.is_allowed("192.168.1.1"));
        assert!(m.is_allowed("192.168.100.255"));
        assert!(!m.is_allowed("192.168.1.")); // trailing dot
        assert!(!m.is_allowed("10.0.0.1"));
    }

    #[test]
    fn regex_substring_match_without_anchors() {
        // Without ^ and $, the regex matches as a substring.
        let m = matcher(&["regex:internal"]);
        assert!(m.is_allowed("db.internal.corp"));
        assert!(m.is_allowed("internal"));
        assert!(!m.is_allowed("external"));
    }

    #[test]
    fn regex_anchored_full_match() {
        let m = matcher(&["regex:^token-[A-Z]{3}-[0-9]{4}$"]);
        assert!(m.is_allowed("token-ABC-1234"));
        assert!(!m.is_allowed("token-AB-1234")); // too short
        assert!(!m.is_allowed("xtoken-ABC-1234")); // extra prefix
    }

    #[test]
    fn regex_case_sensitive_by_default() {
        // regex: patterns are always case-sensitive; (?i) opts in.
        let m = matcher(&["regex:^localhost$"]);
        assert!(m.is_allowed("localhost"));
        assert!(!m.is_allowed("LOCALHOST"));
        assert!(!m.is_allowed("Localhost"));
    }

    #[test]
    fn regex_case_insensitive_via_flag() {
        let m = matcher(&["regex:(?i)^localhost$"]);
        assert!(m.is_allowed("localhost"));
        assert!(m.is_allowed("LOCALHOST"));
        assert!(m.is_allowed("LocalHost"));
    }

    #[test]
    fn regex_invalid_pattern_produces_warning_and_is_skipped() {
        let result = AllowlistMatcher::new(vec!["regex:[invalid".into()]);
        assert!(!result.warnings.is_empty(), "invalid regex must produce a warning");
        assert!(result.warnings[0].contains("failed to compile"));
        // Pattern is skipped — nothing is allowed.
        assert!(!result.matcher.is_allowed("anything"));
        assert_eq!(result.matcher.pattern_count(), 0);
    }

    #[test]
    fn regex_match_pattern_returns_full_prefixed_string() {
        let m = matcher(&["regex:^10\\.0\\."]);
        assert_eq!(m.match_pattern("10.0.1.5"), Some("regex:^10\\.0\\."),);
        assert_eq!(m.match_pattern("192.168.1.1"), None);
    }

    #[test]
    fn regex_seen_counter_increments() {
        let m = matcher(&["regex:^test"]);
        assert_eq!(m.seen_count(), 0);
        m.is_allowed("test-value");
        m.is_allowed("test-value");
        m.is_allowed("other");
        assert_eq!(m.seen_count(), 2);
    }

    #[test]
    fn regex_coexists_with_exact_and_glob() {
        let m = matcher(&[
            "localhost",
            "*.internal",
            "regex:^10\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
        ]);
        assert!(m.is_allowed("localhost"));
        assert!(m.is_allowed("db.internal"));
        assert!(m.is_allowed("10.0.0.1"));
        assert!(m.is_allowed("10.255.255.255"));
        assert!(!m.is_allowed("192.168.1.1"));
        assert!(!m.is_allowed("github.com"));
        assert_eq!(m.pattern_count(), 3);
    }

    #[test]
    fn regex_not_subject_to_case_insensitive_lowercasing() {
        // The case-insensitive matcher lowercases exact/glob query values,
        // but regex must receive the original value to honour (?i) correctly.
        let m = matcher(&["regex:^[A-Z]{3}$"]); // matches exactly 3 uppercase letters
        assert!(m.is_allowed("ABC"));
        assert!(!m.is_allowed("abc")); // no (?i) — must not match lowercased
    }

    #[test]
    fn metacharacter_warning_updated_to_suggest_regex_prefix() {
        let result = AllowlistMatcher::new(vec!["^bad$".into()]);
        assert!(!result.warnings.is_empty());
        assert!(
            result.warnings[0].contains("regex:"),
            "warning should suggest regex: prefix, got: {}",
            result.warnings[0],
        );
    }
}
