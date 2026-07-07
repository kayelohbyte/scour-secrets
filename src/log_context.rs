//! Log context extraction — finds keyword-matching lines and captures
//! surrounding context windows for LLM-friendly log triage.
//!
//! The extractor scans sanitized output line-by-line for any configured
//! keyword (substring match). For each hit it records the matching line,
//! up to N lines of context before and after, and the 1-based line number
//! so engineers can locate the entry in the original file.
//!
//! # Example
//!
//! ```rust
//! use scour_secrets::log_context::{LogContextConfig, extract_context};
//!
//! let log = "INFO  start\nERROR disk full\nINFO  retrying\nINFO  done";
//!
//! let config = LogContextConfig::new().with_context_lines(1);
//! let result = extract_context(log, &config);
//!
//! assert_eq!(result.match_count, 1);
//! assert_eq!(result.matches[0].line_number, 2);
//! assert_eq!(result.matches[0].keyword, "error");
//! assert_eq!(result.matches[0].before, vec!["INFO  start"]);
//! assert_eq!(result.matches[0].after,  vec!["INFO  retrying"]);
//! ```

use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, io};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Built-in keywords used when no custom list is provided.
pub const DEFAULT_KEYWORDS: &[&str] = &[
    "error",
    "failure",
    "warning",
    "warn",
    "fatal",
    "exception",
    "critical",
];

/// Default lines of context captured before and after each match.
pub const DEFAULT_CONTEXT_LINES: usize = 10;

/// Default cap on matches returned in a single result.
pub const DEFAULT_MAX_MATCHES: usize = 50;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for [`extract_context`].
///
/// Built with a fluent API; all setters consume and return `Self`.
///
/// # Example
///
/// ```rust
/// use scour_secrets::log_context::LogContextConfig;
///
/// let config = LogContextConfig::new()
///     .with_extra_keywords(["timeout", "oomkilled"])
///     .with_context_lines(15)
///     .with_max_matches(100);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LogContextConfig {
    /// Keywords to scan for. Each is matched as a substring of the line.
    pub keywords: Vec<String>,

    /// Lines of context captured before and after each match.
    pub context_lines: usize,

    /// Maximum number of matches to return before setting
    /// [`LogContextResult::truncated`].
    pub max_matches: usize,

    /// When `true`, keyword matching is case-sensitive. Default: `false`.
    pub case_sensitive: bool,
}

impl Default for LogContextConfig {
    fn default() -> Self {
        Self {
            keywords: DEFAULT_KEYWORDS.iter().map(|&s| s.to_owned()).collect(),
            context_lines: DEFAULT_CONTEXT_LINES,
            max_matches: DEFAULT_MAX_MATCHES,
            case_sensitive: false,
        }
    }
}

impl LogContextConfig {
    /// Create a config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge additional keywords into the existing list without replacing defaults.
    #[must_use]
    pub fn with_extra_keywords(
        mut self,
        extra: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.keywords.extend(extra.into_iter().map(Into::into));
        self
    }

    /// Replace all keywords with the given list.
    #[must_use]
    pub fn with_keywords(mut self, keywords: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.keywords = keywords.into_iter().map(Into::into).collect();
        self
    }

    /// Set how many lines of context to capture around each match.
    #[must_use]
    pub fn with_context_lines(mut self, n: usize) -> Self {
        self.context_lines = n;
        self
    }

    /// Set the maximum number of matches to return.
    #[must_use]
    pub fn with_max_matches(mut self, n: usize) -> Self {
        self.max_matches = n;
        self
    }

    /// Set case-sensitivity for keyword matching.
    #[must_use]
    pub fn case_sensitive(mut self, sensitive: bool) -> Self {
        self.case_sensitive = sensitive;
        self
    }
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// A single keyword match with surrounding context lines.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct LogContextMatch {
    /// 1-based line number of the matching line.
    pub line_number: usize,

    /// The keyword that triggered this match (preserves original casing
    /// from the config, not the casing found in the log line).
    pub keyword: String,

    /// The matching line as-is from the (sanitized) content.
    pub line: String,

    /// Up to [`LogContextConfig::context_lines`] lines immediately before
    /// the match, in document order.
    pub before: Vec<String>,

    /// Up to [`LogContextConfig::context_lines`] lines immediately after
    /// the match, in document order.
    pub after: Vec<String>,
}

/// Output of [`extract_context`].
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct LogContextResult {
    /// Total number of lines in the input.
    pub total_lines: usize,

    /// Number of matches present in [`Self::matches`].
    /// When [`Self::truncated`] is `true` this equals `max_matches`
    /// and additional matches exist beyond what was returned.
    pub match_count: usize,

    /// `true` when scanning stopped early because `max_matches` was reached.
    /// The caller should increase `max_matches` or narrow the keyword list
    /// if full coverage is required.
    pub truncated: bool,

    /// The matched lines and their context windows, in document order.
    pub matches: Vec<LogContextMatch>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Normalise keywords for comparison.
///
/// Returns each keyword as-is in case-sensitive mode, or lowercased otherwise.
/// Both `extract_context` and `extract_context_reader` call this once at the
/// top so the normalisation cost is paid only once per invocation.
fn normalize_keywords(keywords: &[String], case_sensitive: bool) -> Vec<String> {
    keywords
        .iter()
        .map(|kw| {
            if case_sensitive {
                kw.clone()
            } else {
                kw.to_lowercase()
            }
        })
        .collect()
}

/// Return the index of the first keyword that appears in `line`, or `None`.
///
/// `normalised` is the pre-normalised keyword list from [`normalize_keywords`].
/// When `case_sensitive` is false, `line` is lowercased before comparison.
fn line_first_hit(line: &str, normalised: &[String], case_sensitive: bool) -> Option<usize> {
    if case_sensitive {
        normalised
            .iter()
            .position(|norm| line.contains(norm.as_str()))
    } else {
        let lower = line.to_lowercase();
        normalised
            .iter()
            .position(|norm| lower.contains(norm.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

/// Scan `content` for keyword matches and return surrounding context windows.
///
/// Each line is checked for any configured keyword as a substring match.
/// When multiple keywords appear on the same line the first keyword in
/// [`LogContextConfig::keywords`] wins. Line numbers in the output are
/// 1-based to match standard editor and log viewer conventions.
///
/// This function is allocation-efficient: lines are collected once into a
/// `Vec<&str>` and context slices reference that vec without additional copies
/// until the final owned `String`s are built for the result.
#[must_use]
pub fn extract_context(content: &str, config: &LogContextConfig) -> LogContextResult {
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();

    let normalised = normalize_keywords(&config.keywords, config.case_sensitive);

    let mut matches: Vec<LogContextMatch> = Vec::new();
    let mut truncated = false;

    for (i, &line) in lines.iter().enumerate() {
        if matches.len() >= config.max_matches {
            truncated = true;
            break;
        }

        let hit_idx = line_first_hit(line, &normalised, config.case_sensitive);

        if let Some(idx) = hit_idx {
            let before_start = i.saturating_sub(config.context_lines);
            let after_end = (i + config.context_lines + 1).min(total_lines);

            matches.push(LogContextMatch {
                line_number: i + 1,
                keyword: config.keywords[idx].clone(),
                line: line.to_owned(),
                before: lines[before_start..i]
                    .iter()
                    .map(|&s| s.to_owned())
                    .collect(),
                after: lines[i + 1..after_end]
                    .iter()
                    .map(|&s| s.to_owned())
                    .collect(),
            });
        }
    }

    let match_count = matches.len();
    LogContextResult {
        total_lines,
        match_count,
        truncated,
        matches,
    }
}

/// Streaming variant of [`extract_context`] for large inputs.
///
/// Reads `reader` line by line using a sliding ring buffer of
/// `config.context_lines` lines. Memory usage is
/// `O(context_lines × max_line_length)` regardless of total file size,
/// making it safe for multi-gigabyte log files.
///
/// Semantics match [`extract_context`]: case handling, `max_matches`,
/// `truncated`, and first-keyword-wins on a line all behave identically.
/// "Before" and "after" context windows are clipped at file boundaries.
///
/// # Example
///
/// ```rust
/// use scour_secrets::log_context::{LogContextConfig, extract_context_reader};
/// use std::io::BufReader;
///
/// let data = b"INFO start\nERROR disk full\nINFO retrying\n";
/// let config = LogContextConfig::new().with_context_lines(1);
/// let result = extract_context_reader(BufReader::new(data.as_ref()), &config).unwrap();
///
/// assert_eq!(result.match_count, 1);
/// assert_eq!(result.matches[0].line_number, 2);
/// assert_eq!(result.matches[0].before, vec!["INFO start"]);
/// assert_eq!(result.matches[0].after,  vec!["INFO retrying"]);
/// ```
///
/// # Errors
///
/// Returns an [`io::Error`] if reading from `reader` fails.
#[allow(clippy::too_many_lines)]
pub fn extract_context_reader<R: io::BufRead>(
    reader: R,
    config: &LogContextConfig,
) -> io::Result<LogContextResult> {
    struct Pending {
        line_number: usize,
        keyword: String,
        line: String,
        before: Vec<String>,
        after: Vec<String>,
        remaining: usize,
    }

    let cap = config.context_lines;
    let mut before_buf: VecDeque<String> = VecDeque::with_capacity(cap.saturating_add(1));
    let mut pending: Vec<Pending> = Vec::new();
    let mut matches: Vec<LogContextMatch> = Vec::new();
    let mut truncated = false;
    let mut total_lines: usize = 0;

    let normalised = normalize_keywords(&config.keywords, config.case_sensitive);

    let mut line_buf = String::new();
    let mut reader = reader;
    loop {
        line_buf.clear();
        let n = reader.read_line(&mut line_buf)?;
        if n == 0 {
            break;
        }
        // Strip trailing newline; preserve the rest of the line as-is.
        let line: &str = line_buf.trim_end_matches(['\n', '\r']);
        total_lines += 1;
        let line_number = total_lines;

        // Step 1: feed this line as "after" context to all pending matches.
        let mut i = 0;
        while i < pending.len() {
            pending[i].after.push(line.to_owned());
            pending[i].remaining -= 1;
            if pending[i].remaining == 0 {
                let p = pending.remove(i);
                matches.push(LogContextMatch {
                    line_number: p.line_number,
                    keyword: p.keyword,
                    line: p.line,
                    before: p.before,
                    after: p.after,
                });
            } else {
                i += 1;
            }
        }

        // Step 2: check if this line starts a new match.
        if !truncated {
            let effective_count = matches.len() + pending.len();
            let hit_idx = line_first_hit(line, &normalised, config.case_sensitive);
            if effective_count >= config.max_matches {
                // At the cap — if this line is a match, set the truncated flag.
                if hit_idx.is_some() {
                    truncated = true;
                }
            } else if let Some(idx) = hit_idx {
                let before: Vec<String> = before_buf.iter().cloned().collect();
                if cap == 0 {
                    matches.push(LogContextMatch {
                        line_number,
                        keyword: config.keywords[idx].clone(),
                        line: line.to_owned(),
                        before,
                        after: Vec::new(),
                    });
                } else {
                    pending.push(Pending {
                        line_number,
                        keyword: config.keywords[idx].clone(),
                        line: line.to_owned(),
                        before,
                        after: Vec::new(),
                        remaining: cap,
                    });
                }
            }
        }

        // Step 3: advance the before-context ring buffer.
        if cap > 0 {
            if before_buf.len() >= cap {
                before_buf.pop_front();
            }
            before_buf.push_back(line.to_owned());
        }
    }

    // Flush pending matches whose "after" windows were not fully filled
    // before EOF (context clipped at end of file).
    for p in pending {
        matches.push(LogContextMatch {
            line_number: p.line_number,
            keyword: p.keyword,
            line: p.line,
            before: p.before,
            after: p.after,
        });
    }

    let match_count = matches.len();
    Ok(LogContextResult {
        total_lines,
        match_count,
        truncated,
        matches,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(lines: &[&str]) -> String {
        lines.join("\n")
    }

    // ---- basic matching ----

    #[test]
    fn finds_error_line() {
        let log = make_log(&["INFO start", "ERROR disk full", "INFO done"]);
        let result = extract_context(&log, &LogContextConfig::new().with_context_lines(0));
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].line_number, 2);
        assert_eq!(result.matches[0].keyword, "error");
        assert_eq!(result.matches[0].line, "ERROR disk full");
    }

    #[test]
    fn case_insensitive_by_default() {
        let log = make_log(&["WARNING high load", "Warning: retry", "warn: slow"]);
        let result = extract_context(&log, &LogContextConfig::new().with_context_lines(0));
        assert_eq!(result.match_count, 3);
    }

    #[test]
    fn case_sensitive_skips_uppercase() {
        let log = make_log(&["ERROR upper", "error lower"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .case_sensitive(true)
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].line, "error lower");
    }

    // ---- context windows ----

    #[test]
    fn before_and_after_lines() {
        let log = make_log(&["a", "b", "ERROR c", "d", "e"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(1);
        let result = extract_context(&log, &config);
        assert_eq!(result.matches[0].before, vec!["b"]);
        assert_eq!(result.matches[0].after, vec!["d"]);
    }

    #[test]
    fn context_clipped_at_file_start() {
        let log = make_log(&["ERROR first", "INFO second", "INFO third"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(5);
        let result = extract_context(&log, &config);
        assert!(result.matches[0].before.is_empty());
        assert_eq!(result.matches[0].after.len(), 2);
    }

    #[test]
    fn context_clipped_at_file_end() {
        let log = make_log(&["INFO first", "INFO second", "ERROR last"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(5);
        let result = extract_context(&log, &config);
        assert_eq!(result.matches[0].before.len(), 2);
        assert!(result.matches[0].after.is_empty());
    }

    #[test]
    fn context_lines_zero() {
        let log = make_log(&["a", "ERROR b", "c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert!(result.matches[0].before.is_empty());
        assert!(result.matches[0].after.is_empty());
    }

    // ---- multiple matches ----

    #[test]
    fn multiple_matches_in_order() {
        let log = make_log(&["ERROR a", "INFO b", "FATAL c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error", "fatal"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 2);
        assert_eq!(result.matches[0].line_number, 1);
        assert_eq!(result.matches[0].keyword, "error");
        assert_eq!(result.matches[1].line_number, 3);
        assert_eq!(result.matches[1].keyword, "fatal");
    }

    #[test]
    fn first_keyword_wins_on_same_line() {
        let log = "ERROR and WARNING on same line";
        let config = LogContextConfig::new()
            .with_keywords(["error", "warning"])
            .with_context_lines(0);
        let result = extract_context(log, &config);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].keyword, "error");
    }

    // ---- max_matches and truncation ----

    #[test]
    fn truncated_when_max_reached() {
        let lines: Vec<String> = (0..10).map(|i| format!("ERROR line {i}")).collect();
        let log = lines.join("\n");
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_max_matches(3)
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 3);
        assert!(result.truncated);
    }

    #[test]
    fn not_truncated_under_limit() {
        let log = make_log(&["ERROR a", "INFO b", "ERROR c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_max_matches(10)
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 2);
        assert!(!result.truncated);
    }

    // ---- extra keywords ----

    #[test]
    fn extra_keywords_merge_with_defaults() {
        let log = make_log(&["ERROR a", "OOMKILLED b"]);
        let config = LogContextConfig::new()
            .with_extra_keywords(["oomkilled"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 2);
    }

    #[test]
    fn replace_keywords_removes_defaults() {
        let log = make_log(&["ERROR a", "CUSTOM b"]);
        let config = LogContextConfig::new()
            .with_keywords(["custom"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].keyword, "custom");
    }

    // ---- edge cases ----

    #[test]
    fn empty_content() {
        let result = extract_context("", &LogContextConfig::new());
        assert_eq!(result.total_lines, 0);
        assert_eq!(result.match_count, 0);
        assert!(!result.truncated);
    }

    #[test]
    fn no_matches() {
        let log = make_log(&["INFO all good", "DEBUG trace", "INFO done"]);
        let result = extract_context(&log, &LogContextConfig::new());
        assert_eq!(result.match_count, 0);
        assert!(!result.truncated);
        assert_eq!(result.total_lines, 3);
    }

    #[test]
    fn single_line_match() {
        let result = extract_context("ERROR only line", &LogContextConfig::new());
        assert_eq!(result.total_lines, 1);
        assert_eq!(result.match_count, 1);
        assert!(result.matches[0].before.is_empty());
        assert!(result.matches[0].after.is_empty());
    }

    #[test]
    fn line_numbers_are_one_based() {
        let log = make_log(&["INFO a", "INFO b", "ERROR c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.matches[0].line_number, 3);
    }

    #[test]
    fn keyword_original_case_preserved_in_output() {
        let log = "TIMEOUT occurred";
        let config = LogContextConfig::new()
            .with_keywords(["Timeout"])
            .with_context_lines(0);
        let result = extract_context(log, &config);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].keyword, "Timeout");
    }

    // ---- extract_context_reader ----

    fn reader_of(lines: &[&str]) -> std::io::BufReader<std::io::Cursor<Vec<u8>>> {
        let s = lines.join("\n");
        std::io::BufReader::new(std::io::Cursor::new(s.into_bytes()))
    }

    #[test]
    fn reader_finds_error_line() {
        let r = reader_of(&["INFO start", "ERROR disk full", "INFO done"]);
        let result =
            extract_context_reader(r, &LogContextConfig::new().with_context_lines(0)).unwrap();
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].line_number, 2);
        assert_eq!(result.matches[0].line, "ERROR disk full");
    }

    #[test]
    fn reader_before_and_after_context() {
        let r = reader_of(&["a", "b", "ERROR c", "d", "e"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(1);
        let result = extract_context_reader(r, &config).unwrap();
        assert_eq!(result.matches[0].before, vec!["b"]);
        assert_eq!(result.matches[0].after, vec!["d"]);
    }

    #[test]
    fn reader_case_insensitive_by_default() {
        let r = reader_of(&["Warning: high load", "WARNING again", "warn: slow"]);
        let result =
            extract_context_reader(r, &LogContextConfig::new().with_context_lines(0)).unwrap();
        assert_eq!(result.match_count, 3);
    }

    #[test]
    fn reader_case_sensitive_skips_uppercase() {
        let r = reader_of(&["ERROR upper", "error lower"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .case_sensitive(true)
            .with_context_lines(0);
        let result = extract_context_reader(r, &config).unwrap();
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].line, "error lower");
    }

    #[test]
    fn reader_truncates_at_max_matches() {
        let lines: Vec<String> = (0..10).map(|i| format!("ERROR line {i}")).collect();
        let strs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let r = reader_of(&strs);
        let config = LogContextConfig::new()
            .with_context_lines(0)
            .with_max_matches(3);
        let result = extract_context_reader(r, &config).unwrap();
        assert_eq!(result.match_count, 3);
        assert!(result.truncated);
    }

    #[test]
    fn reader_after_context_clipped_at_eof() {
        // Match is near the end — after-context window can't be fully filled.
        let r = reader_of(&["a", "b", "ERROR c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(3);
        let result = extract_context_reader(r, &config).unwrap();
        assert_eq!(result.match_count, 1);
        // Only 0 lines after the match before EOF.
        assert!(result.matches[0].after.is_empty());
    }

    #[test]
    fn reader_total_lines_counted() {
        let r = reader_of(&["a", "b", "c", "d", "e"]);
        let result =
            extract_context_reader(r, &LogContextConfig::new().with_context_lines(0)).unwrap();
        assert_eq!(result.total_lines, 5);
        assert_eq!(result.match_count, 0);
    }

    #[test]
    fn reader_empty_input() {
        let r = reader_of(&[]);
        let result =
            extract_context_reader(r, &LogContextConfig::new().with_context_lines(0)).unwrap();
        assert_eq!(result.total_lines, 0);
        assert_eq!(result.match_count, 0);
    }

    // ---- serialization ----

    #[test]
    fn result_serializes_to_json() {
        let log = make_log(&["INFO ok", "ERROR fail", "INFO ok"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(1);
        let result = extract_context(&log, &config);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("\"line_number\": 2"));
        assert!(json.contains("\"keyword\": \"error\""));
        assert!(json.contains("\"total_lines\": 3"));
        assert!(json.contains("\"truncated\": false"));
    }
}
