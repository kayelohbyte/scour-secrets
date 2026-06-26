//! Streaming scanner for detecting and replacing sensitive data.
//!
//! # Architecture
//!
//! The streaming scanner processes input data in configurable chunks,
//! detecting secret patterns (regex or literal) and applying one-way
//! replacements via the [`MappingStore`].
//! This design supports files of 20–100 GB+ without requiring the entire
//! content to fit in memory.
//!
//! ```text
//! ┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
//! │  Input (Read) │ ──▶ │  StreamScanner  │ ──▶ │  Output (Write)  │
//! │  (chunked)    │     │  (pattern match │     │  (sanitized)     │
//! └──────────────┘     │   + replace)    │     └──────────────────┘
//!                       └────────┬────────┘
//!                                │
//!                       ┌────────▼────────┐
//!                       │  MappingStore   │
//!                       │  (dedup cache)  │
//!                       └─────────────────┘
//! ```
//!
//! # Chunk Overlap Strategy
//!
//! To avoid missing matches that span chunk boundaries, the scanner
//! maintains an overlap window between consecutive chunks:
//!
//! 1. Read `chunk_size` bytes of new data.
//! 2. Prepend the `carry` buffer (tail of previous window).
//! 3. Scan the combined `window` for all pattern matches.
//! 4. Compute `commit_point = window.len() - overlap_size`, then adjust:
//!    a match fully inside the window that straddles the boundary moves the
//!    commit point *up* (so it is emitted whole); a match that runs to the
//!    right edge of the window may be truncated by the buffer, so the commit
//!    point is pulled *back* to its start and the whole match is carried.
//! 5. Emit output for `window[..commit_point]` with replacements applied.
//! 6. Set `carry = window[commit_point..]` for the next iteration.
//!
//! Matches up to `chunk_size` bytes are therefore always seen in full before
//! being committed. A single match longer than `chunk_size` (a pathological
//! unbroken token) can never be buffered; rather than leak its tail, the
//! scanner fails closed and replaces the whole run with a fixed redaction
//! marker (see [`OVERLONG_MARKER`]).
//!
//! # Thread Safety
//!
//! [`StreamScanner`] is `Send + Sync`. Multiple files can be scanned
//! concurrently using a shared `Arc<StreamScanner>`, all backed by the
//! same [`MappingStore`] for per-run dedup
//! consistency.
//!
//! # Performance
//!
//! - **Chunk-based I/O**: only `chunk_size + overlap_size` bytes in
//!   memory per active scan.
//! - **Compiled regex**: patterns are compiled once at construction and
//!   reused across all chunks and files.
//! - **Lock-free reads**: the `DashMap` inside `MappingStore` provides
//!   lock-free reads for already-seen values.
//! - **File-level parallelism**: share `Arc<StreamScanner>` across
//!   threads to scan multiple files concurrently.

use crate::category::Category;
use crate::error::{Result, SanitizeError};
use crate::store::MappingStore;
use aho_corasick::AhoCorasick;
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default chunk size: 1 MiB.
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Default overlap size: 4 KiB.
const DEFAULT_OVERLAP_SIZE: usize = 4096;

/// Maximum compiled regex automaton size (bytes). Prevents DoS via
/// pathologically complex user-supplied patterns.
const REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// Maximum DFA cache size (bytes) per regex.
const REGEX_DFA_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// Hard ceiling on the combined RegexSet automaton budget.
/// The per-pattern limit is multiplied by the pattern count so that a large
/// pattern set can still compile, but without this cap a pathological secrets
/// file with 10 000 patterns could claim up to ~20 GiB of automaton memory.
const REGEX_SET_SIZE_CAP: usize = 256 * 1024 * 1024; // 256 MiB

/// Maximum number of patterns allowed in a single scanner (F-05 fix).
/// The `RegexSet` automaton memory scales linearly with pattern count.
/// With 1 MiB size/DFA limits per pattern, 10 000 patterns could
/// allocate up to ~20 GiB of automaton memory.  This cap prevents
/// accidental resource exhaustion.  Override via
/// [`StreamScanner::new_with_max_patterns`] if needed.
const DEFAULT_MAX_PATTERNS: usize = 10_000;

/// Fixed marker emitted in place of a single match that is longer than the
/// scanner is willing to buffer (see [`StreamScanner::scan_reader_with_callbacks`]).
///
/// Such a match cannot be length-preserved (we never hold all of it in memory),
/// so the scanner fails closed: it redacts the entire over-long run with this
/// marker rather than risk emitting any of its bytes verbatim.
const OVERLONG_MARKER: &[u8] = b"__SANITIZED_OVERLONG__";

/// Pattern label reported via `on_match` for an over-long redaction.
const OVERLONG_LABEL: &str = "overlong-redacted";

/// Label suffix that marks patterns as key-value-only.
///
/// Patterns whose label ends with this suffix are excluded from the streaming
/// scanner pass (`for_structured_pass`) because the key-value processor
/// resolves their values structurally and the scanner would produce spurious
/// duplicate replacements on the surrounding syntax.
pub const KV_LABEL_SUFFIX: &str = "_kv";

/// Configuration for the streaming scanner.
///
/// # Tuning Guide
///
/// | Workload               | `chunk_size` | `overlap_size` |
/// |------------------------|--------------|----------------|
/// | Small files (< 10 MB)  | 256 KiB      | 1 KiB          |
/// | General purpose        | 1 MiB        | 4 KiB          |
/// | Large files (> 1 GB)   | 4–8 MiB      | 8 KiB          |
/// | Memory-constrained     | 64 KiB       | 1 KiB          |
///
/// `overlap_size` should be ≥ the longest expected match. Most secret
/// patterns (API keys, emails, SSNs) are well under 256 bytes, so the
/// 4 KiB default provides ample margin.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Size of each chunk read from the input (bytes).
    ///
    /// Larger chunks improve throughput (fewer syscalls) but use more
    /// memory. Default: 1 MiB.
    pub chunk_size: usize,

    /// Overlap between consecutive chunks (bytes).
    ///
    /// Must be ≥ the maximum expected match length. Patterns whose
    /// matches can exceed this length risk being missed at chunk
    /// boundaries. Default: 4 KiB.
    pub overlap_size: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            overlap_size: DEFAULT_OVERLAP_SIZE,
        }
    }
}

impl ScanConfig {
    /// Create a new configuration with explicit values.
    #[must_use]
    pub fn new(chunk_size: usize, overlap_size: usize) -> Self {
        Self {
            chunk_size,
            overlap_size,
        }
    }

    /// Validate the configuration, returning an error if invalid.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::InvalidConfig`] if `chunk_size` is zero
    /// or `overlap_size >= chunk_size`.
    pub fn validate(&self) -> Result<()> {
        if self.chunk_size == 0 {
            return Err(SanitizeError::InvalidConfig(
                "chunk_size must be > 0".into(),
            ));
        }
        if self.overlap_size >= self.chunk_size {
            return Err(SanitizeError::InvalidConfig(
                "overlap_size must be < chunk_size".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert any compile-time pattern error into [`SanitizeError::PatternCompileError`].
#[inline]
fn compile_err(e: impl std::fmt::Display) -> SanitizeError {
    SanitizeError::PatternCompileError(e.to_string())
}

// ---------------------------------------------------------------------------
// Scan pattern
// ---------------------------------------------------------------------------

/// A pattern rule defining what to scan for and how to categorize matches.
///
/// Wraps a compiled [`regex::bytes::Regex`] with a [`Category`] for
/// replacement lookups and a human-readable label for reporting.
///
/// Both regex and literal patterns are supported. Literal patterns keep
/// their original text and are matched by the scanner's Aho-Corasick
/// automaton for fast multi-literal scanning.
pub struct ScanPattern {
    /// Compiled regex matcher (used for non-literal patterns and as a
    /// fallback; literal patterns are matched via Aho-Corasick instead).
    regex: Regex,
    /// Category for replacement lookups.
    category: Category,
    /// Human-readable label for reporting / stats.
    label: String,
    /// Original (unescaped) literal string when created via `from_literal`.
    /// `None` for patterns created via `from_regex`.
    /// Stored so `StreamScanner` can build an Aho-Corasick automaton for
    /// fast SIMD literal matching instead of running the regex engine.
    literal: Option<String>,
    /// Minimum match length (bytes). Matches shorter than this are discarded.
    /// For literal patterns this defaults to the byte length of the literal
    /// itself; for regex patterns it defaults to `0` (no minimum). Set from a
    /// secrets entry's `min_length` to suppress short false positives.
    pub min_length: usize,
    /// Maximum match length (bytes). Matches longer than this are discarded.
    /// Defaults to [`usize::MAX`] (no maximum). Set from a secrets entry's
    /// `max_length` to bound a greedy pattern — this also caps how far an
    /// unbounded pattern can run before the streaming scanner's over-long
    /// redaction takes over.
    pub max_length: usize,
}

impl std::fmt::Debug for ScanPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanPattern")
            .field("pattern", &self.regex.as_str())
            .field("category", &self.category)
            .field("label", &self.label)
            .field("literal", &self.literal.as_deref())
            .field("min_length", &self.min_length)
            .field("max_length", &self.max_length)
            .finish()
    }
}

impl Clone for ScanPattern {
    fn clone(&self) -> Self {
        Self {
            regex: self.regex.clone(),
            category: self.category.clone(),
            label: self.label.clone(),
            literal: self.literal.clone(),
            min_length: self.min_length,
            max_length: self.max_length,
        }
    }
}

impl ScanPattern {
    /// Create a pattern from a regex string.
    ///
    /// ## Capture group 1 — partial replacement
    ///
    /// If the regex contains a capture group 1 (`(...)`), only the bytes
    /// matched by that group are replaced; the bytes before and after it
    /// within the full match are emitted verbatim. This lets you write
    /// context-anchored patterns without redacting the prefix/suffix:
    ///
    /// ```text
    /// pattern: glpat-([A-Za-z0-9_-]{20})
    ///           ^^^^^^ prefix preserved
    ///                  ^^^^^^^^^^^^^^^^^^^^ group 1 → replaced
    /// ```
    ///
    /// Patterns **without** a capture group replace the entire match.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::PatternCompileError`] if the regex is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_sanitize::scanner::ScanPattern;
    /// use rust_sanitize::category::Category;
    ///
    /// // No capture group — full match replaced:
    /// let email = ScanPattern::from_regex(
    ///     r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ///     Category::Email,
    ///     "email_address",
    /// ).unwrap();
    ///
    /// // Capture group 1 — prefix preserved, only the token value replaced:
    /// let token = ScanPattern::from_regex(
    ///     r"glpat-([A-Za-z0-9_-]{20})",
    ///     Category::AuthToken,
    ///     "gitlab_pat",
    /// ).unwrap();
    /// ```
    pub fn from_regex(pattern: &str, category: Category, label: impl Into<String>) -> Result<Self> {
        let regex = RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
            .map_err(compile_err)?;
        Ok(Self {
            regex,
            category,
            label: label.into(),
            literal: None,
            min_length: 0,
            max_length: usize::MAX,
        })
    }

    /// Set the inclusive match-length bounds (bytes) for this pattern.
    ///
    /// Matches shorter than `min` or longer than `max` are discarded during
    /// scanning. `min == 0` and `max == usize::MAX` impose no bound. Used to
    /// plumb a secrets entry's `min_length` / `max_length` onto a compiled
    /// pattern without changing the public constructor signatures.
    #[must_use]
    pub fn with_length_bounds(mut self, min: usize, max: usize) -> Self {
        self.min_length = min;
        self.max_length = max;
        self
    }

    /// Create a pattern from a literal string.
    ///
    /// The literal is escaped so that regex metacharacters are matched
    /// verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::PatternCompileError`] if regex compilation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_sanitize::scanner::ScanPattern;
    /// use rust_sanitize::category::Category;
    ///
    /// let pat = ScanPattern::from_literal(
    ///     "sk-proj-abc123secret",
    ///     Category::Custom("api_key".into()),
    ///     "openai_key",
    /// ).unwrap();
    /// ```
    pub fn from_literal(
        literal: &str,
        category: Category,
        label: impl Into<String>,
    ) -> Result<Self> {
        let escaped = regex::escape(literal);
        let regex = RegexBuilder::new(&escaped)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
            .map_err(compile_err)?;
        Ok(Self {
            regex,
            category,
            label: label.into(),
            min_length: literal.len(),
            max_length: usize::MAX,
            literal: Some(literal.to_owned()),
        })
    }

    /// The category this pattern maps to.
    #[must_use]
    pub fn category(&self) -> &Category {
        &self.category
    }

    /// The human-readable label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the raw regex pattern string for RegexSet construction.
    #[must_use]
    pub fn regex_pattern(&self) -> &str {
        self.regex.as_str()
    }
}

// ScanPattern is Send + Sync because:
// - regex::bytes::Regex is Send + Sync
// - Category is Send + Sync (it's an enum of primitives + CompactString)
// - String is Send + Sync

// ---------------------------------------------------------------------------
// Internal: raw match descriptor
// ---------------------------------------------------------------------------

/// A single match found during scanning (internal).
#[derive(Debug, Clone, Copy)]
struct RawMatch {
    /// Start byte offset within the scan window.
    start: usize,
    /// End byte offset (exclusive) within the scan window.
    end: usize,
    /// Index into the `StreamScanner::patterns` vector.
    pattern_idx: usize,
    /// Byte range of capture group 1 within the window, if the pattern has one.
    /// When present, only this sub-range is replaced; the bytes between
    /// `start..capture_start` and `capture_end..end` are emitted verbatim,
    /// preserving surrounding context (delimiters, key names, prefixes).
    capture: Option<(usize, usize)>,
}

// ---------------------------------------------------------------------------
// Per-scan scratch buffers
// ---------------------------------------------------------------------------

/// Scratch buffers reused across chunks within a single scan call.
///
/// Allocating these once per `scan_reader_with_progress` invocation
/// and reusing them each chunk eliminates the per-chunk heap pressure
/// that would otherwise come from `Vec` allocations in `find_matches`
/// and `apply_replacements`.
struct ScanScratch {
    /// Accumulates raw matches from all patterns before deduplication.
    all_matches: Vec<RawMatch>,
    /// Non-overlapping matches selected for the current window
    /// (populated by `find_matches`, consumed by `apply_replacements`).
    selected: Vec<RawMatch>,
    /// Output bytes for the committed region, written by `apply_replacements`.
    output: Vec<u8>,
    /// Per-pattern match counts indexed by `pattern_idx`.
    /// Reset to zero after each chunk's counts are folded into `ScanStats`.
    pattern_counts: Vec<u64>,
}

/// Result of processing one scan window.
struct WindowOutcome {
    /// How many bytes of the window were committed (emitted) this iteration.
    /// The tail `window[commit_point..]` becomes the carry for the next chunk
    /// (or, when `overlong` is set, is dropped as part of the redacted run).
    commit_point: usize,
    /// True when a single match was longer than the scanner will buffer and was
    /// redacted with [`OVERLONG_MARKER`]. The caller must drop the rest of the
    /// window and keep consuming the run until a whitespace boundary is reached.
    overlong: bool,
}

impl ScanScratch {
    fn new(pattern_count: usize, chunk_size: usize, overlap_size: usize) -> Self {
        Self {
            all_matches: Vec::with_capacity(64),
            selected: Vec::with_capacity(64),
            output: Vec::with_capacity(chunk_size + overlap_size),
            pattern_counts: vec![0u64; pattern_count],
        }
    }
}

// ---------------------------------------------------------------------------
// Scan statistics
// ---------------------------------------------------------------------------

/// The file-level position of a single scanner match.
///
/// Emitted via the `on_match` callback in
/// [`StreamScanner::scan_reader_with_callbacks`]. Line numbers are
/// 1-based and count `\n` bytes only (Unix line endings). For files with
/// Windows line endings (`\r\n`), `line` is still correct because `\n` is
/// the canonical line separator — `\r` bytes do not affect the count.
///
/// `byte_offset` is the absolute byte position of the first byte of the
/// matched region within the file (0-based). Both fields refer to the
/// *input* file, not the sanitized output.
#[derive(Debug, Clone, Serialize)]
pub struct MatchLocation {
    /// 1-based line number of the match within the file.
    pub line: u64,
    /// 0-based byte offset of the match start within the file.
    pub byte_offset: u64,
    /// Pattern label that triggered this match.
    pub pattern: String,
}

/// Statistics collected during a scan operation.
///
/// Returned by [`StreamScanner::scan_reader`] and
/// [`StreamScanner::scan_bytes`] to provide visibility into what
/// the scanner did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanStats {
    /// Total bytes read from the input.
    pub bytes_processed: u64,
    /// Total bytes written to the output.
    ///
    /// Equals `bytes_processed` under the default length-preserving policy
    /// ([`LengthPolicy::Preserve`](crate::LengthPolicy)), because replacements
    /// then match the original byte length. Under
    /// [`LengthPolicy::Randomized`](crate::LengthPolicy) replacement lengths are
    /// drawn independently of the original, so the two can differ.
    pub bytes_output: u64,
    /// Total number of matches found across all patterns.
    pub matches_found: u64,
    /// Total number of replacements applied (always == `matches_found`
    /// in one-way mode).
    pub replacements_applied: u64,
    /// Per-pattern match counts, keyed by pattern label.
    pub pattern_counts: HashMap<String, u64>,
}

/// Progress snapshot emitted during streaming scans.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ScanProgress {
    /// Total bytes read from the input so far.
    pub bytes_processed: u64,
    /// Total bytes written to the output so far.
    pub bytes_output: u64,
    /// Total input size when known.
    pub total_bytes: Option<u64>,
    /// Total number of matches found so far.
    pub matches_found: u64,
    /// Total replacements applied so far.
    pub replacements_applied: u64,
}

// ---------------------------------------------------------------------------
// StreamScanner
// ---------------------------------------------------------------------------

/// Streaming scanner that detects and replaces sensitive patterns.
///
/// Thread-safe: can be shared via `Arc<StreamScanner>` for concurrent
/// scanning of multiple files. Each call to [`scan_reader`](Self::scan_reader)
/// is independent and maintains its own chunking state.
///
/// # Usage
///
/// ```rust
/// use rust_sanitize::scanner::{StreamScanner, ScanPattern, ScanConfig};
/// use rust_sanitize::category::Category;
/// use rust_sanitize::generator::HmacGenerator;
/// use rust_sanitize::store::MappingStore;
/// use std::sync::Arc;
///
/// // 1. Build the replacement store.
/// let gen = Arc::new(HmacGenerator::new([42u8; 32]));
/// let store = Arc::new(MappingStore::new(gen, None));
///
/// // 2. Define patterns.
/// let patterns = vec![
///     ScanPattern::from_regex(
///         r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
///         Category::Email,
///         "email",
///     ).unwrap(),
/// ];
///
/// // 3. Create the scanner.
/// let scanner = StreamScanner::new(patterns, store, ScanConfig::default()).unwrap();
///
/// // 4. Scan.
/// let input = b"Contact alice@corp.com for details.";
/// let (output, stats) = scanner.scan_bytes(input).unwrap();
/// assert_eq!(stats.matches_found, 1);
/// assert!(!output.windows(b"alice@corp.com".len())
///     .any(|w| w == b"alice@corp.com"));
/// ```
pub struct StreamScanner {
    /// Compiled scan patterns (both literal and regex).
    patterns: Vec<ScanPattern>,
    /// Pre-compiled set for fast multi-pattern pre-filtering of **regex**
    /// (non-literal) patterns only.  `matches()` returns which regex-pattern
    /// indices matched, avoiding running every individual regex on each chunk
    /// (R-3 optimisation).
    regex_set: RegexSet,
    /// Maps a `RegexSet` index → index into `self.patterns`.
    /// Only non-literal patterns are in the `RegexSet`.
    regex_indices: Vec<usize>,
    /// Aho-Corasick automaton for fast SIMD literal matching.
    /// `None` when there are no literal patterns.
    aho_corasick: Option<AhoCorasick>,
    /// Maps an Aho-Corasick pattern index → index into `self.patterns`.
    /// Only literal patterns appear here.
    literal_indices: Vec<usize>,
    /// Thread-safe dedup replacement store.
    store: Arc<MappingStore>,
    /// Scanner configuration.
    config: ScanConfig,
}

/// Result of loading a secrets file into a [`StreamScanner`].
///
/// Returned by [`StreamScanner::from_encrypted_secrets`] and
/// [`StreamScanner::from_plaintext_secrets`].
///
/// The `#[must_use]` attribute guards against silently discarding
/// `allow_patterns`, which would cause values that should be suppressed
/// to be sanitized instead.
///
/// # Example
///
/// ```rust,ignore
/// let SecretsLoadResult { scanner, warnings, allow_patterns } =
///     StreamScanner::from_plaintext_secrets(bytes, None, store, config, vec![])?;
///
/// for (idx, err) in &warnings {
///     eprintln!("secrets entry {idx} failed to compile: {err}");
/// }
///
/// let (allowlist, al_warnings) = AllowlistMatcher::new(allow_patterns).into_parts();
/// let store = MappingStore::new_with_allowlist(gen, None, Arc::new(allowlist));
/// ```
#[must_use = "use allow_patterns to build an AllowlistMatcher; check warnings for skipped patterns"]
pub struct SecretsLoadResult {
    /// The compiled scanner, ready to use.
    pub scanner: StreamScanner,
    /// Secrets-file entries that failed pattern compilation:
    /// `(index_in_file, error)`. A non-empty list means some patterns were
    /// silently skipped and the scanner covers less than the full file.
    pub warnings: Vec<(usize, SanitizeError)>,
    /// Raw strings from `kind: allow` entries in the secrets file.
    /// Pass these to [`crate::allowlist::AllowlistMatcher::new`] and attach
    /// the resulting matcher to a [`crate::store::MappingStore`] via
    /// [`crate::store::MappingStore::new_with_allowlist`].
    pub allow_patterns: Vec<String>,
}

impl StreamScanner {
    /// Create a new streaming scanner.
    ///
    /// # Arguments
    ///
    /// - `patterns` — the set of patterns to scan for.
    /// - `store` — the mapping store for dedup-consistent replacements.
    /// - `config` — chunking / overlap configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::InvalidConfig`] if the configuration is
    /// invalid (e.g. `chunk_size == 0` or `overlap_size >= chunk_size`).
    pub fn new(
        patterns: Vec<ScanPattern>,
        store: Arc<MappingStore>,
        config: ScanConfig,
    ) -> Result<Self> {
        Self::new_with_max_patterns(patterns, store, config, DEFAULT_MAX_PATTERNS)
    }

    /// Create a new streaming scanner with a custom pattern limit.
    ///
    /// This is identical to [`new`](Self::new) but allows overriding the
    /// default pattern cap (10 000).  Use this
    /// when you have a legitimate need for more patterns and have
    /// verified that your system has enough memory for the resulting
    /// `RegexSet`.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::InvalidConfig`] if the configuration is
    /// invalid or the pattern count exceeds `max_patterns`.
    pub fn new_with_max_patterns(
        patterns: Vec<ScanPattern>,
        store: Arc<MappingStore>,
        config: ScanConfig,
        max_patterns: usize,
    ) -> Result<Self> {
        config.validate()?;

        // F-05 fix: enforce maximum pattern count to bound RegexSet memory.
        if patterns.len() > max_patterns {
            return Err(SanitizeError::InvalidConfig(format!(
                "pattern count ({}) exceeds maximum allowed ({}) — \
                 RegexSet memory scales linearly with pattern count",
                patterns.len(),
                max_patterns
            )));
        }

        // Partition patterns into literal (Aho-Corasick) and regex (RegexSet)
        // so each is matched by the most efficient engine.
        let mut literal_bytes: Vec<Vec<u8>> = Vec::new();
        let mut literal_indices: Vec<usize> = Vec::new();
        let mut regex_strs: Vec<&str> = Vec::new();
        let mut regex_indices: Vec<usize> = Vec::new();

        for (i, pattern) in patterns.iter().enumerate() {
            if let Some(lit) = &pattern.literal {
                literal_bytes.push(lit.as_bytes().to_vec());
                literal_indices.push(i);
            } else {
                regex_strs.push(pattern.regex_pattern());
                regex_indices.push(i);
            }
        }

        // Build Aho-Corasick automaton for literal patterns (SIMD-accelerated,
        // single O(n) pass over the input per chunk).
        let aho_corasick = if literal_bytes.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(&literal_bytes).map_err(compile_err)?)
        };

        // Build RegexSet from non-literal patterns only (R-3 pre-filter).
        let regex_set = if regex_strs.is_empty() {
            RegexSetBuilder::new(Vec::<&str>::new())
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                .build()
                .map_err(compile_err)?
        } else {
            RegexSetBuilder::new(&regex_strs)
                .size_limit((REGEX_SIZE_LIMIT * regex_strs.len().max(1)).min(REGEX_SET_SIZE_CAP))
                .dfa_size_limit(
                    (REGEX_DFA_SIZE_LIMIT * regex_strs.len().max(1)).min(REGEX_SET_SIZE_CAP),
                )
                .build()
                .map_err(compile_err)?
        };

        Ok(Self {
            patterns,
            regex_set,
            regex_indices,
            aho_corasick,
            literal_indices,
            store,
            config,
        })
    }

    /// Create a copy of this scanner extended with additional literal patterns.
    ///
    /// Clones the existing pattern set and appends `extra`, then rebuilds
    /// the internal Aho-Corasick and RegexSet automata. Used by the
    /// format-preserving structured pass to scan original bytes with
    /// discovered field-value literals added to the base pattern set.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] if automaton construction fails or the
    /// combined pattern count exceeds the default limit.
    pub fn with_extra_literals(&self, extra: Vec<ScanPattern>) -> Result<Self> {
        let mut patterns = self.patterns.clone();
        patterns.extend(extra);
        Self::new(patterns, Arc::clone(&self.store), self.config.clone())
    }

    /// Build a scanner suitable for format-preserving structured-file passes.
    ///
    /// Patterns whose labels end with `"_kv"` are excluded from the base set.
    /// Those patterns match both a key name and its value (e.g. `password: s3cr3t`)
    /// as a single unit; in a structured pass the key must survive untouched so
    /// only the discovered field-value literals are safe to replace.
    ///
    /// `extra` (the profile-discovered literals) are always included.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] if Aho-Corasick or RegexSet construction fails
    /// or the combined pattern count exceeds the default limit.
    pub fn for_structured_pass(&self, extra: Vec<ScanPattern>) -> Result<Self> {
        let mut patterns: Vec<ScanPattern> = self
            .patterns
            .iter()
            .filter(|p| !p.label.ends_with(KV_LABEL_SUFFIX))
            .cloned()
            .collect();
        patterns.extend(extra);
        Self::new(patterns, Arc::clone(&self.store), self.config.clone())
    }

    /// Scan a reader and write sanitized output to a writer.
    ///
    /// Processes the input in chunks of `config.chunk_size` bytes,
    /// maintaining an overlap window of `config.overlap_size` bytes to
    /// catch matches spanning chunk boundaries. All detected matches
    /// are replaced one-way via the [`MappingStore`].
    ///
    /// # Arguments
    ///
    /// - `reader` — input source (file, network stream, `&[u8]`, …).
    /// - `writer` — output sink (file, `Vec<u8>`, …).
    ///
    /// # Returns
    ///
    /// [`ScanStats`] with counters for bytes processed, matches found, etc.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] on I/O failures or if a replacement
    /// cannot be generated (e.g. store capacity exceeded).
    pub fn scan_reader<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<ScanStats> {
        self.scan_reader_with_callbacks(reader, writer, None, |_| {}, |_| {})
    }

    /// Scan a reader and emit progress snapshots after each committed chunk.
    ///
    /// `total_bytes` should be provided when the caller knows the full input
    /// size. When omitted, progress consumers should avoid percentages/ETA.
    ///
    /// This is a convenience wrapper around [`scan_reader_with_callbacks`](Self::scan_reader_with_callbacks)
    /// that discards per-match location information. Use that method directly
    /// when you need line numbers or byte offsets for individual matches.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] on I/O failures or if a replacement
    /// cannot be generated (e.g. store capacity exceeded).
    pub fn scan_reader_with_progress<R: Read, W: Write, F>(
        &self,
        reader: R,
        writer: W,
        total_bytes: Option<u64>,
        on_progress: F,
    ) -> Result<ScanStats>
    where
        F: FnMut(&ScanProgress),
    {
        self.scan_reader_with_callbacks(reader, writer, total_bytes, on_progress, |_| {})
    }

    /// Scan a reader, emit progress snapshots, and call `on_match` for every
    /// committed match with its 1-based line number and byte offset.
    ///
    /// `on_match` is called synchronously in the scanning thread, once per
    /// committed match, in document order. The callback receives a
    /// [`MatchLocation`] describing the pattern label, 1-based line number,
    /// and 0-based byte offset within the input file. Callers that only need
    /// aggregate counts (no per-match positions) should prefer
    /// [`scan_reader_with_progress`](Self::scan_reader_with_progress), which
    /// skips the per-byte newline counting entirely.
    ///
    /// # Performance note
    ///
    /// Enabling `on_match` adds an O(committed_bytes_between_matches)
    /// newline-counting pass inside each chunk. For files with sparse matches
    /// this overhead is proportional to file size; for dense matches (e.g. one
    /// secret per line) it is negligible. On 10–15 GiB log files with typical
    /// match densities the overhead is roughly 10–20 % of total scan time.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] on I/O failures or if a replacement
    /// cannot be generated (e.g. store capacity exceeded).
    pub fn scan_reader_with_callbacks<R: Read, W: Write, F, M>(
        &self,
        mut reader: R,
        mut writer: W,
        total_bytes: Option<u64>,
        mut on_progress: F,
        mut on_match: M,
    ) -> Result<ScanStats>
    where
        F: FnMut(&ScanProgress),
        M: FnMut(MatchLocation),
    {
        let mut stats = ScanStats::default();

        // Carry buffer: the tail of the previous window that needs
        // to be re-scanned with the next chunk.
        let mut carry: Vec<u8> = Vec::new();

        // Read buffer (reused across iterations to avoid re-allocation).
        let mut read_buf = vec![0u8; self.config.chunk_size];

        // Scan window (reused across iterations — grows to peak size then
        // stays there, avoiding per-chunk allocation).
        let mut window: Vec<u8> =
            Vec::with_capacity(self.config.chunk_size + self.config.overlap_size);

        // Scratch buffers reused every chunk to eliminate per-chunk heap
        // pressure from match collection, output building, and stats tracking.
        let mut scratch = ScanScratch::new(
            self.patterns.len(),
            self.config.chunk_size,
            self.config.overlap_size,
        );

        // Absolute file byte offset of window[0] for this iteration.
        let mut window_file_offset: u64 = 0;
        // Cumulative newline count in the file before window[0].
        let mut newlines_before_window: u64 = 0;

        // True while dropping the tail of an over-long match that was already
        // replaced with `OVERLONG_MARKER`. The run is consumed (emitting
        // nothing) until the next whitespace byte ends it. See the over-long
        // handling in `process_committed_window`.
        let mut consuming_overlong = false;

        loop {
            // Read the next chunk.
            let bytes_read = read_fully(&mut reader, &mut read_buf)?;
            let is_eof = bytes_read < read_buf.len();

            // Track only genuinely new bytes (carry was already counted).
            stats.bytes_processed += bytes_read as u64;

            if bytes_read == 0 && carry.is_empty() {
                break;
            }

            // Build the scan window: carry ++ new_data.
            // Reuse the window buffer to avoid per-chunk allocation.
            window.clear();
            window.extend_from_slice(&carry);
            window.extend_from_slice(&read_buf[..bytes_read]);

            if window.is_empty() {
                break;
            }

            // If we are still consuming an over-long redacted run, drop its
            // bytes until the first whitespace boundary, then resume normal
            // scanning on whatever follows.
            if consuming_overlong {
                if let Some(pos) = window.iter().position(u8::is_ascii_whitespace) {
                    // Run ends at the first whitespace. Drop the run bytes
                    // (already represented by the marker) and continue from the
                    // boundary byte. A non-whitespace run contains no newlines,
                    // so the newline counter is unchanged.
                    consuming_overlong = false;
                    window_file_offset += pos as u64;
                    window.drain(..pos);
                    if window.is_empty() {
                        if is_eof {
                            break;
                        }
                        carry.clear();
                        continue;
                    }
                    // Fall through to normal processing of the remainder.
                } else {
                    // Whole window is still part of the run — drop it all.
                    window_file_offset += window.len() as u64;
                    carry.clear();
                    if is_eof {
                        break;
                    }
                    continue;
                }
            }

            // Scan the window: find matches, determine commit point, apply
            // replacements, and flush the committed region to the writer.
            let outcome = self.process_committed_window(
                &window,
                is_eof,
                &mut scratch,
                &mut writer,
                &mut stats,
                window_file_offset,
                newlines_before_window,
                &mut on_match,
            )?;
            let commit_point = outcome.commit_point;

            // Advance file-level position counters for the next iteration.
            // window[commit_point] is where the next window's carry starts,
            // so that byte is at file offset (window_file_offset + commit_point).
            newlines_before_window += count_newlines(&window[..commit_point]);
            window_file_offset += commit_point as u64;

            // Fold per-chunk pattern hit counts into the cumulative stats map,
            // then emit a progress snapshot to the caller.
            self.fold_chunk_counts(&mut scratch.pattern_counts, &mut stats);
            on_progress(&ScanProgress {
                bytes_processed: stats.bytes_processed,
                bytes_output: stats.bytes_output,
                total_bytes,
                matches_found: stats.matches_found,
                replacements_applied: stats.replacements_applied,
            });

            if outcome.overlong {
                // The marker was emitted for the run head; drop the rest of this
                // window and keep consuming the run in following windows until a
                // whitespace boundary is reached. (`overlong` implies `!is_eof`.)
                window_file_offset += (window.len() - commit_point) as u64;
                consuming_overlong = true;
                carry.clear();
                continue;
            }

            // Update carry for next iteration.
            if is_eof {
                carry.clear();
                break;
            }
            carry.clear();
            carry.extend_from_slice(&window[commit_point..]);
        }

        Ok(stats)
    }

    /// Scan one window, apply replacements up to the commit point, and flush
    /// the result to `writer`. Returns the commit point so the caller can
    /// slice the carry for the next iteration.
    #[allow(clippy::too_many_arguments)]
    fn process_committed_window(
        &self,
        window: &[u8],
        is_eof: bool,
        scratch: &mut ScanScratch,
        writer: &mut dyn io::Write,
        stats: &mut ScanStats,
        window_file_offset: u64,
        newlines_before_window: u64,
        on_match: &mut dyn FnMut(MatchLocation),
    ) -> Result<WindowOutcome> {
        // Find all non-overlapping matches in the window.
        self.find_matches(window, scratch);

        // Determine how much of the window can be safely committed this iteration.
        let base_commit = if is_eof {
            window.len()
        } else {
            window.len().saturating_sub(self.config.overlap_size)
        };
        let commit_point =
            self.adjusted_commit_point(&scratch.selected, base_commit, window.len(), is_eof);

        // If `adjusted_commit_point` pulled the commit back to carry an
        // edge-touching match, the carry is `window[commit_point..]`. When that
        // carry would exceed `max_carry`, a single match is longer than we are
        // willing to hold in memory (a pathological unbroken token larger than a
        // chunk). We can neither length-preserve it nor safely commit it, so we
        // fail closed: redact the run with a fixed marker. `max_carry` is the
        // chunk size, so peak memory stays ≈ `2 * chunk_size + overlap`.
        let max_carry = self.config.chunk_size;
        let overlong = !is_eof && window.len().saturating_sub(commit_point) > max_carry;

        // Build output for the committed region (fills scratch.output).
        self.apply_replacements(
            &window[..commit_point],
            &scratch.selected,
            stats,
            &mut scratch.output,
            &mut scratch.pattern_counts,
            window_file_offset,
            newlines_before_window,
            on_match,
        )?;

        writer.write_all(&scratch.output)?;
        stats.bytes_output += scratch.output.len() as u64;

        if overlong {
            // The over-long match starts exactly at `commit_point` (it is the
            // sole match occupying the window tail) and continues past the
            // window edge. Emit one redaction marker for it; the caller drops
            // the remaining run bytes across this and following windows.
            writer.write_all(OVERLONG_MARKER)?;
            stats.bytes_output += OVERLONG_MARKER.len() as u64;
            stats.matches_found += 1;
            stats.replacements_applied += 1;
            on_match(MatchLocation {
                line: newlines_before_window
                    + count_newlines(&window[..commit_point])
                    + 1,
                byte_offset: window_file_offset + commit_point as u64,
                pattern: OVERLONG_LABEL.to_string(),
            });
        }

        Ok(WindowOutcome {
            commit_point,
            overlong,
        })
    }

    /// Fold per-chunk pattern hit counts into the cumulative `stats.pattern_counts`
    /// map, then reset `counts` to zero for the next chunk.
    ///
    /// `label.clone()` is called at most once per distinct pattern per chunk,
    /// not once per match hit, which keeps cost proportional to pattern count.
    fn fold_chunk_counts(&self, counts: &mut [u64], stats: &mut ScanStats) {
        for (idx, count) in counts.iter_mut().enumerate() {
            if *count > 0 {
                *stats
                    .pattern_counts
                    .entry(self.patterns[idx].label.clone())
                    .or_insert(0) += *count;
                *count = 0;
            }
        }
    }

    /// Convenience: scan byte slice in-memory and return sanitized output.
    ///
    /// Equivalent to `scan_reader(input, Vec::new())` but returns the
    /// output buffer directly.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] if a replacement cannot be generated
    /// (e.g. store capacity exceeded).
    pub fn scan_bytes(&self, input: &[u8]) -> Result<(Vec<u8>, ScanStats)> {
        self.scan_bytes_with_progress(input, |_| {})
    }

    /// Scan a byte slice in memory and emit progress snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] if a replacement cannot be generated
    /// (e.g. store capacity exceeded).
    pub fn scan_bytes_with_progress<F>(
        &self,
        input: &[u8],
        on_progress: F,
    ) -> Result<(Vec<u8>, ScanStats)>
    where
        F: FnMut(&ScanProgress),
    {
        let mut output = Vec::with_capacity(input.len());
        let stats = self.scan_reader_with_callbacks(
            input,
            &mut output,
            Some(input.len() as u64),
            on_progress,
            |_| {},
        )?;
        Ok((output, stats))
    }

    // ---- Accessors ----

    /// Access the scanner's configuration.
    #[must_use]
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Access the underlying mapping store.
    #[must_use]
    pub fn store(&self) -> &Arc<MappingStore> {
        &self.store
    }

    /// Number of patterns registered in this scanner.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Create a scanner from an encrypted secrets file.
    ///
    /// Decrypts the file in memory, parses the entries, compiles
    /// patterns, and returns the scanner ready to scan. Decrypted
    /// plaintext is scrubbed from memory after parsing.
    ///
    /// # Arguments
    ///
    /// - `encrypted_bytes` — raw bytes of the `.enc` file.
    /// - `password` — user password.
    /// - `format` — optional format override for the plaintext.
    /// - `store` — mapping store for dedup-consistent replacements.
    /// - `config` — chunking / overlap configuration.
    /// - `extra_patterns` — additional patterns to merge in.
    ///
    /// # Returns
    ///
    /// `(scanner, warnings, allow_patterns)` where `warnings` lists entries
    /// that failed to compile (index + error) and `allow_patterns` are the
    /// raw strings from `kind: allow` entries — pass these to
    /// [`AllowlistMatcher::new`](crate::allowlist::AllowlistMatcher) to
    /// suppress replacements for known-safe values.
    ///
    /// # Errors
    ///
    /// Returns a secrets-related [`SanitizeError`] on decryption failure
    /// or [`SanitizeError::InvalidConfig`] on invalid scanner config.
    pub fn from_encrypted_secrets(
        encrypted_bytes: &[u8],
        password: &str,
        format: Option<crate::secrets::SecretsFormat>,
        store: Arc<MappingStore>,
        config: ScanConfig,
        extra_patterns: Vec<ScanPattern>,
    ) -> Result<SecretsLoadResult> {
        let ((mut patterns, warnings), allow_patterns) =
            crate::secrets::load_encrypted_secrets(encrypted_bytes, password, format)?;
        patterns.extend(extra_patterns);
        let scanner = Self::new(patterns, store, config)?;
        Ok(SecretsLoadResult {
            scanner,
            warnings,
            allow_patterns,
        })
    }

    /// Create a scanner from a plaintext secrets file.
    ///
    /// Convenience for development / testing without encryption.
    ///
    /// # Returns
    ///
    /// `(scanner, warnings, allow_patterns)` where `allow_patterns` are the
    /// raw strings from `kind: allow` entries — pass these to
    /// [`AllowlistMatcher::new`](crate::allowlist::AllowlistMatcher) to
    /// suppress replacements for known-safe values.
    ///
    /// # Errors
    ///
    /// Returns a secrets-related [`SanitizeError`] on parse failure
    /// or [`SanitizeError::InvalidConfig`] on invalid scanner config.
    pub fn from_plaintext_secrets(
        plaintext: &[u8],
        format: Option<crate::secrets::SecretsFormat>,
        store: Arc<MappingStore>,
        config: ScanConfig,
        extra_patterns: Vec<ScanPattern>,
    ) -> Result<SecretsLoadResult> {
        let ((mut patterns, warnings), allow_patterns) =
            crate::secrets::load_plaintext_secrets(plaintext, format)?;
        patterns.extend(extra_patterns);
        let scanner = Self::new(patterns, store, config)?;
        Ok(SecretsLoadResult {
            scanner,
            warnings,
            allow_patterns,
        })
    }

    // ---- Internal helpers ----

    /// Find all non-overlapping matches across all patterns.
    ///
    /// Fills `scratch.selected` with the winning non-overlapping matches
    /// for the given `window`.  All three scratch `Vec`s are cleared and
    /// repopulated on each call so callers can freely reuse the same
    /// `ScanScratch` instance across chunks.
    ///
    /// ## Strategy
    ///
    /// 1. **Aho-Corasick** (`aho_corasick`): single O(n) SIMD pass over the
    ///    window reporting every occurrence of every literal pattern,
    ///    including overlapping ones.  This replaces O(k·n) individual regex
    ///    scans for the literal subset.
    /// 2. **RegexSet pre-filter** (R-3 optimisation): fast check of which
    ///    *non-literal* regex patterns have any match in the window.
    /// 3. **Individual regex `find_iter`**: only for regex patterns flagged
    ///    by step 2.
    /// 4. **Sort + greedy dedup**: all raw matches are sorted by start
    ///    (ascending), then length (descending), and a single greedy pass
    ///    selects the final non-overlapping set.
    fn find_matches(&self, window: &[u8], scratch: &mut ScanScratch) {
        scratch.all_matches.clear();
        scratch.selected.clear();

        // Step 1: Aho-Corasick overlapping scan for all literal patterns.
        // find_overlapping_iter reports every match position including
        // overlapping ones, so the sort+greedy step below correctly resolves
        // ambiguities between literals (e.g. "abc" vs "abcd" at same offset).
        // Literals never have capture groups — capture is always None.
        if let Some(ac) = &self.aho_corasick {
            for mat in ac.find_overlapping_iter(window) {
                let pattern_idx = self.literal_indices[mat.pattern().as_usize()];
                if self.length_out_of_bounds(pattern_idx, mat.end() - mat.start()) {
                    continue;
                }
                scratch.all_matches.push(RawMatch {
                    start: mat.start(),
                    end: mat.end(),
                    pattern_idx,
                    capture: None,
                });
            }
        }

        // Steps 2+3: RegexSet pre-filter then individual scan for non-literal
        // patterns.  regex_set only contains non-literal pattern strings, so
        // literals are never scanned twice.
        // Use captures_iter so that patterns with a capture group 1 record
        // the sub-range to replace, while patterns without one fall back to
        // replacing the full match.
        for rs_idx in self.regex_set.matches(window) {
            let pattern_idx = self.regex_indices[rs_idx];
            for cap in self.patterns[pattern_idx].regex.captures_iter(window) {
                let full = cap.get(0).expect("group 0 always exists");
                // Drop matches outside the pattern's configured length bounds
                // (e.g. a `min_length`/`max_length` from the secrets file). The
                // check is on the *match* length, not the window length.
                if self.length_out_of_bounds(pattern_idx, full.end() - full.start()) {
                    continue;
                }
                let capture = cap.get(1).map(|g| (g.start(), g.end()));
                scratch.all_matches.push(RawMatch {
                    start: full.start(),
                    end: full.end(),
                    pattern_idx,
                    capture,
                });
            }
        }

        // Step 4: sort then greedy non-overlapping selection.
        // Skip entirely when no matches were found (the common case for
        // clean data), avoiding an unnecessary sort of an empty Vec.
        if scratch.all_matches.is_empty() {
            return;
        }

        // Primary: start ascending. Secondary: length descending (longer
        // match wins when two matches begin at the same position).
        scratch.all_matches.sort_unstable_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
        });

        let mut last_end = 0;
        for m in scratch.all_matches.drain(..) {
            if m.start >= last_end {
                last_end = m.end;
                scratch.selected.push(m);
            }
        }
    }

    /// Whether a match of `len` bytes falls outside pattern `idx`'s configured
    /// min/max length bounds and should be discarded.
    #[inline]
    fn length_out_of_bounds(&self, idx: usize, len: usize) -> bool {
        let p = &self.patterns[idx];
        len < p.min_length || len > p.max_length
    }

    /// Adjust the commit point to avoid splitting a match across the
    /// commit / carry boundary.
    ///
    /// If any match straddles `base_commit` (starts before, ends after),
    /// the commit point is moved to after that match so it is emitted
    /// in full this iteration.
    #[allow(clippy::unused_self)] // keep &self for API consistency with other scanner methods
    fn adjusted_commit_point(
        &self,
        matches: &[RawMatch],
        base_commit: usize,
        window_len: usize,
        is_eof: bool,
    ) -> usize {
        if is_eof {
            return window_len;
        }

        let mut commit = base_commit;

        for m in matches {
            if m.start < commit && m.end > commit {
                // Match straddles the boundary.
                if m.end >= window_len {
                    // The match runs to the right edge of the window, so it may
                    // be truncated by the buffer — more of it could arrive in
                    // the next chunk. Committing it now would emit a replacement
                    // for a *partial* secret and leak the continuation verbatim
                    // (the continuation no longer matches the pattern). Pull the
                    // commit point back to the match start so the whole match is
                    // carried into the next window and re-scanned with more
                    // context. `matches` is sorted and non-overlapping, so no
                    // earlier match ends after `m.start`; lowering `commit` to it
                    // never strands a partial match in the committed region.
                    commit = m.start;
                    break;
                }
                // Fully contained — safe to commit in this iteration.
                commit = m.end;
            }
        }

        // Never exceed window length.
        commit.min(window_len)
    }

    /// Build the output for the committed region by splicing in replacements.
    ///
    /// Writes into `output_buf` (cleared on entry) and increments
    /// `stats.matches_found` / `stats.replacements_applied` for each applied
    /// replacement.  Per-pattern hit counts are written to `pattern_counts`
    /// (indexed by `pattern_idx`); the caller is responsible for folding
    /// these into `ScanStats::pattern_counts` and resetting them.
    ///
    /// `matches` is the full selected set for the window (may include matches
    /// in the carry region beyond `committed`).  Because `adjusted_commit_point`
    /// guarantees no match straddles the boundary, any match with
    /// `start < committed.len()` also has `end <= committed.len()`.  The
    /// loop breaks early once `m.start >= committed.len()` since matches are
    /// sorted by start.
    ///
    /// `window_file_offset` and `newlines_before_window` are used to compute
    /// the absolute byte offset and 1-based line number for each committed
    /// match, which are delivered to `on_match`. The newline scan is
    /// incremental: we scan only the bytes between consecutive matches, not
    /// the full committed region.
    ///
    /// # Note on `from_utf8_lossy`
    ///
    /// `String::from_utf8_lossy` returns `Cow::Borrowed(&str)` for valid
    /// UTF-8 input (the common case for ASCII secrets) — no heap allocation
    /// on the hot path.
    #[allow(clippy::too_many_arguments)]
    fn apply_replacements(
        &self,
        committed: &[u8],
        matches: &[RawMatch],
        stats: &mut ScanStats,
        output_buf: &mut Vec<u8>,
        pattern_counts: &mut [u64],
        window_file_offset: u64,
        newlines_before_window: u64,
        on_match: &mut dyn FnMut(MatchLocation),
    ) -> Result<()> {
        output_buf.clear();

        let mut last_end = 0;
        // Running newline count within the committed region, advanced
        // incrementally so we only scan the bytes between matches.
        let mut newlines_in_committed: u64 = 0;
        let mut newline_scan_pos: usize = 0;

        for &m in matches {
            // Matches are sorted by start; those at or beyond the committed
            // region belong to the carry window — stop here.
            if m.start >= committed.len() {
                break;
            }

            // Emit bytes before this match verbatim.
            output_buf.extend_from_slice(&committed[last_end..m.start]);

            // Advance newline counter from previous scan position to match start,
            // then emit the match location to the caller.
            newlines_in_committed += count_newlines(&committed[newline_scan_pos..m.start]);
            newline_scan_pos = m.start;
            on_match(MatchLocation {
                line: newlines_before_window + newlines_in_committed + 1,
                byte_offset: window_file_offset + m.start as u64,
                pattern: self.patterns[m.pattern_idx].label.clone(),
            });

            let pattern = &self.patterns[m.pattern_idx];

            if let Some((cap_start, cap_end)) = m.capture {
                // Pattern has a capture group: replace only the capture group,
                // emitting the surrounding context bytes of the full match verbatim.
                // This preserves delimiters, key names, and prefixes that the
                // pattern uses as anchors to reduce false positives.
                if cap_start < m.start || cap_end > m.end || cap_start > cap_end {
                    // Capture bounds outside match bounds — skip rather than panic.
                    // This should not happen with correct regex patterns; log it so it
                    // surfaces during testing without crashing production runs.
                    tracing::warn!(
                        pattern = %pattern.label,
                        m_start = m.start,
                        m_end = m.end,
                        cap_start,
                        cap_end,
                        "capture group bounds outside match bounds — emitting full match unreplaced"
                    );
                    output_buf.extend_from_slice(&committed[m.start..m.end]);
                    last_end = m.end;
                    continue;
                }
                output_buf.extend_from_slice(&committed[m.start..cap_start]);
                let secret = String::from_utf8_lossy(&committed[cap_start..cap_end]);
                let replacement = self.store.get_or_insert(&pattern.category, &secret)?;
                output_buf.extend_from_slice(replacement.as_bytes());
                output_buf.extend_from_slice(&committed[cap_end..m.end]);
            } else {
                // No capture group — replace the full match (e.g. token-prefix
                // patterns like `glpat-[...]` where the full match IS the secret).
                let matched_text = String::from_utf8_lossy(&committed[m.start..m.end]);
                let replacement = self.store.get_or_insert(&pattern.category, &matched_text)?;
                output_buf.extend_from_slice(replacement.as_bytes());
            }

            last_end = m.end;

            stats.matches_found += 1;
            stats.replacements_applied += 1;
            pattern_counts[m.pattern_idx] += 1;
        }

        // Emit the trailing non-matching tail.
        output_buf.extend_from_slice(&committed[last_end..]);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertion
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<StreamScanner>();
    assert_sync::<StreamScanner>();
};

// ---------------------------------------------------------------------------
// I/O helper
// ---------------------------------------------------------------------------

/// Count the number of `\n` bytes in `data`.
///
/// Used to advance the cumulative newline counter between consecutive
/// match positions so we can compute 1-based line numbers without
/// pre-scanning the entire committed region.
#[inline]
fn count_newlines(data: &[u8]) -> u64 {
    bytecount::count(data, b'\n') as u64
}

/// Read up to `buf.len()` bytes from `reader`, retrying on `Interrupted`.
///
/// Returns the number of bytes actually read (< `buf.len()` only at EOF).
fn read_fully<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break, // EOF
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SanitizeError::from(e)),
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::HmacGenerator;

    /// Helper: build a scanner with given patterns and small chunk config.
    fn test_scanner(patterns: Vec<ScanPattern>) -> StreamScanner {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        StreamScanner::new(
            patterns,
            store,
            ScanConfig {
                chunk_size: 64,
                overlap_size: 16,
            },
        )
        .unwrap()
    }

    /// Helper: email pattern.
    fn email_pattern() -> ScanPattern {
        ScanPattern::from_regex(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Category::Email,
            "email",
        )
        .unwrap()
    }

    /// Helper: IPv4 pattern.
    fn ipv4_pattern() -> ScanPattern {
        ScanPattern::from_regex(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            Category::IpV4,
            "ipv4",
        )
        .unwrap()
    }

    // ---- Construction ----

    #[test]
    fn scanner_creation() {
        let scanner = test_scanner(vec![email_pattern()]);
        assert_eq!(scanner.pattern_count(), 1);
    }

    #[test]
    fn invalid_config_zero_chunk() {
        let gen = Arc::new(HmacGenerator::new([0u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let result = StreamScanner::new(vec![], store, ScanConfig::new(0, 0));
        assert!(result.is_err());
    }

    #[test]
    fn invalid_config_overlap_ge_chunk() {
        let gen = Arc::new(HmacGenerator::new([0u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let result = StreamScanner::new(vec![], store, ScanConfig::new(100, 100));
        assert!(result.is_err());
    }

    // ---- Empty / no-match cases ----

    #[test]
    fn empty_input() {
        let scanner = test_scanner(vec![email_pattern()]);
        let (output, stats) = scanner.scan_bytes(b"").unwrap();
        assert!(output.is_empty());
        assert_eq!(stats.matches_found, 0);
        assert_eq!(stats.bytes_processed, 0);
    }

    #[test]
    fn no_matches() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"There are no email addresses here.";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(output, input.as_slice());
        assert_eq!(stats.matches_found, 0);
    }

    // ---- Single match ----

    #[test]
    fn single_email_replaced() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"Contact alice@corp.com for help.";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 1);
        assert_eq!(stats.replacements_applied, 1);
        // Original must not appear in output.
        assert!(!output
            .windows(b"alice@corp.com".len())
            .any(|w| w == b"alice@corp.com"));
        // Replacement should contain the @ from the domain-preserving email.
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("@corp.com"));
        // Length preserved: output is same total length as input.
        assert_eq!(output.len(), input.len(), "length must be preserved");
        // Surrounding text preserved.
        assert!(output_str.starts_with("Contact "));
        assert!(output_str.ends_with(" for help."));
    }

    // ---- Multiple matches ----

    #[test]
    fn multiple_emails_replaced() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"From alice@corp.com to bob@corp.com cc admin@corp.com";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 3);
        let out_str = String::from_utf8_lossy(&output);
        assert!(!out_str.contains("alice@corp.com"));
        assert!(!out_str.contains("bob@corp.com"));
        assert!(!out_str.contains("admin@corp.com"));
    }

    // ---- Same secret gets same replacement ----

    #[test]
    fn same_secret_same_replacement() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"First alice@corp.com then alice@corp.com again.";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 2);
        let out_str = String::from_utf8_lossy(&output);
        // Both occurrences should be replaced with the same value.
        // With length-preserving replacements, look for the preserved domain.
        let parts: Vec<&str> = out_str.split("@corp.com").collect();
        // 3 parts = 2 occurrences of the replacement.
        assert_eq!(parts.len(), 3);
    }

    // ---- Literal pattern ----

    #[test]
    fn literal_pattern_matched() {
        let pat = ScanPattern::from_literal(
            "SECRET_API_KEY_12345",
            Category::Custom("api_key".into()),
            "api_key",
        )
        .unwrap();
        let scanner = test_scanner(vec![pat]);
        let input = b"key=SECRET_API_KEY_12345&foo=bar";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 1);
        assert!(!output
            .windows(b"SECRET_API_KEY_12345".len())
            .any(|w| w == b"SECRET_API_KEY_12345"));
    }

    // ---- Multiple pattern types ----

    #[test]
    fn multiple_pattern_types() {
        let scanner = test_scanner(vec![email_pattern(), ipv4_pattern()]);
        let input = b"Server 192.168.1.100 contact admin@server.com";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 2);
        let out_str = String::from_utf8_lossy(&output);
        assert!(!out_str.contains("192.168.1.100"));
        assert!(!out_str.contains("admin@server.com"));
        assert_eq!(*stats.pattern_counts.get("email").unwrap(), 1);
        assert_eq!(*stats.pattern_counts.get("ipv4").unwrap(), 1);
    }

    // ---- Chunk boundary: match spans two chunks ----

    #[test]
    fn match_at_chunk_boundary() {
        // Use a very small chunk size so the email straddles a boundary.
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let scanner = StreamScanner::new(
            vec![email_pattern()],
            store,
            ScanConfig {
                chunk_size: 20, // very small
                overlap_size: 16,
            },
        )
        .unwrap();

        // Place an email address that will definitely straddle a boundary.
        let input = b"AAAAAAAAAAAAAAAA alice@corp.com BBBBBBBBBBBBB";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 1);
        let out_str = String::from_utf8_lossy(&output);
        assert!(!out_str.contains("alice@corp.com"));
        assert!(out_str.contains("@corp.com"), "domain must be preserved");
    }

    /// Helper: unbounded token pattern (no length cap), like a URL/key body.
    fn token_pattern() -> ScanPattern {
        ScanPattern::from_regex(r"TOK[A-Za-z0-9]+", Category::AuthToken, "tok").unwrap()
    }

    // ---- Over-long match boundary leak (regression) ----

    #[test]
    fn long_match_exceeding_overlap_is_fully_replaced() {
        // A token longer than `overlap` (16) but shorter than `chunk` (64) must
        // be carried whole across the boundary and replaced exactly once — no
        // raw bytes may survive and it must not be split into two mappings.
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let scanner = StreamScanner::new(
            vec![token_pattern()],
            Arc::clone(&store),
            ScanConfig {
                chunk_size: 64,
                overlap_size: 16,
            },
        )
        .unwrap();

        let secret = format!("TOK{}", "A".repeat(40)); // 43 bytes > overlap, < chunk
        let input = format!("{} {} {}", "X".repeat(30), secret, "Y".repeat(30));
        let (output, stats) = scanner.scan_bytes(input.as_bytes()).unwrap();
        let out = String::from_utf8_lossy(&output);

        assert!(
            !out.contains("AAAAAAAAAA"),
            "raw token bytes leaked: {out}"
        );
        assert!(!out.contains(&secret), "full token survived: {out}");
        assert_eq!(stats.matches_found, 1, "token must match exactly once");
        assert_eq!(store.len(), 1, "token must map to a single replacement");
        assert_eq!(
            output.len(),
            input.len(),
            "length must be preserved for a non-overlong match"
        );
    }

    #[test]
    fn overlong_match_is_redacted_not_leaked() {
        // A single token longer than `max_carry` (== chunk_size, 64) cannot be
        // buffered; it must be redacted with the marker and leak zero bytes.
        let scanner = test_scanner(vec![token_pattern()]); // chunk 64, overlap 16
        let secret = format!("TOK{}", "A".repeat(500)); // 503 bytes > chunk
        let input = format!("before {secret} after");
        let (output, _stats) = scanner.scan_bytes(input.as_bytes()).unwrap();
        let out = String::from_utf8_lossy(&output);

        assert!(
            !out.contains("AAAAAAAAAA"),
            "overlong token leaked raw bytes: {out}"
        );
        assert!(
            out.contains(std::str::from_utf8(OVERLONG_MARKER).unwrap()),
            "overlong token must be redacted with the marker: {out}"
        );
        assert!(out.starts_with("before "), "prefix preserved: {out}");
        assert!(out.ends_with(" after"), "suffix after the run preserved: {out}");
    }

    #[test]
    fn overlong_match_running_to_eof_is_redacted() {
        // The over-long run never hits a whitespace boundary before EOF — every
        // remaining byte must be consumed, leaking nothing.
        let scanner = test_scanner(vec![token_pattern()]);
        let secret = format!("TOK{}", "A".repeat(500));
        let input = format!("before {secret}");
        let (output, _stats) = scanner.scan_bytes(input.as_bytes()).unwrap();
        let out = String::from_utf8_lossy(&output);

        assert!(!out.contains("AAAAAAAAAA"), "leaked to EOF: {out}");
        assert!(
            out.contains(std::str::from_utf8(OVERLONG_MARKER).unwrap()),
            "must redact with marker: {out}"
        );
        assert!(out.starts_with("before "), "prefix preserved: {out}");
    }

    #[test]
    fn length_bounds_filter_matches() {
        // A digit-run pattern bounded to 4..=8 bytes: shorter and longer runs
        // pass through untouched; in-range runs are replaced.
        let pat = ScanPattern::from_regex(r"[0-9]+", Category::Custom("num".into()), "num")
            .unwrap()
            .with_length_bounds(4, 8);
        let scanner = test_scanner(vec![pat]);

        let input = b"a 12 b 1234 c 1234567890 d";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        let out = String::from_utf8_lossy(&output);

        assert_eq!(stats.matches_found, 1, "only the 4-digit run is in range");
        assert!(out.contains("12 "), "short run preserved: {out}");
        assert!(out.contains("1234567890"), "long run preserved: {out}");
        assert!(!out.contains(" 1234 "), "in-range run replaced: {out}");
        assert_eq!(output.len(), input.len(), "length preserved");
    }

    // ---- Large input requiring many chunks ----

    #[test]
    fn large_input_many_chunks() {
        let scanner = test_scanner(vec![email_pattern()]);

        // Build a ~2 KiB input with emails sprinkled in.
        let mut input = Vec::new();
        let filler = b"Lorem ipsum dolor sit amet. ";
        for i in 0..20 {
            input.extend_from_slice(filler);
            let email = format!("user{}@example.com ", i);
            input.extend_from_slice(email.as_bytes());
        }

        let (output, stats) = scanner.scan_bytes(&input).unwrap();
        assert_eq!(stats.matches_found, 20);
        let out_str = String::from_utf8_lossy(&output);
        for i in 0..20 {
            let email = format!("user{}@example.com", i);
            assert!(!out_str.contains(&email));
        }
    }

    #[test]
    fn scan_bytes_with_progress_preserves_output_and_stats() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"Contact alice@corp.com and bob@corp.com for help.";

        let (baseline_output, baseline_stats) = scanner.scan_bytes(input).unwrap();

        let mut updates = Vec::new();
        let (progress_output, progress_stats) = scanner
            .scan_bytes_with_progress(input, |progress| updates.push(progress.clone()))
            .unwrap();

        assert_eq!(progress_output, baseline_output);
        assert_eq!(
            progress_stats.bytes_processed,
            baseline_stats.bytes_processed
        );
        assert_eq!(progress_stats.bytes_output, baseline_stats.bytes_output);
        assert_eq!(progress_stats.matches_found, baseline_stats.matches_found);
        assert_eq!(
            progress_stats.replacements_applied,
            baseline_stats.replacements_applied
        );
        assert!(!updates.is_empty());
        assert_eq!(updates.last().unwrap().bytes_processed, input.len() as u64);
        assert_eq!(
            updates.last().unwrap().total_bytes,
            Some(input.len() as u64)
        );
        assert_eq!(updates.last().unwrap().matches_found, 2);
    }

    #[test]
    fn scan_reader_with_progress_reports_multiple_updates_for_multi_chunk_input() {
        let scanner = test_scanner(vec![email_pattern()]);
        let mut input = Vec::new();
        for i in 0..8 {
            input.extend_from_slice(b"padding padding padding ");
            input.extend_from_slice(format!("user{i}@example.com ").as_bytes());
        }

        let mut output = Vec::new();
        let mut updates = Vec::new();
        let stats = scanner
            .scan_reader_with_callbacks(
                &input[..],
                &mut output,
                Some(input.len() as u64),
                |progress| {
                    updates.push(progress.clone());
                },
                |_| {},
            )
            .unwrap();

        assert!(updates.len() >= 2);
        assert_eq!(
            updates.last().unwrap().bytes_processed,
            stats.bytes_processed
        );
        assert_eq!(updates.last().unwrap().bytes_output, stats.bytes_output);
        assert_eq!(
            updates.last().unwrap().total_bytes,
            Some(input.len() as u64)
        );
    }

    // ---- Scan via Read/Write interface ----

    #[test]
    fn scan_reader_writer() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"hello alice@corp.com world";
        let mut output = Vec::new();
        let stats = scanner.scan_reader(&input[..], &mut output).unwrap();
        assert_eq!(stats.matches_found, 1);
        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains("@corp.com"), "domain must be preserved");
    }

    // ---- Pattern compile error ----

    #[test]
    fn invalid_regex_pattern() {
        let result = ScanPattern::from_regex("[invalid(", Category::Email, "bad");
        assert!(result.is_err());
    }

    // ---- Default config ----

    #[test]
    fn default_config_valid() {
        ScanConfig::default().validate().unwrap();
    }

    // ---- Config edge cases ----

    #[test]
    fn config_chunk_1_overlap_0() {
        // Extreme but valid: 1-byte chunks, no overlap.
        // Won't catch multi-byte patterns, but should not crash.
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let scanner = StreamScanner::new(vec![], store, ScanConfig::new(1, 0)).unwrap();
        let (output, _) = scanner.scan_bytes(b"hello").unwrap();
        assert_eq!(output, b"hello");
    }

    // ---- ScanStats equality (exercises the PartialEq derive) ----

    #[test]
    fn scan_stats_equality() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"hello alice@corp.com world";
        let (_, stats_a) = scanner.scan_bytes(input).unwrap();
        let (_, stats_b) = scanner.scan_bytes(input).unwrap();
        // Identical inputs produce identical stats.
        assert_eq!(
            stats_a, stats_b,
            "identical inputs must produce identical stats"
        );
        // Values are correct — not just equal to each other.
        assert_eq!(stats_a.matches_found, 1, "one email in input");
        assert_eq!(stats_a.replacements_applied, 1);
        assert_eq!(stats_a.bytes_processed, input.len() as u64);
        assert_eq!(*stats_a.pattern_counts.get("email").unwrap_or(&0), 1);
        // No-match run produces zeroed counters.
        let (_, stats_empty) = scanner.scan_bytes(b"no matches here").unwrap();
        assert_ne!(stats_a, stats_empty);
        assert_eq!(stats_empty.matches_found, 0);
        assert_eq!(stats_empty.replacements_applied, 0);
    }

    // ---- on_match line number and byte offset accuracy ----

    #[test]
    fn on_match_reports_correct_line_and_byte_offset() {
        // alice@corp.com starts after "line one\n" (9 bytes) → byte 9, line 2.
        // bob@corp.com starts after "line one\nalice@corp.com\nline three\n"
        //   = 9 + 14 + 1 + 10 + 1 = 35 bytes → byte 35, line 4.
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"line one\nalice@corp.com\nline three\nbob@corp.com\n";
        let mut locations = Vec::new();
        let mut output = Vec::new();
        scanner
            .scan_reader_with_callbacks(
                &input[..],
                &mut output,
                None,
                |_| {},
                |loc| locations.push(loc),
            )
            .unwrap();
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 2, "alice must be on line 2");
        assert_eq!(locations[0].byte_offset, 9, "alice must start at byte 9");
        assert_eq!(locations[1].line, 4, "bob must be on line 4");
        assert_eq!(locations[1].byte_offset, 35, "bob must start at byte 35");
    }

    // ---- Cross-chunk newline accumulation ----

    #[test]
    fn on_match_line_numbers_stable_across_chunk_sizes() {
        // alice@corp.com starts after "line one\n" (9 bytes) → byte 9, line 2.
        // bob@corp.com starts after "line one\nalice@corp.com\nline three\n"
        //   = 9 + 14 + 1 + 10 + 1 = 35 bytes → byte 35, line 4.
        // Running the same input through different chunk sizes exercises
        // newlines_before_window accumulation across chunk boundaries.
        let input = b"line one\nalice@corp.com\nline three\nbob@corp.com\n";
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));

        for chunk_size in [16usize, 20, 24, 32, 64] {
            let scanner = StreamScanner::new(
                vec![email_pattern()],
                Arc::clone(&store),
                ScanConfig::new(chunk_size, 14),
            )
            .unwrap();

            let mut locations = Vec::new();
            let mut output = Vec::new();
            scanner
                .scan_reader_with_callbacks(
                    &input[..],
                    &mut output,
                    None,
                    |_| {},
                    |loc| locations.push(loc),
                )
                .unwrap();

            assert_eq!(
                locations.len(),
                2,
                "chunk_size={chunk_size}: expected 2 matches"
            );
            assert_eq!(
                locations[0].line, 2,
                "chunk_size={chunk_size}: alice must be on line 2"
            );
            assert_eq!(
                locations[0].byte_offset, 9,
                "chunk_size={chunk_size}: alice must start at byte 9"
            );
            assert_eq!(
                locations[1].line, 4,
                "chunk_size={chunk_size}: bob must be on line 4"
            );
            assert_eq!(
                locations[1].byte_offset, 35,
                "chunk_size={chunk_size}: bob must start at byte 35"
            );
        }
    }

    // ---- Bytes output tracking ----

    #[test]
    fn bytes_output_preserved_on_replacement() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"a@b.cc"; // short email
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.bytes_processed, input.len() as u64);
        assert_eq!(stats.bytes_output, output.len() as u64);
        // Length-preserving: output length matches input length.
        assert_eq!(output.len(), input.len());
    }

    #[test]
    fn randomized_length_decorrelates_numeric_output() {
        use crate::generator::{LengthPolicy, RandomGenerator};
        // A short numeric value under Randomized is replaced by a band-length
        // digit run (8..=18 digits), so the output no longer matches the input
        // length and bytes_output diverges from bytes_processed.
        let gen = Arc::new(RandomGenerator::new().with_length_policy(LengthPolicy::Randomized));
        let store = Arc::new(MappingStore::new(gen, None));
        let pat = ScanPattern::from_regex(r"\b\d{4,}\b", Category::Phone, "num").unwrap();
        let scanner = StreamScanner::new(
            vec![pat],
            store,
            ScanConfig {
                chunk_size: 64,
                overlap_size: 16,
            },
        )
        .unwrap();
        let input = b"id=123456 end"; // the value "123456" is 6 digits
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        let out = String::from_utf8(output).unwrap();
        assert!(!out.contains("123456"), "value must be replaced: {out}");
        assert_eq!(stats.replacements_applied, 1);
        assert_eq!(stats.bytes_output, out.len() as u64);
        assert!(
            stats.bytes_output > stats.bytes_processed,
            "randomized replacement (>=8 digits) must lengthen a 6-digit value: \
             processed={} output={}",
            stats.bytes_processed,
            stats.bytes_output
        );
    }
}
