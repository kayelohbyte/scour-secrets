//! Archive processor for sanitizing files inside `.zip`, `.tar`, and `.tar.gz` archives.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────┐
//! │  Archive (zip/tar/gz) │
//! └────────┬──────────────┘
//!          │  for each entry
//!          ▼
//! ┌─────────────────────────────────────────────┐
//! │  1. Match entry filename → FileTypeProfile  │
//! │  2. Try ProcessorRegistry (structured)      │
//! │  3. Fallback: StreamScanner (streaming)     │
//! └────────┬────────────────────────────────────┘
//!          │  sanitized bytes
//!          ▼
//! ┌───────────────────────┐
//! │  Rebuilt archive       │
//! │  (same format, meta   │
//! │   preserved)          │
//! └───────────────────────┘
//! ```
//!
//! # Memory Efficiency
//!
//! Archives are processed **entry-by-entry**. Each entry is piped
//! through either a structured processor (which must buffer the full
//! entry) or the [`StreamScanner`]
//! (which processes in configurable chunks). This means the maximum
//! memory footprint is proportional to the largest *single entry*
//! that uses a structured processor. Files without a profile match
//! are streamed through the scanner without buffering the whole entry.
//!
//! For very large individual files inside archives, the streaming
//! scanner path keeps only `chunk_size + overlap_size` bytes in memory.
//!
//! # Thread Safety
//!
//! [`ArchiveProcessor`] is `Send + Sync`. The underlying
//! [`MappingStore`] provides lock-free
//! reads for dedup consistency.
//!
//! # Metadata Preservation
//!
//! - **Tar**: modification time, permissions (mode), uid/gid, and
//!   username/groupname are copied from the source entry.
//! - **Zip**: modification time, compression method, and unix
//!   permissions are preserved.
//! - Symlinks, directories, and other non-regular entries are passed
//!   through unchanged.

use crate::error::{Result, SanitizeError};
use crate::processor::profile::FileTypeProfile;
use crate::processor::registry::ProcessorRegistry;
use crate::scanner::{ScanPattern, ScanStats, StreamScanner};
use crate::store::MappingStore;

/// Strip path traversal components from an archive entry path before writing output.
///
/// Removes: leading `/`, `./`, `../`, and Windows drive-letter prefixes (`C:`).
/// The result is always a relative path with no upward traversal. An empty
/// result is replaced with `"_"` to avoid writing an entry with a blank name.
/// Backslashes are normalised to forward slashes (handles Windows-style zip entries).
fn sanitize_archive_entry_name(name: &str) -> String {
    let name = name.replace('\\', "/");
    let name = name.trim_start_matches('/');
    let safe: Vec<&str> = name
        .split('/')
        .filter(|s| {
            if s.is_empty() || *s == "." || *s == ".." {
                return false;
            }
            // Strip Windows drive-letter prefixes ("C:", "D:", etc.) to prevent
            // zip-slip path-traversal when the output is extracted on Windows.
            if s.len() == 2 && s.as_bytes()[1] == b':' && s.as_bytes()[0].is_ascii_alphabetic() {
                return false;
            }
            true
        })
        .collect();
    let result = safe.join("/");
    if result.is_empty() {
        "_".to_string()
    } else {
        result
    }
}

#[inline]
fn sanitize_zip_entry_name(name: &str) -> String {
    sanitize_archive_entry_name(name)
}

#[inline]
fn sanitize_tar_entry_name(name: &str) -> String {
    sanitize_archive_entry_name(name)
}

use glob::MatchOptions;
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::{self, Read, Seek, Write};
use std::sync::{Arc, OnceLock};

use crate::processor::limits::{
    DEFAULT_ARCHIVE_DEPTH, MAX_ARCHIVE_DEPTH, PARALLEL_ENTRY_THRESHOLD, PARALLEL_TAR_DATA_SIZE,
    PARALLEL_ZIP_DATA_SIZE, STRUCTURED_ENTRY_SIZE,
};

/// Read up to `limit` bytes from `reader` into a `Vec<u8>`.
///
/// Returns an error if the reader yields more than `limit` bytes, preventing
/// unbounded heap growth from crafted archive entries.
fn read_bounded(reader: &mut dyn Read, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    // Read one byte beyond the limit so we can detect over-sized entries.
    reader
        .take(limit + 1)
        .read_to_end(&mut content)
        .map_err(|e| SanitizeError::ArchiveError(format!("read '{label}': {e}")))?;
    if content.len() as u64 > limit {
        return Err(SanitizeError::ArchiveError(format!(
            "entry '{label}' exceeds the {limit}-byte size limit",
        )));
    }
    Ok(content)
}

// ---------------------------------------------------------------------------
// Archive format enum
// ---------------------------------------------------------------------------

/// Per-entry result from parallel archive processing: `(source_index, sanitized_bytes_and_stats)`.
type ParEntryResult = (usize, Result<(Vec<u8>, ArchiveStats)>);

/// Callback invoked with `(entry_name, sanitized_bytes)` after each file entry
/// inside an archive is processed. Used by callers that need to inspect the
/// sanitized content without buffering the entire archive (e.g. log context
/// extraction).
pub type EntryCallback = Arc<dyn Fn(&str, &[u8]) + Send + Sync>;

// ---------------------------------------------------------------------------
// ArchiveFilter
// ---------------------------------------------------------------------------

/// A compiled glob-based entry filter for archive processing.
///
/// Patterns are compiled once at construction time. At processing time
/// `passes()` is called for each file entry path inside the archive.
///
/// ## Pattern semantics
///
/// - `*` matches any sequence of characters that does **not** contain `/`.
/// - `**` matches any sequence of characters including `/`.
/// - `?` matches any single character except `/`.
/// - `[abc]` matches one of the listed characters.
/// - A pattern ending with `/` is a *directory prefix* — it matches
///   the directory itself and any path underneath it.
///
/// ## Filter logic
///
/// 1. If `--only` patterns are present: the entry path must match at
///    least one pattern, otherwise it is dropped.
/// 2. If `--exclude` patterns are present: if the entry path matches
///    any pattern, it is dropped.
/// 3. Only file entries are filtered; directory / symlink entries
///    always pass through to preserve archive structure.
#[derive(Default, Clone)]
pub struct ArchiveFilter {
    only: Vec<CompiledPattern>,
    exclude: Vec<CompiledPattern>,
}

#[derive(Clone)]
enum CompiledPattern {
    /// Pattern that ended with `/` — matches the prefix directory and
    /// everything inside it.
    DirPrefix(String),
    /// General glob pattern compiled with `require_literal_separator`.
    Glob(glob::Pattern),
}

const GLOB_OPTS: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

impl CompiledPattern {
    fn compile(raw: &str) -> std::result::Result<Self, String> {
        if raw.ends_with('/') {
            // Strip trailing slash; matching is done manually in `matches`.
            Ok(CompiledPattern::DirPrefix(
                raw.trim_end_matches('/').to_string(),
            ))
        } else {
            glob::Pattern::new(raw)
                .map(CompiledPattern::Glob)
                .map_err(|e| format!("invalid glob pattern '{raw}': {e}"))
        }
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            CompiledPattern::DirPrefix(prefix) => {
                path == prefix || path.starts_with(&format!("{prefix}/"))
            }
            CompiledPattern::Glob(pat) => pat.matches_with(path, GLOB_OPTS),
        }
    }
}

impl ArchiveFilter {
    /// Compile `only` and `exclude` pattern lists into an `ArchiveFilter`.
    ///
    /// # Errors
    ///
    /// Returns an error if any pattern contains invalid glob syntax.
    pub fn new(only: Vec<String>, exclude: Vec<String>) -> std::result::Result<Self, String> {
        let only = only
            .into_iter()
            .map(|p| CompiledPattern::compile(&p))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let exclude = exclude
            .into_iter()
            .map(|p| CompiledPattern::compile(&p))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self { only, exclude })
    }

    /// Returns `true` when neither `--only` nor `--exclude` patterns are set.
    pub fn is_empty(&self) -> bool {
        self.only.is_empty() && self.exclude.is_empty()
    }

    /// Returns `true` if `path` should be included in the output archive.
    ///
    /// Only applies to file entries; directory entries bypass this check.
    pub fn passes(&self, path: &str) -> bool {
        if !self.only.is_empty() && !self.only.iter().any(|p| p.matches(path)) {
            return false;
        }
        if self.exclude.iter().any(|p| p.matches(path)) {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Archive format enum
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// `.zip` archive.
    Zip,
    /// Uncompressed `.tar` archive.
    Tar,
    /// Gzip-compressed `.tar.gz` / `.tgz` archive.
    TarGz,
}

impl ArchiveFormat {
    /// Detect archive format from a file path / extension.
    ///
    /// Returns `None` for unrecognised extensions.
    pub fn from_path(path: &str) -> Option<Self> {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".tar.gz")
            || std::path::Path::new(&lower)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tgz"))
        {
            Some(Self::TarGz)
        } else if std::path::Path::new(&lower)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"))
        {
            Some(Self::Tar)
        } else if std::path::Path::new(&lower)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        {
            Some(Self::Zip)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Archive statistics
// ---------------------------------------------------------------------------

/// Statistics collected while processing an archive.
#[derive(Debug, Clone, Default)]
pub struct ArchiveStats {
    /// Number of file entries processed (excludes dirs/symlinks).
    pub files_processed: u64,
    /// Number of entries passed through unchanged (dirs, symlinks, etc.).
    pub entries_skipped: u64,
    /// Number of files handled by a structured processor.
    pub structured_hits: u64,
    /// Number of files handled by the streaming scanner fallback.
    pub scanner_fallback: u64,
    /// Number of entries that were themselves archives and processed
    /// recursively.
    pub nested_archives: u64,
    /// Total input bytes across all file entries.
    pub total_input_bytes: u64,
    /// Total output bytes across all file entries.
    pub total_output_bytes: u64,
    /// Per-file processing method: filename → `"structured:<proc>"`, `"scanner"`,
    /// or `"nested:<format>"`.
    pub file_methods: HashMap<String, String>,
    /// Per-file scan statistics (matches, replacements, bytes, pattern counts).
    pub file_scan_stats: HashMap<String, ScanStats>,
    /// Number of file entries removed by the [`ArchiveFilter`].
    pub entries_filtered: u64,
}

/// Progress snapshot emitted while processing archive entries.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArchiveProgress {
    /// Entries seen so far, including skipped entries.
    pub entries_seen: u64,
    /// Regular file entries processed so far.
    pub files_processed: u64,
    /// Non-file entries skipped so far.
    pub entries_skipped: u64,
    /// Total entries when cheaply known.
    pub total_entries: Option<u64>,
    /// Path of the current entry.
    pub current_entry: String,
}

type ArchiveProgressCallback = Arc<dyn Fn(&ArchiveProgress) + Send + Sync>;

impl ArchiveStats {
    /// Merge statistics from a nested archive into this parent.
    fn merge(&mut self, child: &ArchiveStats) {
        self.files_processed += child.files_processed;
        self.entries_skipped += child.entries_skipped;
        self.structured_hits += child.structured_hits;
        self.scanner_fallback += child.scanner_fallback;
        self.nested_archives += child.nested_archives;
        self.total_input_bytes += child.total_input_bytes;
        self.total_output_bytes += child.total_output_bytes;
        self.entries_filtered += child.entries_filtered;
        self.file_methods.extend(
            child
                .file_methods
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        self.file_scan_stats.extend(
            child
                .file_scan_stats
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }
}

// ---------------------------------------------------------------------------
// ArchiveProcessor
// ---------------------------------------------------------------------------

/// Processes archives by sanitizing each contained file and rebuilding
/// the archive with the same format and preserved metadata.
///
/// # Usage
///
/// ```rust,no_run
/// use rust_sanitize::processor::archive::{ArchiveProcessor, ArchiveFormat};
/// use rust_sanitize::processor::registry::ProcessorRegistry;
/// use rust_sanitize::scanner::{StreamScanner, ScanPattern, ScanConfig};
/// use rust_sanitize::generator::HmacGenerator;
/// use rust_sanitize::store::MappingStore;
/// use rust_sanitize::category::Category;
/// use std::sync::Arc;
///
/// let gen = Arc::new(HmacGenerator::new([42u8; 32]));
/// let store = Arc::new(MappingStore::new(gen, None));
/// let patterns = vec![
///     ScanPattern::from_regex(r"secret\w+", Category::Custom("secret".into()), "secrets").unwrap(),
/// ];
/// let scanner = Arc::new(
///     StreamScanner::new(patterns, Arc::clone(&store), ScanConfig::default()).unwrap(),
/// );
/// let registry = Arc::new(ProcessorRegistry::with_builtins());
///
/// let archive_proc = ArchiveProcessor::new(registry, scanner, store, vec![]);
/// ```
pub struct ArchiveProcessor {
    /// Registry of structured processors.
    registry: Arc<ProcessorRegistry>,
    /// Streaming scanner for fallback processing.
    scanner: Arc<StreamScanner>,
    /// Shared mapping store (one-way replacements).
    store: Arc<MappingStore>,
    /// File-type profiles for structured processor matching.
    profiles: Vec<FileTypeProfile>,
    /// Maximum nesting depth for recursive archive processing.
    max_depth: u32,
    /// Optional callback for per-entry progress updates.
    progress_callback: Option<ArchiveProgressCallback>,
    /// Minimum number of file entries required to enable parallel entry
    /// sanitization. Default: [`PARALLEL_ENTRY_THRESHOLD`].
    parallel_threshold: usize,
    /// Entry-level filter controlling which paths are included in the
    /// output archive. Default: empty (pass all entries).
    filter: ArchiveFilter,
    /// When true, bypass all structured processors and use only the
    /// streaming scanner for every entry. Trades format preservation
    /// for maximum sanitization coverage.
    force_text: bool,
    /// Optional callback invoked with `(entry_name, sanitized_bytes)` after
    /// each file entry is processed. Only called for regular file entries.
    entry_callback: Option<EntryCallback>,
    /// Lazily-built format-preserving scanner for structured entries: the
    /// scanner with structure-corrupting key/value patterns stripped. Built
    /// once on first use and reused across entries (and threads).
    structured_scanner: OnceLock<Arc<StreamScanner>>,
}

impl ArchiveProcessor {
    /// Create a new archive processor.
    ///
    /// # Arguments
    ///
    /// - `registry` — structured processor registry.
    /// - `scanner` — streaming scanner for fallback.
    /// - `store` — shared mapping store for one-way dedup replacements.
    /// - `profiles` — file-type profiles for structured matching.
    pub fn new(
        registry: Arc<ProcessorRegistry>,
        scanner: Arc<StreamScanner>,
        store: Arc<MappingStore>,
        profiles: Vec<FileTypeProfile>,
    ) -> Self {
        Self {
            registry,
            scanner,
            store,
            profiles,
            max_depth: DEFAULT_ARCHIVE_DEPTH,
            progress_callback: None,
            parallel_threshold: PARALLEL_ENTRY_THRESHOLD,
            filter: ArchiveFilter::default(),
            force_text: false,
            entry_callback: None,
            structured_scanner: OnceLock::new(),
        }
    }

    /// Format-preserving scanner for structured entries, built lazily from
    /// `self.scanner` with structure-corrupting key/value patterns removed (see
    /// [`StreamScanner::for_structured_pass`]). Applied to an entry's **original**
    /// bytes so comments, key order, and whitespace are preserved while
    /// discovered field values and non-structural patterns are still redacted.
    fn structured_pass_scanner(&self) -> Result<&Arc<StreamScanner>> {
        if let Some(scanner) = self.structured_scanner.get() {
            return Ok(scanner);
        }
        let built = Arc::new(self.scanner.for_structured_pass(Vec::new())?);
        // A racing thread may have set it first; either value is equivalent.
        let _ = self.structured_scanner.set(built);
        Ok(self
            .structured_scanner
            .get()
            .expect("structured scanner was just set"))
    }

    /// Override the maximum nesting depth for recursive archive
    /// processing.
    ///
    /// The default is [`DEFAULT_ARCHIVE_DEPTH`] (5). Values above
    /// 10 are clamped.
    #[must_use]
    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth.min(MAX_ARCHIVE_DEPTH);
        self
    }

    /// Override the minimum entry count required to enable parallel
    /// entry sanitization. Set to `usize::MAX` to disable parallelism
    /// entirely for this processor instance (e.g. when outer file-level
    /// parallelism is already saturating the thread budget).
    #[must_use]
    pub fn with_parallel_threshold(mut self, threshold: usize) -> Self {
        self.parallel_threshold = threshold;
        self
    }

    /// Register a per-entry archive progress callback.
    #[must_use]
    pub fn with_progress_callback(mut self, callback: ArchiveProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// Apply an [`ArchiveFilter`] that controls which file entries are
    /// included in the output archive.
    ///
    /// Entries that do not pass the filter are **removed** from the
    /// output entirely. Directory / symlink entries are never filtered.
    #[must_use]
    pub fn with_filter(mut self, filter: ArchiveFilter) -> Self {
        self.filter = filter;
        self
    }

    /// When set, bypass all structured processors and use only the
    /// streaming scanner for every archive entry.
    ///
    /// Trades format preservation for maximum sanitization coverage.
    /// Useful when the user is uncertain about field rules or wants a
    /// belt-and-suspenders guarantee that every byte is scanned.
    #[must_use]
    pub fn with_force_text(mut self, force_text: bool) -> Self {
        self.force_text = force_text;
        self
    }

    /// Register a callback that is invoked with `(entry_name, sanitized_bytes)`
    /// after each regular file entry is fully processed.
    #[must_use]
    pub fn with_entry_callback(mut self, callback: EntryCallback) -> Self {
        self.entry_callback = Some(callback);
        self
    }

    fn emit_entry_bytes(&self, name: &str, bytes: &[u8]) {
        if let Some(cb) = &self.entry_callback {
            cb(name, bytes);
        }
    }

    /// Find the first profile matching a filename.
    fn find_profile(&self, filename: &str) -> Option<&FileTypeProfile> {
        self.profiles.iter().find(|p| p.matches_filename(filename))
    }

    fn emit_progress(&self, stats: &ArchiveStats, total_entries: Option<u64>, current_entry: &str) {
        if let Some(callback) = &self.progress_callback {
            callback(&ArchiveProgress {
                entries_seen: stats.files_processed + stats.entries_skipped,
                files_processed: stats.files_processed,
                entries_skipped: stats.entries_skipped,
                total_entries,
                current_entry: current_entry.to_string(),
            });
        }
    }

    /// Sanitize a file entry given its raw bytes.
    ///
    /// Returns the sanitized bytes together with a fresh [`ArchiveStats`]
    /// covering only this entry. This is the core work unit for parallel
    /// entry processing in [`process_tar_at_depth`] and
    /// [`process_zip_at_depth`].
    fn sanitize_entry_bytes(
        &self,
        filename: &str,
        data: &[u8],
        entry_size_hint: Option<u64>,
        depth: u32,
    ) -> Result<(Vec<u8>, ArchiveStats)> {
        let mut out: Vec<u8> = Vec::with_capacity(data.len());
        let mut entry_stats = ArchiveStats::default();
        let mut reader = io::Cursor::new(data);
        self.sanitize_entry(
            filename,
            &mut reader,
            &mut out,
            &mut entry_stats,
            entry_size_hint,
            depth,
        )?;
        Ok((out, entry_stats))
    }

    /// Sanitize the content of a single file entry.
    ///
    /// If the entry is itself an archive (detected via extension), it is
    /// recursively processed up to `self.max_depth`. Otherwise, tries a
    /// structured processor first; falls back to the streaming scanner
    /// if no processor matches.
    ///
    /// For the streaming scanner path, the content is piped through
    /// `scan_reader` directly to the writer for memory-efficient
    /// chunk-based processing (F-02 fix: no full output buffering).
    #[allow(clippy::missing_errors_doc)] // private method
    fn sanitize_entry(
        &self,
        filename: &str,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
        stats: &mut ArchiveStats,
        entry_size_hint: Option<u64>,
        depth: u32,
    ) -> Result<()> {
        // --- Nested archive detection ---
        if let Some(nested_fmt) = ArchiveFormat::from_path(filename) {
            return self.sanitize_nested_archive(
                filename,
                reader,
                writer,
                stats,
                entry_size_hint,
                nested_fmt,
                depth,
            );
        }

        // --- Structured / scanner processing ---

        // Try structured processing first, but only if the entry is
        // within the size cap and --force-text is not set.
        // Oversized entries fall through to the streaming scanner (M-3 fix).
        let within_size_cap = entry_size_hint.is_none_or(|sz| sz <= STRUCTURED_ENTRY_SIZE); // unknown size → allow (conservative)

        if !self.force_text && within_size_cap {
            if let Some(profile) = self.find_profile(filename) {
                // Structured processors need the full content in memory.
                let mut content = Vec::new();
                reader.read_to_end(&mut content).map_err(|e| {
                    SanitizeError::ArchiveError(format!("read entry '{filename}': {e}"))
                })?;

                stats.total_input_bytes += content.len() as u64;

                // A parse error (e.g. binary content with a .yaml extension, like
                // macOS resource-fork ._* files) falls through to the scanner
                // rather than failing the whole archive.
                // A parse error or heuristic rejection falls through to the scanner below.
                let pre_snapshot = self.store.snapshot();
                // Prefer span-based edit mode (field values replaced in place —
                // exact, format-preserving, leak-free even for escaped values).
                // Fall back to the literal structured pass, whose re-serialized
                // output is discarded; either way the store is populated.
                let structured_base: Option<Vec<u8>> =
                    match self
                        .registry
                        .process_to_edits(&content, profile, &self.store)
                    {
                        Ok(Some((edited, _count))) => Some(edited),
                        Ok(None) => match self.registry.process(&content, profile, &self.store) {
                            Ok(Some(_)) => Some(content.clone()),
                            _ => None,
                        },
                        Err(_) => None,
                    };
                if let Some(base) = structured_base {
                    // Run the format-preserving scanner over the structured-redacted
                    // bytes to catch the same values in comments / unstructured
                    // regions. Field values discovered *for this entry* are added
                    // as literal patterns so they are redacted even when the
                    // caller's scanner does not already carry them (library usage
                    // without a pre-discovery pass). When the delta is empty — the
                    // common case in the CLI, where the augmented scanner already
                    // holds every literal — a cached scanner is reused to avoid
                    // rebuilding the automaton per entry.
                    let extra: Vec<ScanPattern> = self
                        .store
                        .iter_since(pre_snapshot)
                        .filter_map(|(category, original, _)| {
                            // Label by category, never the value (labels surface
                            // in report/findings/summary output — no secrets).
                            let label = format!("field:{category}");
                            ScanPattern::from_literal(original.as_str(), category, label).ok()
                        })
                        .collect();
                    let (output, scan_stats) = if extra.is_empty() {
                        self.structured_pass_scanner()?.scan_bytes(&base)?
                    } else {
                        self.scanner.for_structured_pass(extra)?.scan_bytes(&base)?
                    };
                    stats.structured_hits += 1;
                    stats.total_output_bytes += output.len() as u64;
                    stats.file_methods.insert(
                        filename.to_string(),
                        format!("structured+scan:{}", profile.processor),
                    );
                    stats
                        .file_scan_stats
                        .insert(filename.to_string(), scan_stats);
                    writer.write_all(&output).map_err(|e| {
                        SanitizeError::ArchiveError(format!("write entry '{filename}': {e}"))
                    })?;
                    return Ok(());
                }

                // Processor didn't match or failed — fall back to
                // scanner with the already-buffered content.
                let (output, scan_stats) = self.scanner.scan_bytes(&content)?;
                stats.scanner_fallback += 1;
                stats.total_output_bytes += output.len() as u64;
                stats
                    .file_methods
                    .insert(filename.to_string(), "scanner".to_string());
                stats
                    .file_scan_stats
                    .insert(filename.to_string(), scan_stats);
                writer.write_all(&output).map_err(|e| {
                    SanitizeError::ArchiveError(format!("write entry '{filename}': {e}"))
                })?;
                return Ok(());
            }
        }

        // No profile (or entry too large) → streaming scanner.
        // F-02 fix: stream directly from reader → scanner → writer
        // without buffering the full output. We use a CountingWriter
        // to track output bytes alongside the CountingReader for input.
        let mut counting_r = CountingReader::new(reader);
        let mut counting_w = CountingWriter::new(writer);
        let scan_stats = self.scanner.scan_reader(&mut counting_r, &mut counting_w)?;

        stats.scanner_fallback += 1;
        stats.total_input_bytes += counting_r.bytes_read();
        stats.total_output_bytes += counting_w.bytes_written();
        stats
            .file_methods
            .insert(filename.to_string(), "scanner".to_string());
        stats
            .file_scan_stats
            .insert(filename.to_string(), scan_stats);

        Ok(())
    }

    /// Handle a nested archive entry: validate depth/size, buffer, recurse,
    /// and write the sanitized output.
    #[allow(clippy::too_many_arguments)]
    fn sanitize_nested_archive(
        &self,
        filename: &str,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
        stats: &mut ArchiveStats,
        entry_size_hint: Option<u64>,
        nested_fmt: ArchiveFormat,
        depth: u32,
    ) -> Result<()> {
        if depth >= self.max_depth {
            return Err(SanitizeError::RecursionDepthExceeded(format!(
                "nested archive '{}' at depth {} exceeds maximum nesting depth of {}",
                filename, depth, self.max_depth,
            )));
        }

        // Buffer the nested archive (always bounded by STRUCTURED_ENTRY_SIZE).
        // The size hint (from a zip central-directory entry) is checked first for
        // a fast early rejection; the bounded read enforces the cap even when the
        // hint is absent (e.g. some tar entries) to prevent unbounded heap growth.
        if let Some(sz) = entry_size_hint {
            if sz > STRUCTURED_ENTRY_SIZE {
                return Err(SanitizeError::ArchiveError(format!(
                    "nested archive '{}' is too large ({} bytes, limit {} bytes)",
                    filename, sz, STRUCTURED_ENTRY_SIZE,
                )));
            }
        }

        let content = read_bounded(reader, STRUCTURED_ENTRY_SIZE, filename)?;
        stats.total_input_bytes += content.len() as u64;

        // Recurse into the nested archive.
        let mut output_buf: Vec<u8> = Vec::new();
        let child_stats = match nested_fmt {
            ArchiveFormat::Tar => {
                self.process_tar_at_depth(&content[..], &mut output_buf, depth + 1)?
            }
            ArchiveFormat::TarGz => {
                self.process_tar_gz_at_depth(&content[..], &mut output_buf, depth + 1)?
            }
            ArchiveFormat::Zip => {
                let reader = io::Cursor::new(&content);
                let mut writer = io::Cursor::new(Vec::new());
                let s = self.process_zip_at_depth(reader, &mut writer, depth + 1)?;
                output_buf = writer.into_inner();
                s
            }
        };

        stats.nested_archives += 1;
        stats.merge(&child_stats);
        stats.total_output_bytes += output_buf.len() as u64;
        let fmt_name = match nested_fmt {
            ArchiveFormat::Tar => "tar",
            ArchiveFormat::TarGz => "tar.gz",
            ArchiveFormat::Zip => "zip",
        };
        stats
            .file_methods
            .insert(filename.to_string(), format!("nested:{fmt_name}"));
        writer.write_all(&output_buf).map_err(|e| {
            SanitizeError::ArchiveError(format!("write nested archive '{filename}': {e}"))
        })?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Profile discovery passes (two-phase support)
    // -----------------------------------------------------------------------
    //
    // These methods perform a read-only pre-pass over an archive, running the
    // structured processor on every profile-matched entry and discarding the
    // output.  The side-effect is that `self.store` is populated with the
    // original→replacement mappings for those fields, so a subsequent call to
    // `build_augmented_scanner` can inject those values as literals into the
    // scanner used for the real processing pass.

    /// Run the structured processor on every profile-matched entry in a
    /// `.tar` archive, recording replacements into the store.  Output is
    /// discarded; the archive is not modified.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive cannot be read or an entry cannot be processed.
    pub fn discover_profiles_tar<R: Read>(&self, reader: R) -> Result<()> {
        if self.profiles.is_empty() {
            return Ok(());
        }
        let mut archive = tar::Archive::new(reader);
        let entries = archive
            .entries()
            .map_err(|e| SanitizeError::ArchiveError(format!("discover tar entries: {e}")))?;
        for entry_result in entries {
            let mut entry = entry_result
                .map_err(|e| SanitizeError::ArchiveError(format!("discover tar entry: {e}")))?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .map_err(|e| SanitizeError::ArchiveError(format!("entry path: {e}")))?
                .to_string_lossy()
                .to_string();
            let Some(profile) = self.find_profile(&path) else {
                continue;
            };
            let content = match read_bounded(&mut entry, STRUCTURED_ENTRY_SIZE, &path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "discovery: skipping oversized entry");
                    continue;
                }
            };
            if let Err(e) = self.registry.process(&content, profile, &self.store) {
                tracing::warn!(path = %path, error = %e, "discovery: structured processor failed; partial mappings may persist");
            }
        }
        Ok(())
    }

    /// Run the structured processor on every profile-matched entry in a
    /// `.tar.gz` archive, recording replacements into the store.  Output is
    /// discarded; the archive is not modified.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive cannot be read or an entry cannot be processed.
    pub fn discover_profiles_tar_gz<R: Read>(&self, reader: R) -> Result<()> {
        let gz = flate2::read::GzDecoder::new(reader);
        self.discover_profiles_tar(gz)
    }

    /// Run the structured processor on every profile-matched entry in a
    /// `.zip` archive, recording replacements into the store.  Output is
    /// discarded; the archive is not modified.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive cannot be read or an entry cannot be processed.
    pub fn discover_profiles_zip<R: Read + Seek>(&self, reader: R) -> Result<()> {
        if self.profiles.is_empty() {
            return Ok(());
        }
        let mut zip = zip::ZipArchive::new(reader)
            .map_err(|e| SanitizeError::ArchiveError(format!("open zip for discovery: {e}")))?;
        for i in 0..zip.len() {
            let mut entry = zip
                .by_index(i)
                .map_err(|e| SanitizeError::ArchiveError(format!("zip entry {i}: {e}")))?;
            if entry.is_dir() {
                continue;
            }
            let name = sanitize_zip_entry_name(entry.name());
            let Some(profile) = self.find_profile(&name) else {
                continue;
            };
            let content = match read_bounded(&mut entry, STRUCTURED_ENTRY_SIZE, &name) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(name = %name, error = %e, "discovery: skipping oversized entry");
                    continue;
                }
            };
            if let Err(e) = self.registry.process(&content, profile, &self.store) {
                tracing::warn!(name = %name, error = %e, "discovery: structured processor failed; partial mappings may persist");
            }
        }
        Ok(())
    }

    // Tar processing
    // -----------------------------------------------------------------------

    /// Process a `.tar` archive, sanitizing each file entry and
    /// rebuilding the archive with preserved metadata.
    ///
    /// Entries that are not regular files (directories, symlinks, etc.)
    /// are copied through unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::ArchiveError`] on I/O failures or
    /// [`SanitizeError::RecursionDepthExceeded`] for nested archives.
    pub fn process_tar<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<ArchiveStats> {
        self.process_tar_at_depth(reader, writer, 0)
    }

    /// Internal: process a tar archive at a given nesting depth.
    ///
    /// Uses a speculative-buffer strategy to decide between parallel and
    /// sequential processing:
    ///
    /// - **Parallel** (total buffered data ≤ `PARALLEL_TAR_DATA_SIZE` AND
    ///   file count ≥ threshold AND not inside a rayon worker): buffer all
    ///   entries, sanitize concurrently with rayon, write in source order.
    /// - **Sequential — buffered** (threshold not met but data fits): process
    ///   entries from the in-memory buffer one at a time.
    /// - **Sequential — streaming** (data exceeds cap mid-stream): process
    ///   already-buffered entries from memory, then continue streaming the
    ///   remainder of the archive without additional buffering.
    ///
    /// Unlike zip, tar has no central directory so sizes cannot be known before
    /// reading. The buffer cap (`PARALLEL_TAR_DATA_SIZE`) bounds peak memory to
    /// cap + one entry overhead regardless of archive size.
    #[allow(clippy::too_many_lines)]
    fn process_tar_at_depth<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        depth: u32,
    ) -> Result<ArchiveStats> {
        struct TarEntry {
            header: tar::Header,
            path: String,
            is_file: bool,
            passes_filter: bool,
            data: Vec<u8>,
        }

        let mut archive = tar::Archive::new(reader);
        let mut builder = tar::Builder::new(writer);
        let mut stats = ArchiveStats::default();

        // --- Phase 1: speculative buffering ----------------------------------
        // Stream entries into memory, tracking total file-data size.
        // Stop buffering (but keep the last entry) if the cap is exceeded.
        let mut entries_iter = archive
            .entries()
            .map_err(|e| SanitizeError::ArchiveError(format!("read tar entries: {e}")))?;

        let mut buffered: Vec<TarEntry> = Vec::new();
        let mut file_count: usize = 0;
        let mut total_data: u64 = 0;
        let mut overflowed = false;

        for entry_result in entries_iter.by_ref() {
            let mut entry = entry_result
                .map_err(|e| SanitizeError::ArchiveError(format!("read tar entry: {e}")))?;

            let header = entry.header().clone();
            let path = entry
                .path()
                .map_err(|e| SanitizeError::ArchiveError(format!("entry path: {e}")))?
                .to_string_lossy()
                .into_owned();
            let is_file = header.entry_type().is_file();
            let passes_filter = !is_file || self.filter.passes(&path);

            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|e| SanitizeError::ArchiveError(format!("read entry '{path}': {e}")))?;
            drop(entry);

            if is_file && passes_filter {
                file_count += 1;
                total_data = total_data.saturating_add(data.len() as u64);
            }

            buffered.push(TarEntry {
                header,
                path,
                is_file,
                passes_filter,
                data,
            });

            if total_data > PARALLEL_TAR_DATA_SIZE {
                overflowed = true;
                break;
            }
        }

        // --- Phase 2: choose strategy ----------------------------------------
        let use_parallel = !overflowed
            && file_count >= self.parallel_threshold
            && rayon::current_thread_index().is_none();

        if use_parallel {
            // --- Parallel path -----------------------------------------------
            // Sanitize all file entries concurrently; write in source order.
            let file_indices: Vec<usize> = buffered
                .iter()
                .enumerate()
                .filter(|(_, e)| e.is_file && e.passes_filter)
                .map(|(i, _)| i)
                .collect();

            let results: Vec<ParEntryResult> = file_indices
                .into_par_iter()
                .map(|i| {
                    let e = &buffered[i];
                    let size_hint = e.header.size().ok();
                    (
                        i,
                        self.sanitize_entry_bytes(&e.path, &e.data, size_hint, depth),
                    )
                })
                .collect();

            let mut sanitized: Vec<Option<(Vec<u8>, ArchiveStats)>> = vec![None; buffered.len()];
            for (i, r) in results {
                sanitized[i] = Some(r?);
            }

            for (i, entry) in buffered.iter().enumerate() {
                if !entry.is_file {
                    builder
                        .append(&entry.header, entry.data.as_slice())
                        .map_err(|e| {
                            SanitizeError::ArchiveError(format!("append '{}': {e}", entry.path))
                        })?;
                    stats.entries_skipped += 1;
                    self.emit_progress(&stats, None, &entry.path);
                    continue;
                }
                if !entry.passes_filter {
                    stats.entries_filtered += 1;
                    self.emit_progress(&stats, None, &entry.path);
                    continue;
                }

                let (sanitized_buf, entry_stats) =
                    sanitized[i].take().expect("parallel result missing");
                stats.merge(&entry_stats);
                self.emit_entry_bytes(&entry.path, &sanitized_buf);

                let mut new_header = entry.header.clone();
                let safe_path = sanitize_tar_entry_name(&entry.path);
                new_header.set_path(&safe_path).map_err(|e| {
                    SanitizeError::ArchiveError(format!("set path '{safe_path}': {e}"))
                })?;
                new_header.set_size(sanitized_buf.len() as u64);
                new_header.set_cksum();
                builder
                    .append(&new_header, sanitized_buf.as_slice())
                    .map_err(|e| {
                        SanitizeError::ArchiveError(format!("append '{safe_path}': {e}"))
                    })?;
                stats.files_processed += 1;
                self.emit_progress(&stats, None, &entry.path);
            }
        } else {
            // --- Sequential path ---------------------------------------------
            // Process buffered entries first, then stream the remainder.

            // Helper: write one buffered entry to the builder.
            let write_buffered = |entry: &TarEntry,
                                  builder: &mut tar::Builder<W>,
                                  stats: &mut ArchiveStats,
                                  processor: &ArchiveProcessor|
             -> Result<()> {
                if !entry.is_file {
                    builder
                        .append(&entry.header, entry.data.as_slice())
                        .map_err(|e| {
                            SanitizeError::ArchiveError(format!("append '{}': {e}", entry.path))
                        })?;
                    stats.entries_skipped += 1;
                    processor.emit_progress(stats, None, &entry.path);
                    return Ok(());
                }
                if !entry.passes_filter {
                    stats.entries_filtered += 1;
                    processor.emit_progress(stats, None, &entry.path);
                    return Ok(());
                }
                let size_hint = entry.header.size().ok();
                let (sanitized_buf, entry_stats) =
                    processor.sanitize_entry_bytes(&entry.path, &entry.data, size_hint, depth)?;
                stats.merge(&entry_stats);
                processor.emit_entry_bytes(&entry.path, &sanitized_buf);
                let mut new_header = entry.header.clone();
                let safe_path = sanitize_tar_entry_name(&entry.path);
                new_header.set_path(&safe_path).map_err(|e| {
                    SanitizeError::ArchiveError(format!("set path '{safe_path}': {e}"))
                })?;
                new_header.set_size(sanitized_buf.len() as u64);
                new_header.set_cksum();
                builder
                    .append(&new_header, sanitized_buf.as_slice())
                    .map_err(|e| {
                        SanitizeError::ArchiveError(format!("append '{safe_path}': {e}"))
                    })?;
                stats.files_processed += 1;
                processor.emit_progress(stats, None, &entry.path);
                Ok(())
            };

            for entry in &buffered {
                write_buffered(entry, &mut builder, &mut stats, self)?;
            }
            drop(buffered);

            // Stream remaining entries when the buffer cap was exceeded.
            if overflowed {
                for entry_result in entries_iter {
                    let mut entry = entry_result
                        .map_err(|e| SanitizeError::ArchiveError(format!("read tar entry: {e}")))?;

                    let header = entry.header().clone();
                    let path = entry
                        .path()
                        .map_err(|e| SanitizeError::ArchiveError(format!("entry path: {e}")))?
                        .to_string_lossy()
                        .into_owned();
                    let is_file = header.entry_type().is_file();

                    if !is_file {
                        let mut data = Vec::new();
                        entry.read_to_end(&mut data).map_err(|e| {
                            SanitizeError::ArchiveError(format!("read '{path}': {e}"))
                        })?;
                        drop(entry);
                        builder.append(&header, data.as_slice()).map_err(|e| {
                            SanitizeError::ArchiveError(format!("append '{path}': {e}"))
                        })?;
                        stats.entries_skipped += 1;
                        self.emit_progress(&stats, None, &path);
                        continue;
                    }

                    if !self.filter.passes(&path) {
                        stats.entries_filtered += 1;
                        continue;
                    }

                    let size_hint = header.size().ok();
                    let mut sanitized_buf = Vec::new();
                    let mut entry_stats = ArchiveStats::default();
                    self.sanitize_entry(
                        &path,
                        &mut entry,
                        &mut sanitized_buf,
                        &mut entry_stats,
                        size_hint,
                        depth,
                    )?;
                    drop(entry);
                    self.emit_entry_bytes(&path, &sanitized_buf);

                    let mut new_header = header.clone();
                    let safe_path = sanitize_tar_entry_name(&path);
                    new_header.set_path(&safe_path).map_err(|e| {
                        SanitizeError::ArchiveError(format!("set path '{safe_path}': {e}"))
                    })?;
                    new_header.set_size(sanitized_buf.len() as u64);
                    new_header.set_cksum();
                    builder
                        .append(&new_header, sanitized_buf.as_slice())
                        .map_err(|e| {
                            SanitizeError::ArchiveError(format!("append '{safe_path}': {e}"))
                        })?;

                    stats.merge(&entry_stats);
                    stats.files_processed += 1;
                    self.emit_progress(&stats, None, &path);
                }
            }
        }

        builder
            .finish()
            .map_err(|e| SanitizeError::ArchiveError(format!("finalize tar: {e}")))?;

        Ok(stats)
    }

    /// Process a `.tar.gz` archive (gzip-compressed tar).
    ///
    /// Decompresses on the fly, processes each entry, and recompresses
    /// the output.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::ArchiveError`] on I/O failures or
    /// [`SanitizeError::RecursionDepthExceeded`] for nested archives.
    pub fn process_tar_gz<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<ArchiveStats> {
        self.process_tar_gz_at_depth(reader, writer, 0)
    }

    /// Internal: process a tar.gz archive at a given nesting depth.
    fn process_tar_gz_at_depth<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        depth: u32,
    ) -> Result<ArchiveStats> {
        let gz_reader = flate2::read::GzDecoder::new(reader);
        let gz_writer = flate2::write::GzEncoder::new(writer, flate2::Compression::fast());

        let stats = self.process_tar_at_depth(gz_reader, gz_writer, depth)?;
        // GzEncoder is flushed when the tar builder finishes and the
        // encoder is dropped. The `finish()` call in `process_tar`
        // flushes the tar builder, which flushes writes to the
        // GzEncoder. When the GzEncoder is dropped it finalises the
        // gzip stream.
        Ok(stats)
    }

    // -----------------------------------------------------------------------
    // Zip processing
    // -----------------------------------------------------------------------

    /// Process a `.zip` archive, sanitizing each file entry and
    /// rebuilding the archive with preserved metadata.
    ///
    /// # Type Bounds
    ///
    /// Zip requires seekable I/O for both reading and writing.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::ArchiveError`] on I/O failures or
    /// [`SanitizeError::RecursionDepthExceeded`] for nested archives.
    pub fn process_zip<R: Read + Seek, W: Write + Seek>(
        &self,
        reader: R,
        writer: W,
    ) -> Result<ArchiveStats> {
        self.process_zip_at_depth(reader, writer, 0)
    }

    /// Internal: process a zip archive at a given nesting depth.
    ///
    /// Uses a lightweight metadata pre-pass (local-header reads, no data
    /// decompression) to decide between parallel and sequential strategies:
    ///
    /// - **Parallel** (total uncompressed ≤ `PARALLEL_ZIP_DATA_SIZE` AND
    ///   file count ≥ threshold AND depth == 0): load all entry data into
    ///   memory, sanitize with rayon, write in order.
    /// - **Sequential** (everything else): read → sanitize → write one entry
    ///   at a time.  Peak memory is bounded to 2 × largest single entry.
    #[allow(clippy::too_many_lines)]
    fn process_zip_at_depth<R: Read + Seek, W: Write + Seek>(
        &self,
        reader: R,
        writer: W,
        depth: u32,
    ) -> Result<ArchiveStats> {
        // --- Stage 0: metadata pre-pass (no data reads) ---------------------
        // Read local file headers to collect names, sizes, and options.
        // This does N seeks but decompresses nothing, keeping memory flat.
        struct ZipMeta {
            name: String,
            is_dir: bool,
            compression: zip::CompressionMethod,
            last_modified: Option<zip::DateTime>,
            unix_mode: Option<u32>,
            size: u64,
        }

        let mut zip_in = zip::ZipArchive::new(reader)
            .map_err(|e| SanitizeError::ArchiveError(format!("open zip: {}", e)))?;
        let total_entries = zip_in.len();
        let total_entries_hint = Some(total_entries as u64);

        let mut metas: Vec<ZipMeta> = Vec::with_capacity(total_entries);
        let mut file_count = 0usize;
        let mut total_uncompressed_size: u64 = 0;

        for i in 0..total_entries {
            let entry = zip_in
                .by_index(i)
                .map_err(|e| SanitizeError::ArchiveError(format!("zip entry {}: {}", i, e)))?;
            let is_dir = entry.is_dir();
            let size = entry.size();
            if !is_dir {
                file_count += 1;
                total_uncompressed_size = total_uncompressed_size.saturating_add(size);
            }
            metas.push(ZipMeta {
                name: sanitize_zip_entry_name(entry.name()),
                is_dir,
                compression: entry.compression(),
                last_modified: entry.last_modified(),
                unix_mode: entry.unix_mode(),
                size,
            });
            // entry dropped here — no data decompressed
        }

        // Parallel only when the total data fits comfortably in memory.
        // Parallel when: enough entries, data fits in memory, and we are not
        // already running inside a rayon worker thread (nested parallelism
        // would over-subscribe the pool without proportional gains).
        let use_parallel = file_count >= self.parallel_threshold
            && rayon::current_thread_index().is_none()
            && total_uncompressed_size <= PARALLEL_ZIP_DATA_SIZE;

        let mut stats = ArchiveStats::default();

        // Helper: build SimpleFileOptions for a metadata entry.
        let make_options = |m: &ZipMeta| {
            let mut opts =
                zip::write::SimpleFileOptions::default().compression_method(m.compression);
            if let Some(dt) = m.last_modified {
                opts = opts.last_modified_time(dt);
            }
            if let Some(mode) = m.unix_mode {
                opts.unix_permissions(mode)
            } else {
                opts
            }
        };

        if use_parallel {
            // --- Parallel path: load all data then sanitize concurrently ----
            struct ZipEntry {
                meta_idx: usize,
                data: Vec<u8>,
            }

            let mut file_entries: Vec<ZipEntry> = Vec::with_capacity(file_count);

            for (i, meta) in metas.iter().enumerate() {
                if meta.is_dir {
                    continue;
                }
                // Skip loading data for entries that will be filtered out.
                if !self.filter.passes(&meta.name) {
                    continue;
                }
                let mut entry = zip_in
                    .by_index(i)
                    .map_err(|e| SanitizeError::ArchiveError(format!("zip entry {}: {}", i, e)))?;
                let mut data = Vec::new();
                entry.read_to_end(&mut data).map_err(|e| {
                    SanitizeError::ArchiveError(format!("read zip entry '{}': {}", meta.name, e))
                })?;
                file_entries.push(ZipEntry { meta_idx: i, data });
            }

            let results: Vec<ParEntryResult> = file_entries
                .into_par_iter()
                .map(|e| {
                    let meta = &metas[e.meta_idx];
                    let result =
                        self.sanitize_entry_bytes(&meta.name, &e.data, Some(meta.size), depth);
                    (e.meta_idx, result)
                })
                .collect();

            // Collect into a positional Vec (indexed by metas position) for
            // O(1) ordered writes, avoiding HashMap hashing overhead.
            let mut sanitized: Vec<Option<(Vec<u8>, ArchiveStats)>> = vec![None; metas.len()];
            for (meta_idx, r) in results {
                sanitized[meta_idx] = Some(r?);
            }

            let mut zip_out = zip::ZipWriter::new(writer);
            for (i, meta) in metas.iter().enumerate() {
                let options = make_options(meta);
                if meta.is_dir {
                    zip_out.add_directory(&meta.name, options).map_err(|e| {
                        SanitizeError::ArchiveError(format!("add dir '{}': {}", meta.name, e))
                    })?;
                    stats.entries_skipped += 1;
                    self.emit_progress(&stats, total_entries_hint, &meta.name);
                    continue;
                }
                // Filter: drop entries not matching --only/--exclude rules.
                if !self.filter.passes(&meta.name) {
                    stats.entries_filtered += 1;
                    self.emit_progress(&stats, total_entries_hint, &meta.name);
                    continue;
                }
                let (sanitized_buf, entry_stats) = sanitized[i]
                    .take()
                    .expect("file entry sanitization result missing");
                stats.merge(&entry_stats);
                self.emit_entry_bytes(&meta.name, &sanitized_buf);
                zip_out.start_file(&meta.name, options).map_err(|e| {
                    SanitizeError::ArchiveError(format!("start file '{}': {}", meta.name, e))
                })?;
                zip_out.write_all(&sanitized_buf).map_err(|e| {
                    SanitizeError::ArchiveError(format!("write file '{}': {}", meta.name, e))
                })?;
                stats.files_processed += 1;
                self.emit_progress(&stats, total_entries_hint, &meta.name);
            }
            zip_out
                .finish()
                .map_err(|e| SanitizeError::ArchiveError(format!("finalize zip: {}", e)))?;
        } else {
            // --- Sequential path: one entry at a time -----------------------
            // Only one entry's data (input + sanitized output) is live at once.
            let mut zip_out = zip::ZipWriter::new(writer);
            for (i, meta) in metas.iter().enumerate() {
                let options = make_options(meta);
                if meta.is_dir {
                    zip_out.add_directory(&meta.name, options).map_err(|e| {
                        SanitizeError::ArchiveError(format!("add dir '{}': {}", meta.name, e))
                    })?;
                    stats.entries_skipped += 1;
                    self.emit_progress(&stats, total_entries_hint, &meta.name);
                    continue;
                }

                // Filter: drop entries not matching --only/--exclude rules.
                if !self.filter.passes(&meta.name) {
                    stats.entries_filtered += 1;
                    self.emit_progress(&stats, total_entries_hint, &meta.name);
                    continue;
                }

                let data = {
                    let mut entry = zip_in.by_index(i).map_err(|e| {
                        SanitizeError::ArchiveError(format!("zip entry {}: {}", i, e))
                    })?;
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).map_err(|e| {
                        SanitizeError::ArchiveError(format!(
                            "read zip entry '{}': {}",
                            meta.name, e
                        ))
                    })?;
                    buf
                    // entry dropped here
                };

                let (sanitized_buf, entry_stats) =
                    self.sanitize_entry_bytes(&meta.name, &data, Some(meta.size), depth)?;
                drop(data);
                self.emit_entry_bytes(&meta.name, &sanitized_buf);

                zip_out.start_file(&meta.name, options).map_err(|e| {
                    SanitizeError::ArchiveError(format!("start file '{}': {}", meta.name, e))
                })?;
                zip_out.write_all(&sanitized_buf).map_err(|e| {
                    SanitizeError::ArchiveError(format!("write file '{}': {}", meta.name, e))
                })?;
                drop(sanitized_buf);

                stats.merge(&entry_stats);
                stats.files_processed += 1;
                self.emit_progress(&stats, total_entries_hint, &meta.name);
            }
            zip_out
                .finish()
                .map_err(|e| SanitizeError::ArchiveError(format!("finalize zip: {}", e)))?;
        }

        Ok(stats)
    }

    // -----------------------------------------------------------------------
    // Format-aware dispatch
    // -----------------------------------------------------------------------

    /// Auto-detect the archive format and process accordingly.
    ///
    /// For zip archives the reader must additionally implement `Seek`.
    /// This method accepts `Read + Seek` to cover all formats uniformly.
    /// Tar and tar.gz do not require seeking, but the bound is imposed
    /// for a single entry point.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::ArchiveError`] on I/O failures or
    /// [`SanitizeError::RecursionDepthExceeded`] for nested archives.
    pub fn process<R: Read + Seek, W: Write + Seek>(
        &self,
        reader: R,
        writer: W,
        format: ArchiveFormat,
    ) -> Result<ArchiveStats> {
        match format {
            ArchiveFormat::Zip => self.process_zip(reader, writer),
            ArchiveFormat::Tar => self.process_tar(reader, writer),
            ArchiveFormat::TarGz => self.process_tar_gz(reader, writer),
        }
    }
}

// ---------------------------------------------------------------------------
// Counting reader wrapper (for input byte tracking)
// ---------------------------------------------------------------------------

/// A thin wrapper around a reader that counts bytes read.
struct CountingReader<'a> {
    inner: &'a mut dyn Read,
    count: u64,
}

impl<'a> CountingReader<'a> {
    fn new(inner: &'a mut dyn Read) -> Self {
        Self { inner, count: 0 }
    }

    fn bytes_read(&self) -> u64 {
        self.count
    }
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

/// A thin wrapper around a writer that counts bytes written (F-02 fix).
struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    count: u64,
}

impl<'a> CountingWriter<'a> {
    fn new(inner: &'a mut dyn Write) -> Self {
        Self { inner, count: 0 }
    }

    fn bytes_written(&self) -> u64 {
        self.count
    }
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::generator::HmacGenerator;
    use crate::processor::profile::{FieldRule, FileTypeProfile};
    use crate::processor::registry::ProcessorRegistry;
    use crate::scanner::{ScanConfig, ScanPattern};
    use std::io::Cursor;
    use std::sync::Mutex;

    /// Build a test archive processor with an email pattern and a JSON profile.
    fn make_archive_processor() -> ArchiveProcessor {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));

        let patterns = vec![
            ScanPattern::from_regex(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                Category::Email,
                "email",
            )
            .unwrap(),
            ScanPattern::from_literal("SUPERSECRET", Category::Custom("api_key".into()), "api_key")
                .unwrap(),
        ];

        let scanner = Arc::new(
            StreamScanner::new(patterns, Arc::clone(&store), ScanConfig::default()).unwrap(),
        );

        let registry = Arc::new(ProcessorRegistry::with_builtins());

        let profiles = vec![FileTypeProfile::new(
            "json",
            vec![FieldRule::new("*").with_category(Category::Custom("field".into()))],
        )
        .with_extension(".json")];

        ArchiveProcessor::new(registry, scanner, store, profiles)
    }

    // -- Tar tests ----------------------------------------------------------

    fn build_test_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            for (name, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(1_700_000_000);
                header.set_cksum();
                builder.append_data(&mut header, *name, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        buf
    }

    #[test]
    fn tar_sanitizes_plaintext_with_scanner() {
        let proc = make_archive_processor();
        let input = build_test_tar(&[("readme.txt", b"Contact alice@corp.com for help.")]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&input[..], &mut output).unwrap();

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.scanner_fallback, 1);
        assert_eq!(stats.structured_hits, 0);

        // Verify the output is a valid tar and the secret is gone.
        let mut archive = tar::Archive::new(&output[..]);
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let mut content = String::new();
            e.read_to_string(&mut content).unwrap();
            assert!(
                !content.contains("alice@corp.com"),
                "email should be sanitized: {content}"
            );
        }
    }

    #[test]
    fn tar_sanitizes_json_with_structured_processor() {
        let proc = make_archive_processor();
        let json_content = br#"{"email": "bob@example.org", "name": "Bob"}"#;
        let input = build_test_tar(&[("config.json", json_content)]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&input[..], &mut output).unwrap();

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.structured_hits, 1);
        assert_eq!(stats.scanner_fallback, 0);
        assert_eq!(
            stats.file_methods.get("config.json").unwrap(),
            "structured+scan:json"
        );

        // Verify sanitized output.
        let mut archive = tar::Archive::new(&output[..]);
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let mut content = String::new();
            e.read_to_string(&mut content).unwrap();
            assert!(
                !content.contains("bob@example.org"),
                "email should be sanitized"
            );
            assert!(!content.contains("Bob"), "name should be sanitized");
        }
    }

    /// Regression: structured entries inside archives must preserve comments,
    /// key order, and whitespace (byte-level), redacting only field values —
    /// not re-serialize the parsed tree. Uses a scanner with NO pre-loaded
    /// literals, so the field value is redacted purely via the per-entry
    /// discovery delta; the same value embedded in a comment is redacted too.
    #[test]
    fn archive_structured_entry_preserves_comments_and_formatting() {
        let gen = Arc::new(HmacGenerator::new([7u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        // Empty pattern set: redaction of the email can only come from the
        // structured field discovery, not from a base regex.
        let scanner = Arc::new(
            StreamScanner::new(vec![], Arc::clone(&store), ScanConfig::default()).unwrap(),
        );
        let registry = Arc::new(ProcessorRegistry::with_builtins());
        let profiles = vec![FileTypeProfile::new(
            "yaml",
            vec![FieldRule::new("owner_email").with_category(Category::Email)],
        )
        .with_extension(".yaml")];
        let proc = ArchiveProcessor::new(registry, scanner, store, profiles);

        let yaml = b"# owner was secret.person@corp.test  (keep this comment)\nowner_email: secret.person@corp.test\nport: 8080\n";
        let input = build_test_tar(&[("settings.yaml", yaml)]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&input[..], &mut output).unwrap();
        assert_eq!(stats.structured_hits, 1);

        let mut archive = tar::Archive::new(&output[..]);
        let mut content = String::new();
        for entry in archive.entries().unwrap() {
            entry.unwrap().read_to_string(&mut content).unwrap();
        }

        // Secret email gone from both the field and the comment.
        assert!(
            !content.contains("secret.person@corp.test"),
            "email must be redacted everywhere: {content}"
        );
        // Formatting preserved byte-for-byte around the redactions: the comment
        // line (with its trailing text) and the unrelated `port` line survive,
        // and the file was not re-serialized into a different shape.
        assert!(
            content.starts_with("# owner was "),
            "leading comment must be preserved: {content}"
        );
        assert!(
            content.contains("(keep this comment)"),
            "comment trailing text must be preserved: {content}"
        );
        assert!(
            content.contains("\nport: 8080\n"),
            "unrelated line and surrounding whitespace must be untouched: {content}"
        );
        assert!(
            content.contains("owner_email: "),
            "key and `: ` separator must be preserved: {content}"
        );
    }

    #[test]
    fn tar_preserves_metadata() {
        let proc = make_archive_processor();
        let input = build_test_tar(&[("data.txt", b"SUPERSECRET token here")]);

        let mut output = Vec::new();
        proc.process_tar(&input[..], &mut output).unwrap();

        let mut archive = tar::Archive::new(&output[..]);
        for entry in archive.entries().unwrap() {
            let e = entry.unwrap();
            let hdr = e.header();
            assert_eq!(hdr.mode().unwrap(), 0o644);
            assert_eq!(hdr.mtime().unwrap(), 1_700_000_000);
        }
    }

    #[test]
    fn tar_handles_multiple_files() {
        let proc = make_archive_processor();
        let input = build_test_tar(&[
            ("a.txt", b"alice@corp.com"),
            ("b.json", br#"{"key":"value"}"#),
            ("c.log", b"no secrets here"),
        ]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&input[..], &mut output).unwrap();

        assert_eq!(stats.files_processed, 3);
        // b.json matched the JSON profile
        assert_eq!(stats.structured_hits, 1);
        // a.txt and c.log fall back to scanner
        assert_eq!(stats.scanner_fallback, 2);
    }

    #[test]
    fn tar_passes_through_directories() {
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            // Add a directory entry.
            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_cksum();
            builder
                .append_data(&mut dir_header, "mydir/", &b""[..])
                .unwrap();

            // Add a file.
            let mut file_header = tar::Header::new_gnu();
            file_header.set_size(5);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            builder
                .append_data(&mut file_header, "mydir/hello.txt", &b"hello"[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let proc = make_archive_processor();
        let mut output = Vec::new();
        let stats = proc.process_tar(&buf[..], &mut output).unwrap();

        assert_eq!(stats.entries_skipped, 1);
        assert_eq!(stats.files_processed, 1);
    }

    // -- Tar.gz tests -------------------------------------------------------

    #[test]
    fn tar_gz_round_trip() {
        let proc = make_archive_processor();

        // Build a tar and gzip it.
        let tar_data = build_test_tar(&[("secret.txt", b"Key is SUPERSECRET okay")]);
        let mut gz_input = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz_input, flate2::Compression::fast());
            encoder.write_all(&tar_data).unwrap();
            encoder.finish().unwrap();
        }

        let mut gz_output = Vec::new();
        let stats = proc.process_tar_gz(&gz_input[..], &mut gz_output).unwrap();

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.scanner_fallback, 1);

        // Decompress and verify.
        let decoder = flate2::read::GzDecoder::new(&gz_output[..]);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let mut content = String::new();
            e.read_to_string(&mut content).unwrap();
            assert!(
                !content.contains("SUPERSECRET"),
                "secret should be sanitized: {content}"
            );
        }
    }

    // -- Zip tests ----------------------------------------------------------

    fn build_test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            for (name, data) in entries {
                let options = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);
                zip.start_file(*name, options).unwrap();
                zip.write_all(data).unwrap();
            }
            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn zip_sanitizes_plaintext_with_scanner() {
        let proc = make_archive_processor();
        let zip_data = build_test_zip(&[("notes.txt", b"Reach alice@corp.com for info.")]);

        let reader = Cursor::new(&zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.scanner_fallback, 1);

        // Verify the output zip.
        let out_data = writer.into_inner();
        let mut zip_out = zip::ZipArchive::new(Cursor::new(out_data)).unwrap();
        let mut entry = zip_out.by_index(0).unwrap();
        let mut content = String::new();
        entry.read_to_string(&mut content).unwrap();
        assert!(
            !content.contains("alice@corp.com"),
            "email should be sanitized: {content}"
        );
    }

    #[test]
    fn zip_sanitizes_json_with_structured_processor() {
        let proc = make_archive_processor();
        let json_content = br#"{"password": "hunter2", "host": "db.internal"}"#;
        let zip_data = build_test_zip(&[("settings.json", json_content)]);

        let reader = Cursor::new(&zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.structured_hits, 1);

        let out_data = writer.into_inner();
        let mut zip_out = zip::ZipArchive::new(Cursor::new(out_data)).unwrap();
        let mut entry = zip_out.by_index(0).unwrap();
        let mut content = String::new();
        entry.read_to_string(&mut content).unwrap();
        assert!(!content.contains("hunter2"), "password should be sanitized");
        assert!(!content.contains("db.internal"), "host should be sanitized");
    }

    #[test]
    fn zip_preserves_directory_entries() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);

            let dir_options = zip::write::SimpleFileOptions::default();
            zip.add_directory("subdir/", dir_options).unwrap();

            let file_options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("subdir/data.txt", file_options).unwrap();
            zip.write_all(b"SUPERSECRET value").unwrap();

            zip.finish().unwrap();
        }

        let zip_data = buf.into_inner();
        let proc = make_archive_processor();
        let reader = Cursor::new(&zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();

        assert_eq!(stats.entries_skipped, 1); // directory
        assert_eq!(stats.files_processed, 1);
    }

    #[test]
    fn zip_handles_multiple_files() {
        let proc = make_archive_processor();
        let zip_data = build_test_zip(&[
            ("file1.txt", b"alice@corp.com"),
            ("file2.json", br#"{"secret":"SUPERSECRET"}"#),
            ("file3.log", b"nothing to see"),
        ]);

        let reader = Cursor::new(&zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();

        assert_eq!(stats.files_processed, 3);
        assert_eq!(stats.structured_hits, 1); // JSON
        assert_eq!(stats.scanner_fallback, 2); // .txt + .log
    }

    #[test]
    fn tar_progress_callback_receives_updates() {
        let updates = Arc::new(Mutex::new(Vec::new()));
        let proc = make_archive_processor().with_progress_callback({
            let updates = Arc::clone(&updates);
            Arc::new(move |progress| {
                updates
                    .lock()
                    .expect("archive progress lock")
                    .push(progress.clone());
            })
        });
        let input = build_test_tar(&[("a.txt", b"alice@corp.com"), ("b.txt", b"SUPERSECRET")]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&input[..], &mut output).unwrap();
        let updates = updates.lock().unwrap();

        assert_eq!(updates.len(), 2);
        assert_eq!(updates.last().unwrap().entries_seen, 2);
        assert_eq!(
            updates.last().unwrap().files_processed,
            stats.files_processed
        );
        assert_eq!(updates.last().unwrap().total_entries, None);
    }

    #[test]
    fn zip_progress_callback_reports_total_entries() {
        let updates = Arc::new(Mutex::new(Vec::new()));
        let proc = make_archive_processor().with_progress_callback({
            let updates = Arc::clone(&updates);
            Arc::new(move |progress| {
                updates
                    .lock()
                    .expect("archive progress lock")
                    .push(progress.clone());
            })
        });
        let zip_data = build_test_zip(&[
            ("file1.txt", b"alice@corp.com"),
            ("file2.log", b"nothing to see"),
        ]);

        let reader = Cursor::new(&zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();
        let updates = updates.lock().unwrap();

        assert_eq!(updates.len(), 2);
        assert_eq!(
            updates.last().unwrap().files_processed,
            stats.files_processed
        );
        assert_eq!(updates.last().unwrap().total_entries, Some(2));
        assert_eq!(updates.last().unwrap().current_entry, "file2.log");
    }

    // -- Format detection tests ---------------------------------------------

    #[test]
    fn format_detection_from_path() {
        assert_eq!(
            ArchiveFormat::from_path("data.tar"),
            Some(ArchiveFormat::Tar)
        );
        assert_eq!(
            ArchiveFormat::from_path("data.tar.gz"),
            Some(ArchiveFormat::TarGz)
        );
        assert_eq!(
            ArchiveFormat::from_path("data.tgz"),
            Some(ArchiveFormat::TarGz)
        );
        assert_eq!(
            ArchiveFormat::from_path("data.zip"),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(
            ArchiveFormat::from_path("DATA.ZIP"),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(ArchiveFormat::from_path("photo.png"), None);
    }

    // -- Determinism / dedup tests ------------------------------------------

    #[test]
    fn same_secret_gets_same_replacement_across_entries() {
        let proc = make_archive_processor();
        let input = build_test_tar(&[
            ("a.txt", b"contact alice@corp.com"),
            ("b.txt", b"reach alice@corp.com"),
        ]);

        let mut output = Vec::new();
        proc.process_tar(&input[..], &mut output).unwrap();

        let mut archive = tar::Archive::new(&output[..]);
        let mut contents: Vec<String> = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let mut s = String::new();
            e.read_to_string(&mut s).unwrap();
            contents.push(s);
        }

        // Both files should have the *same* replacement for alice@corp.com.
        // Extract the replacement by removing the prefix.
        let replacement_a = contents[0].strip_prefix("contact ").unwrap();
        let replacement_b = contents[1].strip_prefix("reach ").unwrap();
        assert_eq!(
            replacement_a, replacement_b,
            "dedup should produce identical replacements"
        );
        assert!(!replacement_a.contains("alice@corp.com"));
    }

    // -- Auto-dispatch test -------------------------------------------------

    #[test]
    fn process_auto_dispatch_tar() {
        let proc = make_archive_processor();
        let tar_data = build_test_tar(&[("f.txt", b"SUPERSECRET")]);

        let reader = Cursor::new(tar_data);
        let writer = Cursor::new(Vec::new());
        let stats = proc.process(reader, writer, ArchiveFormat::Tar).unwrap();

        assert_eq!(stats.files_processed, 1);
    }

    #[test]
    fn process_auto_dispatch_zip() {
        let proc = make_archive_processor();
        let zip_data = build_test_zip(&[("f.txt", b"SUPERSECRET")]);

        let reader = Cursor::new(zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc
            .process(reader, &mut writer, ArchiveFormat::Zip)
            .unwrap();

        assert_eq!(stats.files_processed, 1);
    }

    // -- Empty archive tests ------------------------------------------------

    #[test]
    fn tar_empty_archive() {
        let proc = make_archive_processor();
        let tar_data = build_test_tar(&[]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&tar_data[..], &mut output).unwrap();

        assert_eq!(stats.files_processed, 0);
        assert_eq!(stats.entries_skipped, 0);
    }

    #[test]
    fn zip_empty_archive() {
        let proc = make_archive_processor();
        let zip_data = build_test_zip(&[]);

        let reader = Cursor::new(zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();

        assert_eq!(stats.files_processed, 0);
    }

    // sanitize_zip_entry_name

    #[test]
    fn zip_entry_name_clean_passthrough() {
        assert_eq!(sanitize_zip_entry_name("logs/app.log"), "logs/app.log");
        assert_eq!(sanitize_zip_entry_name("config.yaml"), "config.yaml");
        assert_eq!(sanitize_zip_entry_name("a/b/c.txt"), "a/b/c.txt");
    }

    #[test]
    fn zip_entry_name_strips_leading_slash() {
        assert_eq!(sanitize_zip_entry_name("/etc/passwd"), "etc/passwd");
        assert_eq!(sanitize_zip_entry_name("///etc/passwd"), "etc/passwd");
    }

    #[test]
    fn zip_entry_name_strips_dotdot() {
        assert_eq!(sanitize_zip_entry_name("../etc/passwd"), "etc/passwd");
        assert_eq!(
            sanitize_zip_entry_name("a/../../etc/passwd"),
            "a/etc/passwd"
        );
        assert_eq!(
            sanitize_zip_entry_name("../../root/.ssh/id_rsa"),
            "root/.ssh/id_rsa"
        );
    }

    #[test]
    fn zip_entry_name_strips_leading_dot_slash() {
        assert_eq!(sanitize_zip_entry_name("./config.yaml"), "config.yaml");
        assert_eq!(sanitize_zip_entry_name("././config.yaml"), "config.yaml");
    }

    #[test]
    fn zip_entry_name_backslash_normalised() {
        assert_eq!(sanitize_zip_entry_name("a\\b\\c.txt"), "a/b/c.txt");
        assert_eq!(sanitize_zip_entry_name("..\\etc\\passwd"), "etc/passwd");
    }

    #[test]
    fn zip_entry_name_empty_result_replaced() {
        assert_eq!(sanitize_zip_entry_name("../.."), "_");
        assert_eq!(sanitize_zip_entry_name(""), "_");
        assert_eq!(sanitize_zip_entry_name("/"), "_");
    }

    #[test]
    fn zip_entry_name_absolute_dotdot_combo() {
        assert_eq!(sanitize_zip_entry_name("/../etc/passwd"), "etc/passwd");
    }

    // -- ArchiveFilter tests ------------------------------------------------

    #[test]
    fn filter_empty_passes_everything() {
        let f = ArchiveFilter::new(vec![], vec![]).unwrap();
        assert!(f.is_empty());
        assert!(f.passes("config/app.yaml"));
        assert!(f.passes("logs/server.log"));
    }

    #[test]
    fn filter_only_glob_includes_match() {
        let f = ArchiveFilter::new(vec!["**/*.json".into()], vec![]).unwrap();
        assert!(!f.is_empty());
        assert!(f.passes("config/settings.json"));
        assert!(f.passes("deep/nested/file.json"));
        assert!(!f.passes("config/settings.yaml"));
    }

    #[test]
    fn filter_only_dir_prefix_includes_subtree() {
        let f = ArchiveFilter::new(vec!["config/".into()], vec![]).unwrap();
        assert!(f.passes("config/app.yaml"));
        assert!(f.passes("config/nested/db.yaml"));
        assert!(!f.passes("logs/server.log"));
    }

    #[test]
    fn filter_dir_prefix_exact_match() {
        let f = ArchiveFilter::new(vec!["config/".into()], vec![]).unwrap();
        // Exact prefix without trailing separator should also match.
        assert!(f.passes("config"));
    }

    #[test]
    fn filter_exclude_removes_match() {
        let f = ArchiveFilter::new(vec![], vec!["**/*.log".into()]).unwrap();
        assert!(!f.passes("logs/server.log"));
        assert!(f.passes("config/app.yaml"));
    }

    #[test]
    fn filter_only_and_exclude_combined() {
        let f =
            ArchiveFilter::new(vec!["config/".into()], vec!["config/secrets.yaml".into()]).unwrap();
        assert!(f.passes("config/app.yaml"));
        assert!(!f.passes("config/secrets.yaml"));
        assert!(!f.passes("logs/server.log"));
    }

    #[test]
    fn filter_invalid_glob_returns_error() {
        assert!(ArchiveFilter::new(vec!["[invalid".into()], vec![]).is_err());
        assert!(ArchiveFilter::new(vec![], vec!["[bad".into()]).is_err());
    }

    // -- ArchiveProcessor builder methods -----------------------------------

    #[test]
    fn builder_with_max_depth_clamps_at_max() {
        let proc = make_archive_processor().with_max_depth(999);
        assert_eq!(proc.max_depth, MAX_ARCHIVE_DEPTH);
    }

    #[test]
    fn builder_with_max_depth_sets_value() {
        let proc = make_archive_processor().with_max_depth(2);
        assert_eq!(proc.max_depth, 2);
    }

    #[test]
    fn builder_with_parallel_threshold_sets_value() {
        let proc = make_archive_processor().with_parallel_threshold(usize::MAX);
        assert_eq!(proc.parallel_threshold, usize::MAX);
    }

    #[test]
    fn builder_with_force_text_enables_flag() {
        let proc = make_archive_processor().with_force_text(true);
        assert!(proc.force_text);
    }

    #[test]
    fn builder_with_filter_applied_to_zip() {
        let proc = make_archive_processor()
            .with_filter(ArchiveFilter::new(vec!["**/*.json".into()], vec![]).unwrap());

        let zip_data = build_test_zip(&[
            ("config.json", br#"{"email":"alice@corp.com"}"#),
            ("notes.txt", b"alice@corp.com"),
        ]);

        let reader = Cursor::new(zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();

        // notes.txt is excluded by the filter — only config.json processed.
        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.entries_filtered, 1);
    }

    #[test]
    fn builder_with_filter_applied_to_tar() {
        let proc = make_archive_processor()
            .with_filter(ArchiveFilter::new(vec!["**/*.json".into()], vec![]).unwrap());

        let tar_data = build_test_tar(&[
            ("config.json", br#"{"email":"alice@corp.com"}"#),
            ("notes.txt", b"alice@corp.com"),
        ]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&tar_data[..], &mut output).unwrap();

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.entries_filtered, 1);
    }

    // -- Parallel path tests ------------------------------------------------

    #[test]
    fn parallel_tar_sanitizes_all_entries() {
        // parallel_threshold(0) forces parallel execution regardless of entry count.
        let proc = make_archive_processor().with_parallel_threshold(0);
        let tar_data = build_test_tar(&[
            ("a.txt", b"alice@corp.com"),
            ("b.txt", b"bob@corp.com"),
            ("c.txt", b"carol@corp.com"),
            ("d.txt", b"dave@corp.com"),
        ]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&tar_data[..], &mut output).unwrap();

        assert_eq!(stats.files_processed, 4);

        // Verify originals are gone (domain is preserved by email strategy, full addresses must not appear).
        let originals = [
            "alice@corp.com",
            "bob@corp.com",
            "carol@corp.com",
            "dave@corp.com",
        ];
        let mut archive = tar::Archive::new(&output[..]);
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let mut content = String::new();
            e.read_to_string(&mut content).unwrap();
            for orig in &originals {
                assert!(
                    !content.contains(orig),
                    "original secret leaked in {:?}",
                    e.path()
                );
            }
        }
    }

    #[test]
    fn parallel_tar_preserves_entry_order() {
        let proc = make_archive_processor().with_parallel_threshold(0);
        let tar_data = build_test_tar(&[
            ("first.txt", b"alice@corp.com"),
            ("second.txt", b"hello"),
            ("third.txt", b"bob@corp.com"),
        ]);

        let mut output = Vec::new();
        proc.process_tar(&tar_data[..], &mut output).unwrap();

        let mut archive = tar::Archive::new(&output[..]);
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
            .collect();

        assert_eq!(names, vec!["first.txt", "second.txt", "third.txt"]);
    }

    #[test]
    fn parallel_zip_sanitizes_all_entries() {
        let proc = make_archive_processor().with_parallel_threshold(0);
        let zip_data = build_test_zip(&[
            ("a.txt", b"alice@corp.com"),
            ("b.txt", b"bob@corp.com"),
            ("c.txt", b"carol@corp.com"),
            ("d.txt", b"dave@corp.com"),
        ]);

        let reader = Cursor::new(zip_data);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();

        assert_eq!(stats.files_processed, 4);

        let originals = [
            "alice@corp.com",
            "bob@corp.com",
            "carol@corp.com",
            "dave@corp.com",
        ];
        let out_data = writer.into_inner();
        let mut zip_out = zip::ZipArchive::new(Cursor::new(out_data)).unwrap();
        for i in 0..zip_out.len() {
            let mut entry = zip_out.by_index(i).unwrap();
            let mut content = String::new();
            entry.read_to_string(&mut content).unwrap();
            for orig in &originals {
                assert!(
                    !content.contains(orig),
                    "original secret leaked in entry {i}"
                );
            }
        }
    }

    #[test]
    fn parallel_tar_mixed_structured_and_scanner() {
        let proc = make_archive_processor().with_parallel_threshold(0);
        let tar_data = build_test_tar(&[
            ("config.json", br#"{"email":"alice@corp.com","port":5432}"#),
            ("notes.txt", b"contact bob@corp.com for help"),
            ("data.json", br#"{"email":"carol@corp.com"}"#),
            ("readme.txt", b"dave@corp.com is the owner"),
        ]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&tar_data[..], &mut output).unwrap();

        assert_eq!(stats.files_processed, 4);
        assert_eq!(stats.structured_hits, 2); // two JSON files
        assert_eq!(stats.scanner_fallback, 2); // two plain text files

        let originals = [
            "alice@corp.com",
            "bob@corp.com",
            "carol@corp.com",
            "dave@corp.com",
        ];
        let mut archive = tar::Archive::new(&output[..]);
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let mut content = String::new();
            e.read_to_string(&mut content).unwrap();
            for orig in &originals {
                assert!(!content.contains(orig), "original secret leaked");
            }
        }
    }

    // -- Nested archive tests -----------------------------------------------

    #[test]
    fn tar_in_tar_secrets_sanitized() {
        // Build inner tar with a secret.
        let inner_tar = build_test_tar(&[("inner.txt", b"alice@corp.com")]);

        // Embed the inner tar as an entry in the outer tar.
        let outer_tar = build_test_tar(&[("nested.tar", &inner_tar)]);

        let proc = make_archive_processor();
        let mut output = Vec::new();
        let stats = proc.process_tar(&outer_tar[..], &mut output).unwrap();

        assert_eq!(stats.nested_archives, 1);

        // Unpack the outer tar and read the inner tar's content.
        let mut outer = tar::Archive::new(&output[..]);
        for entry in outer.entries().unwrap() {
            let mut e = entry.unwrap();
            let mut inner_bytes = Vec::new();
            e.read_to_end(&mut inner_bytes).unwrap();
            let mut inner = tar::Archive::new(&inner_bytes[..]);
            for inner_entry in inner.entries().unwrap() {
                let mut ie = inner_entry.unwrap();
                let mut content = String::new();
                ie.read_to_string(&mut content).unwrap();
                assert!(
                    !content.contains("alice@corp.com"),
                    "secret survived nested tar"
                );
            }
        }
    }

    #[test]
    fn zip_in_tar_secrets_sanitized() {
        let inner_zip = build_test_zip(&[("inner.txt", b"SUPERSECRET")]);
        let outer_tar = build_test_tar(&[("nested.zip", &inner_zip)]);

        let proc = make_archive_processor();
        let mut output = Vec::new();
        let stats = proc.process_tar(&outer_tar[..], &mut output).unwrap();

        assert_eq!(stats.nested_archives, 1);

        let mut outer = tar::Archive::new(&output[..]);
        for entry in outer.entries().unwrap() {
            let mut e = entry.unwrap();
            let mut zip_bytes = Vec::new();
            e.read_to_end(&mut zip_bytes).unwrap();
            let mut zip_out = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
            for i in 0..zip_out.len() {
                let mut ze = zip_out.by_index(i).unwrap();
                let mut content = String::new();
                ze.read_to_string(&mut content).unwrap();
                assert!(
                    !content.contains("SUPERSECRET"),
                    "secret survived zip-in-tar"
                );
            }
        }
    }

    #[test]
    fn zip_in_zip_secrets_sanitized() {
        let inner_zip = build_test_zip(&[("secret.txt", b"alice@corp.com")]);
        let outer_zip = build_test_zip(&[("nested.zip", &inner_zip)]);

        let proc = make_archive_processor();
        let reader = Cursor::new(outer_zip);
        let mut writer = Cursor::new(Vec::new());
        let stats = proc.process_zip(reader, &mut writer).unwrap();

        assert_eq!(stats.nested_archives, 1);

        let out_bytes = writer.into_inner();
        let mut outer = zip::ZipArchive::new(Cursor::new(out_bytes)).unwrap();
        let mut inner_bytes = Vec::new();
        outer
            .by_index(0)
            .unwrap()
            .read_to_end(&mut inner_bytes)
            .unwrap();
        let mut inner = zip::ZipArchive::new(Cursor::new(inner_bytes)).unwrap();
        let mut content = String::new();
        inner
            .by_index(0)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(
            !content.contains("alice@corp.com"),
            "secret survived zip-in-zip"
        );
    }

    #[test]
    fn nested_archive_depth_limit_returns_error() {
        // Build an archive nested max_depth + 1 levels deep.
        // Default max_depth is DEFAULT_ARCHIVE_DEPTH (5); use a proc with depth=1.
        let proc = make_archive_processor().with_max_depth(1);

        let innermost = build_test_tar(&[("file.txt", b"secret")]);
        let middle = build_test_tar(&[("inner.tar", &innermost)]);
        let outer = build_test_tar(&[("middle.tar", &middle)]);

        let mut output = Vec::new();
        let err = proc.process_tar(&outer[..], &mut output).unwrap_err();
        assert!(matches!(err, SanitizeError::RecursionDepthExceeded(_)));
    }

    #[test]
    fn force_text_skips_structured_processor() {
        let proc = make_archive_processor().with_force_text(true);
        let tar_data = build_test_tar(&[("config.json", br#"{"email":"alice@corp.com"}"#)]);

        let mut output = Vec::new();
        let stats = proc.process_tar(&tar_data[..], &mut output).unwrap();

        // With force_text, JSON is scanned as plain text — no structured hit.
        assert_eq!(stats.scanner_fallback, 1);
        assert_eq!(stats.structured_hits, 0);
    }
}
