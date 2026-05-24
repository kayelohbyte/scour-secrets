//! Centralized safety limits for all structured processors.
//!
//! Keeping limits in one place makes it easy to audit, compare, and update
//! them together. Non-default values are documented with the reason they
//! differ from the standard.

// ---------------------------------------------------------------------------
// Input size caps (bytes)
// ---------------------------------------------------------------------------

/// Standard maximum input size for most structured processors (256 MiB).
/// Inputs exceeding this are rejected before parsing to prevent OOM (F-04 fix).
pub(crate) const DEFAULT_INPUT_SIZE: usize = 256 * 1024 * 1024;

/// Maximum input size for YAML (64 MiB).
/// Smaller than the default because serde_yaml fully expands aliases/anchors
/// during deserialization, so a small file can balloon into gigabytes of
/// in-memory nodes (alias/anchor bomb, F-06 fix).
pub(crate) const YAML_INPUT_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Recursion / nesting depth caps
// ---------------------------------------------------------------------------

/// Standard maximum recursion depth for tree-walking processors (JSON, YAML, TOML).
/// Prevents stack overflow from deeply nested or malicious inputs (R-4 fix).
pub(crate) const DEFAULT_DEPTH: usize = 128;

/// Maximum element nesting depth for the XML processor.
/// Higher than the default because deeply nested XML documents are common in
/// practice (e.g. Maven POMs, Android manifests) and XML is iterative rather
/// than recursive in this processor (R-5 fix).
pub(crate) const XML_DEPTH: usize = 256;

// ---------------------------------------------------------------------------
// YAML-specific limits
// ---------------------------------------------------------------------------

/// Maximum number of distinct YAML nodes after alias expansion.
/// serde_yaml_ng expands aliases into full value copies during deserialization;
/// this caps total node count to prevent exponential growth (F-06 fix).
pub(crate) const YAML_NODE_COUNT: usize = 10_000_000;

// ---------------------------------------------------------------------------
// Archive limits
// ---------------------------------------------------------------------------

/// Maximum size (bytes) for a single archive entry loaded into memory for
/// structured processing. Larger entries are streamed through the scanner
/// instead (M-3 fix).
pub(crate) const STRUCTURED_ENTRY_SIZE: u64 = 256 * 1024 * 1024;

/// Maximum total uncompressed data size (bytes) across all zip entries before
/// the parallel processing path is disabled. Above this threshold the zip
/// processor falls back to sequential entry processing to avoid holding the
/// entire archive in memory at once.
pub(crate) const PARALLEL_ZIP_DATA_SIZE: u64 = 256 * 1024 * 1024;

/// Maximum total buffered data size (bytes) across all tar entries before
/// parallel processing is disabled.
///
/// Unlike zip, tar has no central directory so entry sizes cannot be known
/// before reading. Entries are buffered speculatively; if the running total
/// exceeds this cap the parallel path is abandoned and remaining entries are
/// processed sequentially from the stream.
pub(crate) const PARALLEL_TAR_DATA_SIZE: u64 = 256 * 1024 * 1024;

/// Default maximum nesting depth for recursive archive processing.
///
/// Depth 0 is the top-level archive. Nested archives at depths 1 through
/// `DEFAULT_ARCHIVE_DEPTH` are recursively extracted and sanitized. Exceeding
/// this limit returns [`SanitizeError::RecursionDepthExceeded`](crate::error::SanitizeError::RecursionDepthExceeded).
pub const DEFAULT_ARCHIVE_DEPTH: u32 = 3;

/// Absolute maximum allowed value for `--max-archive-depth`.
/// Each nesting level can buffer up to [`STRUCTURED_ENTRY_SIZE`] bytes, so
/// capping at 10 bounds peak memory to ~2.5 GiB in the worst case.
pub(crate) const MAX_ARCHIVE_DEPTH: u32 = 10;

/// Minimum number of file entries in an archive before parallel entry
/// processing is enabled. Below this threshold rayon task overhead exceeds
/// the parallelism benefit.
pub(crate) const PARALLEL_ENTRY_THRESHOLD: usize = 4;
