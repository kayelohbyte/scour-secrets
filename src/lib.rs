//! # rust-sanitize
//!
//! Deterministic, one-way data sanitization engine.
//!
//! This crate provides the core replacement infrastructure for replacing
//! sensitive values with category-aware, deterministic substitutes.
//! Replacements are **one-way only** — there is no key file, mapping
//! table, or restore mode. It is the foundation layer consumed by
//! higher-level streaming and CLI components.
//!
//! ## Key Components
//!
//! - [`category::Category`] — Classification of sensitive values (email,
//!   IP, name, etc.) that determines replacement format.
//! - [`generator::ReplacementGenerator`] — Trait abstracting replacement
//!   strategy (HMAC-deterministic or CSPRNG-random).
//! - [`strategy::Strategy`] — Pluggable replacement strategies that can
//!   be called **directly** without any mapping table.
//! - [`store::MappingStore`] — Optional thread-safe per-run dedup cache
//!   ensuring the same input always maps to the same output within a run.
//! - [`scanner::StreamScanner`] — Streaming regex scanner with chunk +
//!   overlap for bounded-memory processing.
//!
//! ## Concurrency Model
//!
//! The `MappingStore` uses `DashMap` (shard-level locking) for the forward
//! dedup cache. All types are `Send + Sync`.
//!
//! ## Stability
//!
//! As of 0.8.0 the public API is considered stable and follows Semantic Versioning.
//! Breaking changes require a major version bump. The core guarantees —
//! one-way replacement, deterministic mode, and length preservation — are
//! stable across all 1.x releases. Processor heuristics, default limit
//! values, and report schema may change in minor releases (additive only).
//!
//! ## Example: Store-Level Replacement
//!
//! ```rust
//! use rust_sanitize::category::Category;
//! use rust_sanitize::generator::HmacGenerator;
//! use rust_sanitize::store::MappingStore;
//! use std::sync::Arc;
//!
//! // Create a deterministic generator with a fixed seed.
//! let generator = Arc::new(HmacGenerator::new([42u8; 32]));
//!
//! // Create the replacement store (optional capacity limit).
//! let store = MappingStore::new(generator, None);
//!
//! // Sanitize a value (one-way).
//! let sanitized = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
//! assert!(sanitized.contains("@corp.com"));
//! assert_eq!(sanitized.len(), "alice@corp.com".len());
//!
//! // Same input → same output (per-run consistency).
//! let again = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
//! assert_eq!(sanitized, again);
//! ```
//!
//! ## Example: Streaming Scanner
//!
//! ```rust
//! use rust_sanitize::category::Category;
//! use rust_sanitize::generator::HmacGenerator;
//! use rust_sanitize::scanner::{ScanConfig, ScanPattern, StreamScanner};
//! use rust_sanitize::store::MappingStore;
//! use std::sync::Arc;
//!
//! // Build patterns.
//! let patterns = vec![
//!     ScanPattern::from_regex(r"alice@corp\.com", Category::Email, "alice_email").unwrap(),
//! ];
//!
//! // Store with deterministic generator.
//! let generator = Arc::new(HmacGenerator::new([42u8; 32]));
//! let store = Arc::new(MappingStore::new(generator, Some(1_000_000)));
//!
//! // Scanner with default chunk config.
//! let config = ScanConfig::new(1_048_576, 4096);
//! let scanner = StreamScanner::new(patterns, store, config).unwrap();
//!
//! // Scan bytes in-memory.
//! let input = b"Contact alice@corp.com for details.";
//! let (output, stats) = scanner.scan_bytes(input).unwrap();
//!
//! assert_eq!(stats.replacements_applied, 1);
//! assert_eq!(output.len(), input.len());
//! ```
//!
//! ## Example: Log Context Extraction
//!
//! After sanitizing, scan the output for error/warning keywords and capture
//! surrounding lines for LLM-friendly triage:
//!
//! ```rust
//! use rust_sanitize::log_context::{extract_context, LogContextConfig};
//!
//! let sanitized = "INFO  request received\n\
//!                  ERROR disk full on /dev/sda1\n\
//!                  INFO  retrying mount\n\
//!                  WARN  filesystem degraded\n\
//!                  INFO  recovery complete";
//!
//! let config = LogContextConfig::new().with_context_lines(1);
//! let result = extract_context(sanitized, &config);
//!
//! // Two keyword hits: "error" and "warn".
//! assert_eq!(result.match_count, 2);
//!
//! // First match: ERROR line with one line of context on each side.
//! assert_eq!(result.matches[0].keyword, "error");
//! assert_eq!(result.matches[0].before, vec!["INFO  request received"]);
//! assert_eq!(result.matches[0].after,  vec!["INFO  retrying mount"]);
//! ```

// Crate-level lint configuration.
#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
// Allow specific pedantic lints that are too noisy for this crate.
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_panics_doc,
    clippy::must_use_candidate, // We add #[must_use] manually on key APIs.
    clippy::uninlined_format_args,
    clippy::redundant_closure_for_method_calls,
    clippy::doc_markdown,
    clippy::similar_names
)]

pub mod allowlist;
pub mod atomic;
pub mod category;
pub mod error;
pub mod generator;
pub mod llm;
pub mod log_context;
pub mod processor;
pub mod report;
pub mod scanner;
pub mod secrets;
pub mod store;
pub mod strategy;
pub mod strip_values;

// Re-exports for convenience.
pub use atomic::{atomic_write, atomic_write_private, AtomicFileWriter};
pub use category::Category;
pub use error::{Result, SanitizeError};
pub use generator::{HmacGenerator, RandomGenerator, ReplacementGenerator};
pub use llm::{
    format_llm_prompt, format_llm_prompt_reference, resolve_llm_template, LlmEntry, LlmPathEntry,
    PROMPT_PREAMBLE, TEMPLATE_REVIEW_CONFIG, TEMPLATE_REVIEW_SECURITY, TEMPLATE_TROUBLESHOOT,
};
pub use log_context::{
    extract_context, extract_context_reader, LogContextConfig, LogContextMatch, LogContextResult,
    DEFAULT_CONTEXT_LINES, DEFAULT_KEYWORDS, DEFAULT_MAX_MATCHES,
};
pub use processor::archive::{
    ArchiveFilter, ArchiveFormat, ArchiveProcessor, ArchiveProgress, ArchiveStats, EntryCallback,
};
pub use processor::limits::DEFAULT_ARCHIVE_DEPTH;
pub use processor::{
    FieldNameSignal, FieldRule, FileTypeProfile, Processor, ProcessorRegistry,
    DEFAULT_FIELD_SIGNAL_THRESHOLD,
};
pub use report::{FileReport, ReportBuilder, ReportMetadata, SanitizeReport};
pub use scanner::{ScanConfig, ScanPattern, ScanProgress, ScanStats, StreamScanner};
pub use secrets::{
    decrypt_secrets, encrypt_secrets, load_secrets_auto, looks_encrypted, SecretEntry,
    SecretsFormat,
};
pub use store::MappingStore;
pub use strategy::{
    EntropyMode, FakeIp, HmacHash, PreserveLength, RandomString, RandomUuid, Strategy,
    StrategyGenerator,
};
pub use strip_values::strip_values_from_text;
