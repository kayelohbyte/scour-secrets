//! Fuzz target: TOML structured processor.
//!
//! Feeds arbitrary bytes through both `TomlProcessor::process` (re-serialize
//! path) and the span-based edit path (`process_to_edits` + `apply_edits`, via
//! `ProcessorRegistry::process_to_edits`) to ensure neither panics on malformed
//! or adversarial input — the toml_edit span path does byte-span slicing on
//! untrusted parser output, so it is the higher-risk path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scour::category::Category;
use scour::generator::HmacGenerator;
use scour::processor::toml_proc::TomlProcessor;
use scour::processor::{FieldRule, FileTypeProfile, Processor, ProcessorRegistry};
use scour::store::MappingStore;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    // Limit input size to avoid timeouts on huge blobs.
    if data.len() > 256 * 1024 {
        return;
    }

    let gen = Arc::new(HmacGenerator::new([0xABu8; 32]));
    let store = MappingStore::new(gen, Some(5000));

    let profile = FileTypeProfile::new(
        "toml",
        vec![
            FieldRule::new("*").with_category(Category::Custom("field".into())),
            FieldRule::new("*.password").with_category(Category::Custom("password".into())),
            FieldRule::new("*.email").with_category(Category::Email),
        ],
    )
    .with_extension("toml");

    let processor = TomlProcessor;
    if processor.can_handle(data, &profile) {
        let _ = processor.process(data, &profile, &store);
    }
    // Span-based edit path (toml_edit parse → span edits → apply_edits).
    let registry = ProcessorRegistry::with_builtins();
    let _ = registry.process_to_edits(data, &profile, &store);
});
