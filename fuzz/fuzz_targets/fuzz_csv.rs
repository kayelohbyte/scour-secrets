//! Fuzz target: CSV structured processor.
//!
//! Feeds arbitrary bytes through both `CsvProcessor::process` and the
//! span-based edit path (`process_to_edits` + `apply_edits`, via
//! `ProcessorRegistry::process_to_edits`) to ensure neither panics on
//! malformed or adversarial input — the csv-core span path computes
//! byte-accurate field spans on untrusted input (quoting, embedded newlines,
//! missing EOL), so it is the higher-risk path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scour::category::Category;
use scour::generator::HmacGenerator;
use scour::processor::csv_proc::CsvProcessor;
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
        "csv",
        vec![
            FieldRule::new("*").with_category(Category::Custom("field".into())),
            FieldRule::new("email").with_category(Category::Email),
            FieldRule::new("password").with_category(Category::Custom("password".into())),
        ],
    )
    .with_extension("csv");

    let processor = CsvProcessor;
    if processor.can_handle(data, &profile) {
        let _ = processor.process(data, &profile, &store);
    }
    // Span-based edit path (csv-core field spans → apply_edits).
    let registry = ProcessorRegistry::with_builtins();
    let _ = registry.process_to_edits(data, &profile, &store);
});
