//! Fuzz target: YAML structured processor.
//!
//! Feeds arbitrary bytes through `YamlProcessor::process` to exercise
//! the YAML-bomb mitigations (size cap, node-count cap, depth limit).
//! The processor should never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_sanitize::category::Category;
use rust_sanitize::generator::HmacGenerator;
use rust_sanitize::processor::yaml_proc::YamlProcessor;
use rust_sanitize::processor::{FieldRule, FileTypeProfile, Processor, ProcessorRegistry};
use rust_sanitize::store::MappingStore;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    // Hard-cap to prevent corpus growth from burning resources.
    if data.len() > 256 * 1024 {
        return;
    }

    let gen = Arc::new(HmacGenerator::new([0xCDu8; 32]));
    let store = MappingStore::new(gen, Some(5000));

    let profile = FileTypeProfile::new(
        "yaml",
        vec![
            FieldRule::new("*").with_category(Category::Custom("field".into())),
            FieldRule::new("*.secret").with_category(Category::Custom("password".into())),
            FieldRule::new("*.api_key").with_category(Category::Custom("api_key".into())),
        ],
    )
    .with_extension("yml")
    .with_extension("yaml");

    let processor = YamlProcessor;
    if processor.can_handle(data, &profile) {
        let _ = processor.process(data, &profile, &store);
    }
    // Span-based edit path (saphyr event walk → span edits → apply_edits).
    let registry = ProcessorRegistry::with_builtins();
    let _ = registry.process_to_edits(data, &profile, &store);
});
