//! Fuzz target: XML structured processor.
//!
//! Feeds arbitrary bytes through `XmlProcessor::process` to ensure it never
//! panics on malformed or adversarial XML input (deeply nested elements,
//! crafted entity references, oversized attribute values, etc.).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_sanitize::category::Category;
use rust_sanitize::generator::HmacGenerator;
use rust_sanitize::processor::xml_proc::XmlProcessor;
use rust_sanitize::processor::{FieldRule, FileTypeProfile, Processor};
use rust_sanitize::store::MappingStore;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let gen = Arc::new(HmacGenerator::new([0xEFu8; 32]));
    let store = MappingStore::new(gen, Some(5000));

    let profile = FileTypeProfile::new(
        "xml",
        vec![
            FieldRule::new("*.password").with_category(Category::Custom("password".into())),
            FieldRule::new("*.email").with_category(Category::Email),
            FieldRule::new("*.token").with_category(Category::Custom("api_key".into())),
        ],
    )
    .with_extension("xml");

    let processor = XmlProcessor;
    if processor.can_handle(data, &profile) {
        let _ = processor.process(data, &profile, &store);
    }
});
