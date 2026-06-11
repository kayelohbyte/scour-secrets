//! Fuzz target: INI structured processor.
//!
//! `IniProcessor` uses a hand-rolled parser (split on newlines, detect
//! `[section]` headers, split on `=`). Feeds arbitrary bytes to ensure
//! it never panics on malformed input — unterminated sections, duplicate
//! keys, missing `=`, binary content, etc.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_sanitize::category::Category;
use rust_sanitize::generator::HmacGenerator;
use rust_sanitize::processor::ini_proc::IniProcessor;
use rust_sanitize::processor::{FieldRule, FileTypeProfile, Processor};
use rust_sanitize::store::MappingStore;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let gen = Arc::new(HmacGenerator::new([0x12u8; 32]));
    let store = MappingStore::new(gen, Some(5000));

    let profile = FileTypeProfile::new(
        "ini",
        vec![
            FieldRule::new("*.password").with_category(Category::Custom("password".into())),
            FieldRule::new("*.secret").with_category(Category::Custom("secret".into())),
            FieldRule::new("*").with_category(Category::Custom("generic".into())),
        ],
    )
    .with_extension("ini")
    .with_extension("cfg");

    let processor = IniProcessor;
    if processor.can_handle(data, &profile) {
        let _ = processor.process(data, &profile, &store);
    }
});
