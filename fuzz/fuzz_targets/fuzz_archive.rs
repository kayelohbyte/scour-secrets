//! Fuzz target: archive processor (tar format).
//!
//! Feeds arbitrary bytes through `ArchiveProcessor::process_tar` to
//! exercise tar parsing and ensure the archive processor never panics
//! on malformed or adversarial archive data.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scour_secrets::category::Category;
use scour_secrets::generator::HmacGenerator;
use scour_secrets::processor::archive::ArchiveProcessor;
use scour_secrets::processor::{FieldRule, FileTypeProfile, ProcessorRegistry};
use scour_secrets::scanner::{ScanConfig, ScanPattern, StreamScanner};
use scour_secrets::store::MappingStore;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    // Cap size to prevent timeouts.
    if data.len() > 512 * 1024 {
        return;
    }

    let gen = Arc::new(HmacGenerator::new([0xEFu8; 32]));
    let store = Arc::new(MappingStore::new(gen, Some(5000)));

    // Minimal pattern for scanning inside archive entries.
    let pattern = match ScanPattern::from_regex(
        r"secret|password|token",
        Category::Custom("password".into()),
        "fuzz-archive",
    ) {
        Ok(p) => p,
        Err(_) => return,
    };

    let config = ScanConfig::new(64, 16);
    let scanner = match StreamScanner::new(vec![pattern], store.clone(), config) {
        Ok(s) => s,
        Err(_) => return,
    };

    let profiles = vec![FileTypeProfile::new(
        "json",
        vec![FieldRule::new("*.password").with_category(Category::Custom("password".into()))],
    )
    .with_extension("json")];

    let registry = Arc::new(ProcessorRegistry::with_builtins());
    let scanner = Arc::new(scanner);

    let archive_processor = ArchiveProcessor::new(registry, scanner, store, profiles);

    // Try tar format — should not panic on arbitrary bytes.
    let mut output = Vec::new();
    let _ = archive_processor.process_tar(&data[..], &mut output);

    // Try tar.gz format.
    let mut output2 = Vec::new();
    let _ = archive_processor.process_tar_gz(&data[..], &mut output2);
});
