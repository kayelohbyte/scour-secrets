//! Fuzz target: regex pattern compilation and scanning.
//!
//! Exercises `ScanPattern::from_regex` and `StreamScanner::scan_bytes`
//! with arbitrary pattern strings and input data. The scanner should
//! never panic regardless of input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scour_secrets::category::Category;
use scour_secrets::generator::HmacGenerator;
use scour_secrets::scanner::{ScanConfig, ScanPattern, StreamScanner};
use scour_secrets::store::MappingStore;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Split input: first byte determines split point for pattern vs data.
    let split = (data[0] as usize).min(data.len() - 1).max(1);
    let pattern_bytes = &data[1..split];
    let input_data = &data[split..];

    let pattern_str = match std::str::from_utf8(pattern_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Attempt to compile the pattern — should not panic.
    let pattern = match ScanPattern::from_regex(pattern_str, Category::Email, "fuzz") {
        Ok(p) => p,
        Err(_) => return, // invalid regex is expected
    };

    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, Some(1000)));
    let config = ScanConfig::new(64, 16);

    let scanner = match StreamScanner::new(vec![pattern], store, config) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Scan should not panic.
    let _ = scanner.scan_bytes(input_data);
});
