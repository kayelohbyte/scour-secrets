//! Basic usage of rust-sanitize as a library.
//!
//! Run with: `cargo run --example basic`

use rust_sanitize::category::Category;
use rust_sanitize::generator::HmacGenerator;
use rust_sanitize::store::MappingStore;
use std::sync::Arc;

fn main() {
    // Create a deterministic generator with a fixed seed.
    let generator = Arc::new(HmacGenerator::new([42u8; 32]));

    // Create the replacement store (with a 1 million entry capacity limit).
    let store = MappingStore::new(generator, Some(1_000_000));

    // Sanitize values across different categories.
    let pairs = [
        (Category::Email, "alice@corp.com"),
        (Category::Email, "bob@corp.com"),
        (Category::IpV4, "192.168.1.42"),
        (Category::Name, "Alice Johnson"),
    ];

    for (category, original) in &pairs {
        let sanitized = store
            .get_or_insert(category, original)
            .expect("replacement should succeed");
        println!("{category:>8} | {original:<20} → {sanitized}");
    }

    // Demonstrate per-run consistency: same input → same output.
    let first = store
        .get_or_insert(&Category::Email, "alice@corp.com")
        .unwrap();
    let second = store
        .get_or_insert(&Category::Email, "alice@corp.com")
        .unwrap();
    assert_eq!(first, second);
    println!("\nConsistency check passed: repeated lookups return the same value.");
}
