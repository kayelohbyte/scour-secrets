//! Property-based tests for the sanitization engine.
//!
//! These tests use `proptest` to verify invariants that must hold for
//! arbitrary inputs, not just hand-crafted examples.

use proptest::prelude::*;
use rust_sanitize::category::Category;
use rust_sanitize::generator::{HmacGenerator, ReplacementGenerator};
use rust_sanitize::scanner::{ScanConfig, ScanPattern, StreamScanner};
use rust_sanitize::store::MappingStore;
use std::sync::Arc;

/// Arbitrary `Category` generator for proptest.
fn arb_category() -> impl Strategy<Value = Category> {
    prop_oneof![
        Just(Category::Email),
        Just(Category::Name),
        Just(Category::Phone),
        Just(Category::IpV4),
        Just(Category::IpV6),
        Just(Category::CreditCard),
        Just(Category::Ssn),
        Just(Category::Hostname),
        Just(Category::MacAddress),
        Just(Category::ContainerId),
        Just(Category::Uuid),
        Just(Category::Jwt),
        Just(Category::AuthToken),
        Just(Category::FilePath),
        Just(Category::WindowsSid),
        Just(Category::Url),
        Just(Category::AwsArn),
        Just(Category::AzureResourceId),
        "[a-z_]{1,16}".prop_map(|s| Category::Custom(s.into())),
    ]
}

/// Arbitrary 32-byte seed.
fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

// ─── Determinism ───────────────────────────────────────────────────────────

proptest! {
    /// For any seed, category, and input, the HMAC generator is deterministic.
    #[test]
    fn generator_determinism(
        seed in arb_seed(),
        cat in arb_category(),
        input in ".*",  // any UTF-8 string
    ) {
        let gen = HmacGenerator::new(seed);
        let a = gen.generate(&cat, &input);
        let b = gen.generate(&cat, &input);
        prop_assert_eq!(a, b, "HMAC generator must be deterministic");
    }

    /// For any seed, the store returns the same output for repeated inserts.
    #[test]
    fn store_idempotent(
        seed in arb_seed(),
        cat in arb_category(),
        input in ".{1,200}",
    ) {
        let gen = Arc::new(HmacGenerator::new(seed));
        let store = MappingStore::new(gen, None);
        let s1 = store.get_or_insert(&cat, &input).unwrap();
        let s2 = store.get_or_insert(&cat, &input).unwrap();
        prop_assert_eq!(s1, s2, "repeated insert must be idempotent");
        prop_assert_eq!(store.len(), 1);
    }
}

// ─── One-way replacement (no reverse) ─────────────────────────────────────

proptest! {
    /// One-way: sanitized output is always non-empty.
    #[test]
    fn one_way_replacement_non_empty(
        seed in arb_seed(),
        cat in arb_category(),
        input in ".{1,200}",
    ) {
        let gen = Arc::new(HmacGenerator::new(seed));
        let store = MappingStore::new(gen, None);
        let sanitized = store.get_or_insert(&cat, &input).unwrap();
        prop_assert!(!sanitized.is_empty(), "sanitized output must not be empty");
    }
}

// ─── Collision freedom ─────────────────────────────────────────────────────

proptest! {
    /// Different inputs within the same category must map to different outputs.
    /// Note: the Name category uses a small lookup table (32×32 = 1024 possible
    /// outputs), so collisions are expected for arbitrary inputs.  We exclude
    /// Name here to avoid false-positive failures (F-01 fix).
    #[test]
    fn no_intra_category_collision(
        seed in arb_seed(),
        cat in prop_oneof![
            Just(Category::Email),
            Just(Category::Phone),
            Just(Category::IpV4),
            Just(Category::IpV6),
            Just(Category::CreditCard),
            Just(Category::Ssn),
            Just(Category::Hostname),
            Just(Category::MacAddress),
            Just(Category::ContainerId),
            Just(Category::Uuid),
            Just(Category::Jwt),
            Just(Category::AuthToken),
            Just(Category::FilePath),
            Just(Category::WindowsSid),
            Just(Category::Url),
            Just(Category::AwsArn),
            Just(Category::AzureResourceId),
            "[a-z_]{1,16}".prop_map(|s| Category::Custom(s.into())),
        ],
        a in ".{1,100}",
        b in ".{1,100}",
    ) {
        prop_assume!(a != b);
        let gen = Arc::new(HmacGenerator::new(seed));
        let store = MappingStore::new(gen, None);
        let sa = store.get_or_insert(&cat, &a).unwrap();
        let sb = store.get_or_insert(&cat, &b).unwrap();
        prop_assert_ne!(sa, sb, "different inputs must not collide");
    }
}

// ─── Category domain separation ────────────────────────────────────────────

proptest! {
    /// Same input in different categories must map to different outputs.
    /// Uses inputs of length ≥ 10 to avoid trivial collisions in the
    /// reduced output space of very short length-preserving replacements.
    #[test]
    fn cross_category_separation(
        seed in arb_seed(),
        input in ".{10,100}",
    ) {
        let gen = Arc::new(HmacGenerator::new(seed));
        let store = MappingStore::new(gen, None);
        let email = store.get_or_insert(&Category::Email, &input).unwrap();
        let name  = store.get_or_insert(&Category::Name, &input).unwrap();
        let ipv4  = store.get_or_insert(&Category::IpV4, &input).unwrap();
        prop_assert_ne!(email.clone(), name.clone());
        prop_assert_ne!(email, ipv4.clone());
        prop_assert_ne!(name, ipv4);
    }
}

// ─── Concurrency invariant ─────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    /// N threads inserting the same keys must all agree on mappings.
    #[test]
    fn concurrent_agreement(
        seed in arb_seed(),
        inputs in prop::collection::vec(".{1,50}", 1..30),
    ) {
        use std::thread;

        let gen = Arc::new(HmacGenerator::new(seed));
        let store = Arc::new(MappingStore::new(gen, None));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let store = Arc::clone(&store);
                let inputs = inputs.clone();
                thread::spawn(move || {
                    inputs
                        .iter()
                        .map(|inp| {
                            store.get_or_insert(&Category::Email, inp).unwrap()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        let results: Vec<Vec<_>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All threads must have produced the same output for each input.
        for i in 0..inputs.len() {
            let expected = &results[0][i];
            for thread_result in &results[1..] {
                prop_assert_eq!(&thread_result[i], expected);
            }
        }
    }
}

// ─── Format invariants ─────────────────────────────────────────────────────

proptest! {
    /// Replacement byte-length must always equal the original byte-length
    /// for every category.
    #[test]
    fn replacement_length_preserved(
        seed in arb_seed(),
        cat in arb_category(),
        input in ".{1,200}",
    ) {
        let gen = HmacGenerator::new(seed);
        let out = gen.generate(&cat, &input);
        prop_assert_eq!(
            out.len(),
            input.len(),
            "length mismatch for {:?}: input({}) -> output({})",
            cat, input.len(), out.len(),
        );
    }

    /// Email replacements with a proper email-like input must contain '@'
    /// and preserve the domain.
    #[test]
    fn email_format_always_valid(
        seed in arb_seed(),
        user in "[a-z]{1,20}",
        domain in "[a-z]{2,10}\\.[a-z]{2,4}",
    ) {
        let input = format!("{}@{}", user, domain);
        let gen = HmacGenerator::new(seed);
        let out = gen.generate(&Category::Email, &input);
        prop_assert_eq!(out.len(), input.len());
        prop_assert!(out.contains('@'), "email must contain @");
        prop_assert!(
            out.ends_with(&format!("@{}", domain)),
            "email must preserve domain: got '{}'", out
        );
    }

    /// IPv4 replacements must preserve dot-separated structure and length.
    #[test]
    fn ipv4_format_always_valid(
        seed in arb_seed(),
        a in 1u16..256,
        b in 0u16..256,
        c in 0u16..256,
        d in 1u16..256,
    ) {
        let input = format!("{}.{}.{}.{}", a, b, c, d);
        let gen = HmacGenerator::new(seed);
        let out = gen.generate(&Category::IpV4, &input);
        prop_assert_eq!(out.len(), input.len());
        let parts: Vec<&str> = out.split('.').collect();
        prop_assert_eq!(parts.len(), 4);
        for part in &parts {
            prop_assert!(part.chars().all(|ch| ch.is_ascii_digit()),
                "each octet must be digits, got '{}'", part);
        }
    }

    /// SSN replacements must start with 000, preserve dashes, and match length.
    #[test]
    fn ssn_format_always_valid(
        seed in arb_seed(),
        area in 100u16..999,
        group in 10u16..99,
        serial in 1000u16..9999,
    ) {
        let input = format!("{:03}-{:02}-{:04}", area, group, serial);
        let gen = HmacGenerator::new(seed);
        let out = gen.generate(&Category::Ssn, &input);
        prop_assert!(out.starts_with("000-"));
        prop_assert_eq!(out.len(), 11);
    }
}

// ─── Chunk-size independence ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Scanner output must be identical regardless of chunk size.
    ///
    /// Any streaming scanner that is correct for one chunk size must be correct
    /// for all chunk sizes — the overlap/carry buffer exists specifically to
    /// guarantee this. We verify it by scanning the same input with four
    /// different chunk sizes and asserting byte-for-byte identical output.
    #[test]
    fn scanner_output_independent_of_chunk_size(
        // ASCII filler around a fixed literal secret so we have guaranteed matches
        // at known positions, including near chunk boundaries.
        prefix in "[a-zA-Z0-9 ]{0,200}",
        middle in "[a-zA-Z0-9 ]{0,200}",
        suffix in "[a-zA-Z0-9 ]{0,200}",
    ) {
        const SECRET: &str = "TOP_SECRET_LITERAL_XYZ";
        let input = format!("{prefix}{SECRET}{middle}{SECRET}{suffix}");
        let input_bytes = input.as_bytes();

        let gen = Arc::new(HmacGenerator::new([77u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let pattern = ScanPattern::from_literal(SECRET, Category::Custom("s".into()), "s").unwrap();

        // Reference output: use a large chunk so the whole input fits in one window.
        let reference = {
            let scanner = StreamScanner::new(
                vec![pattern.clone()],
                Arc::clone(&store),
                ScanConfig::new(input_bytes.len().max(16) + 16, 8),
            ).unwrap();
            let (out, _) = scanner.scan_bytes(input_bytes).unwrap();
            out
        };

        // Verify with progressively smaller chunk sizes that force the secret
        // to straddle chunk boundaries at different offsets.
        //
        // The scanner contract requires overlap_size ≥ max_pattern_length.
        // Use exactly SECRET.len() + 1 as overlap so the pattern is always
        // catchable at boundaries, and skip any chunk_size that's too small
        // to satisfy chunk_size > overlap.
        let required_overlap = SECRET.len() + 1;
        for &chunk_size in &[32usize, 64, 128, 256] {
            if required_overlap >= chunk_size {
                continue;
            }
            let overlap = required_overlap;
            let scanner = StreamScanner::new(
                vec![pattern.clone()],
                Arc::clone(&store),
                ScanConfig::new(chunk_size, overlap),
            ).unwrap();
            let (out, _) = scanner.scan_bytes(input_bytes).unwrap();
            prop_assert_eq!(
                &out, &reference,
                "chunk_size={} produced different output for input {:?}",
                chunk_size, input,
            );
        }
    }
}
