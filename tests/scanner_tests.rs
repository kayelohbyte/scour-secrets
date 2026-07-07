//! Integration tests for the streaming scanner.
//!
//! Tests cover:
//! - Large file simulation (multi-chunk / multi-MB)
//! - Chunk boundary overlap handling
//! - Multiple concurrent scans sharing a MappingStore
//! - Replacement consistency (same secret → same replacement)
//! - Regex and literal patterns
//! - Mixed pattern types
//! - Edge cases (empty input, no matches, very small chunks)

use scour_secrets::category::Category;
use scour_secrets::error::SanitizeError;
use scour_secrets::generator::HmacGenerator;
use scour_secrets::scanner::{ScanConfig, ScanPattern, StreamScanner};
use scour_secrets::store::MappingStore;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a scanner with default deterministic generator.
fn make_scanner(
    patterns: Vec<ScanPattern>,
    config: ScanConfig,
) -> (Arc<StreamScanner>, Arc<MappingStore>) {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let scanner = Arc::new(StreamScanner::new(patterns, Arc::clone(&store), config).unwrap());
    (scanner, store)
}

/// Email regex pattern.
fn email_pattern() -> ScanPattern {
    ScanPattern::from_regex(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        Category::Email,
        "email",
    )
    .unwrap()
}

/// IPv4 regex pattern.
fn ipv4_pattern() -> ScanPattern {
    ScanPattern::from_regex(
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        Category::IpV4,
        "ipv4",
    )
    .unwrap()
}

/// SSN regex pattern (XXX-XX-XXXX).
fn ssn_pattern() -> ScanPattern {
    ScanPattern::from_regex(r"\b\d{3}-\d{2}-\d{4}\b", Category::Ssn, "ssn").unwrap()
}

// ===========================================================================
// 1. Large file simulation
// ===========================================================================

#[test]
fn large_file_multi_chunk() {
    // Simulate a ~500 KiB file scanned with 4 KiB chunks.
    let config = ScanConfig::new(4096, 256);
    let (scanner, _store) = make_scanner(vec![email_pattern()], config);

    let filler = "The quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::new();
    let emails_per_block = 5;
    let blocks = 200; // ~500 KiB
    let mut expected_matches = 0;

    for block in 0..blocks {
        for _ in 0..10 {
            input.extend_from_slice(filler.as_bytes());
        }
        for i in 0..emails_per_block {
            let email = format!("user_{}_{:04}@bigcorp.example.com ", block, i);
            input.extend_from_slice(email.as_bytes());
            expected_matches += 1;
        }
    }

    let (output, stats) = scanner.scan_bytes(&input).unwrap();

    assert_eq!(
        stats.matches_found, expected_matches,
        "should find all {} emails in large input",
        expected_matches
    );
    // No original email should survive.
    let out_str = String::from_utf8_lossy(&output);
    for block in 0..blocks {
        for i in 0..emails_per_block {
            let email = format!("user_{}_{:04}@bigcorp.example.com", block, i);
            assert!(
                !out_str.contains(&email),
                "email '{}' must be replaced",
                email
            );
        }
    }
    // All replacements should use the preserved domain.
    let replacement_count = out_str.matches("@bigcorp.example.com").count();
    assert_eq!(replacement_count, expected_matches as usize);
}

#[test]
fn large_file_with_many_pattern_types() {
    let config = ScanConfig::new(2048, 128);
    let (scanner, _store) =
        make_scanner(vec![email_pattern(), ipv4_pattern(), ssn_pattern()], config);

    let mut input = String::new();
    for i in 0..100u32 {
        input.push_str(&format!(
            "Record {}: email=rec{}@corp.com ip=10.0.{}.{} ssn=123-45-{:04} | ",
            i,
            i,
            i % 256,
            (i + 1) % 256,
            i % 10000
        ));
    }

    let (output, stats) = scanner.scan_bytes(input.as_bytes()).unwrap();
    let out_str = String::from_utf8_lossy(&output);

    // Expect 100 emails + 100 IPs + some SSN matches.
    assert!(
        stats.matches_found >= 200,
        "should find at least 200 matches (emails + IPs), got {}",
        stats.matches_found
    );
    assert_eq!(*stats.pattern_counts.get("email").unwrap(), 100);
    // Verify no original emails survive.
    for i in 0..100u32 {
        let email = format!("rec{}@corp.com", i);
        assert!(!out_str.contains(&email));
    }
}

// ===========================================================================
// 2. Chunk boundary overlap
// ===========================================================================

#[test]
fn email_straddling_every_chunk_boundary() {
    // Use a tiny chunk size and place emails at positions that straddle
    // every possible boundary offset.
    let config = ScanConfig::new(32, 20);
    let (scanner, _store) = make_scanner(vec![email_pattern()], config);

    for offset in 0..30usize {
        let prefix = "X".repeat(offset);
        let input = format!("{}test@boundary.org rest", prefix);
        let (output, stats) = scanner.scan_bytes(input.as_bytes()).unwrap();
        assert_eq!(
            stats.matches_found, 1,
            "offset {}: should find 1 email",
            offset
        );
        let out_str = String::from_utf8_lossy(&output);
        assert!(
            !out_str.contains("test@boundary.org"),
            "offset {}: email must be replaced",
            offset
        );
    }
}

#[test]
fn match_exactly_at_boundary() {
    // Match ends exactly at the chunk boundary.
    let config = ScanConfig::new(40, 20);
    let (scanner, _store) = make_scanner(vec![email_pattern()], config);

    // "AAAA…" padding + email that ends at byte 40.
    let email = "ab@cd.ef"; // 8 bytes
    let padding_len = 40 - email.len();
    let mut input = "P".repeat(padding_len);
    input.push_str(email);
    input.push_str(" trailing data");

    let (output, stats) = scanner.scan_bytes(input.as_bytes()).unwrap();
    assert_eq!(stats.matches_found, 1);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains(email));
}

#[test]
fn match_starts_in_carry_region() {
    // Ensure a match whose start is in the overlap/carry region from the
    // previous chunk is found.
    let config = ScanConfig::new(24, 16);
    let (scanner, _store) = make_scanner(vec![email_pattern()], config);

    // Chunk 1: 24 bytes, carry = last 16 bytes.
    // Place email starting at byte 12 (within carry of chunk 1).
    let input = b"AAAAAAAAAAAA x@longdomain.org ZZZZZZZZ";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("x@longdomain.org"));
}

// ===========================================================================
// 3. Concurrent scans
// ===========================================================================

#[test]
fn concurrent_scans_shared_store() {
    use std::thread;

    let config = ScanConfig::new(256, 32);
    let (scanner, store) = make_scanner(vec![email_pattern()], config);

    let mut handles = vec![];
    for t in 0..8 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            let mut input = Vec::new();
            for i in 0..50 {
                let line = format!(
                    "Thread {} record {}: contact user_t{}r{}@corp.com | ",
                    t, i, t, i
                );
                input.extend_from_slice(line.as_bytes());
            }
            let (output, stats) = scanner.scan_bytes(&input).unwrap();
            assert_eq!(stats.matches_found, 50, "thread {}: expected 50 matches", t);
            (output, stats)
        }));
    }

    for h in handles {
        let (_output, stats) = h.join().unwrap();
        assert_eq!(stats.matches_found, 50);
    }

    // All unique emails across all threads should be in the store.
    // 8 threads × 50 unique emails = 400 unique entries.
    assert_eq!(store.len(), 400);
}

#[test]
fn concurrent_scans_same_secret_consistent() {
    use std::thread;

    let config = ScanConfig::new(128, 32);
    let (scanner, _store) = make_scanner(vec![email_pattern()], config);

    // All threads scan the same input containing the same email.
    let shared_input = b"Please contact shared@corp.com for help.";

    let mut handles = vec![];
    for _ in 0..8 {
        let scanner = Arc::clone(&scanner);
        let input = shared_input.to_vec();
        handles.push(thread::spawn(move || {
            let (output, _) = scanner.scan_bytes(&input).unwrap();
            output
        }));
    }

    let outputs: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads must produce identical output.
    for i in 1..outputs.len() {
        assert_eq!(
            outputs[0], outputs[i],
            "thread {} output differs from thread 0",
            i
        );
    }
}

// ===========================================================================
// 4. Replacement consistency
// ===========================================================================

#[test]
fn repeated_secret_same_replacement() {
    let config = ScanConfig::new(128, 32);
    let (scanner, _) = make_scanner(vec![email_pattern()], config);

    let input = b"A: alice@corp.com B: alice@corp.com C: alice@corp.com";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 3);

    // Extract the replacement values by splitting on "@corp.com" (preserved domain).
    let out_str = String::from_utf8_lossy(&output);
    let replacements: Vec<&str> = out_str
        .match_indices("@corp.com")
        .map(|(idx, _)| {
            // Walk back to find the start of the replacement username.
            // The replacement has the same length as "alice@corp.com" (14 chars),
            // so the username is 14 - 1 - 8 = 5 chars.
            let user_len = "alice".len(); // 5
            let prefix_start = idx - user_len;
            &out_str[prefix_start..idx + "@corp.com".len()]
        })
        .collect();

    assert_eq!(replacements.len(), 3);
    assert_eq!(replacements[0], replacements[1]);
    assert_eq!(replacements[1], replacements[2]);
}

#[test]
fn different_secrets_different_replacements() {
    let config = ScanConfig::new(256, 32);
    let (scanner, _) = make_scanner(vec![email_pattern()], config);

    let input = b"alice@corp.com bob@corp.com carol@corp.com";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 3);

    let out_str = String::from_utf8_lossy(&output);
    // Each email has the same domain "@corp.com".  The replacements
    // preserve the domain and have length-matched hex usernames.
    // Since the original emails have different lengths (alice=5, bob=3,
    // carol=5), we extract each replacement individually.
    let replacements: Vec<&str> = out_str
        .match_indices("@corp.com")
        .map(|(idx, _)| {
            // Find the preceding space or start-of-string.
            let before = &out_str[..idx];
            let start = before.rfind(' ').map_or(0, |p| p + 1);
            &out_str[start..idx + "@corp.com".len()]
        })
        .collect();

    assert_eq!(replacements.len(), 3);
    // All three should be different.
    assert_ne!(replacements[0], replacements[1]);
    assert_ne!(replacements[1], replacements[2]);
    assert_ne!(replacements[0], replacements[2]);
}

// ===========================================================================
// 5. Literal patterns
// ===========================================================================

#[test]
fn literal_with_regex_metacharacters() {
    // Ensure metacharacters in literals are escaped properly.
    let pat = ScanPattern::from_literal(
        "secret.key+foo@bar.com",
        Category::Custom("api_key".into()),
        "literal_key",
    )
    .unwrap();
    let config = ScanConfig::new(128, 32);
    let (scanner, _) = make_scanner(vec![pat], config);

    let input = b"Token: secret.key+foo@bar.com end";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    assert!(!output
        .windows(b"secret.key+foo@bar.com".len())
        .any(|w| w == b"secret.key+foo@bar.com"));
}

#[test]
fn literal_no_false_positives() {
    let pat =
        ScanPattern::from_literal("EXACT_TOKEN_123", Category::Custom("token".into()), "token")
            .unwrap();
    let config = ScanConfig::new(128, 32);
    let (scanner, _) = make_scanner(vec![pat], config);

    // "EXACT_TOKEN_12" does NOT contain the literal, but
    // "EXACT_TOKEN_1234" DOES (substring match) and so does
    // "xEXACT_TOKEN_123x". Literals match as substrings unless
    // the caller adds word-boundary anchors.
    let input = b"EXACT_TOKEN_12 EXACT_TOKEN_1234 xEXACT_TOKEN_123x";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    // "EXACT_TOKEN_12" (without the trailing '3') should survive.
    assert!(out_str.contains("EXACT_TOKEN_12 "));
}

// ===========================================================================
// 6. Edge cases
// ===========================================================================

#[test]
fn input_smaller_than_chunk() {
    let config = ScanConfig::new(1024 * 1024, 4096); // 1 MiB chunk
    let (scanner, _) = make_scanner(vec![email_pattern()], config);
    let input = b"tiny input a@b.co";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("a@b.co"));
}

#[test]
fn input_exactly_chunk_size() {
    let chunk_size = 64;
    let config = ScanConfig::new(chunk_size, 16);
    let (scanner, _) = make_scanner(vec![email_pattern()], config);

    // Build input of exactly chunk_size bytes.
    let email = "t@d.co";
    let padding = chunk_size - email.len();
    let mut input = vec![b'X'; padding];
    input.extend_from_slice(email.as_bytes());
    assert_eq!(input.len(), chunk_size);

    let (output, stats) = scanner.scan_bytes(&input).unwrap();
    assert_eq!(stats.matches_found, 1);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains(email));
}

#[test]
fn no_patterns_passthrough() {
    let config = ScanConfig::new(64, 16);
    let (scanner, _) = make_scanner(vec![], config);
    let input = b"Nothing to scan alice@corp.com should pass through";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 0);
    assert_eq!(output, input.as_slice());
}

#[test]
fn all_bytes_are_matches() {
    // Input is entirely one match.
    let pat = ScanPattern::from_literal("AAAA", Category::Custom("test".into()), "test").unwrap();
    let config = ScanConfig::new(64, 16);
    let (scanner, _) = make_scanner(vec![pat], config);

    let input = b"AAAA";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    assert_ne!(output.as_slice(), b"AAAA");
}

// ===========================================================================
// 7. Scan statistics
// ===========================================================================

#[test]
fn stats_bytes_tracked_correctly() {
    let config = ScanConfig::new(256, 32);
    let (scanner, _) = make_scanner(vec![email_pattern()], config);

    let input = b"Hello alice@corp.com world";
    let (output, stats) = scanner.scan_bytes(input).unwrap();

    assert_eq!(stats.bytes_processed, input.len() as u64);
    assert_eq!(stats.bytes_output, output.len() as u64);
    assert_eq!(stats.matches_found, 1);
    assert_eq!(stats.replacements_applied, 1);
    assert_eq!(*stats.pattern_counts.get("email").unwrap(), 1);
}

#[test]
fn stats_pattern_counts_per_type() {
    let config = ScanConfig::new(512, 32);
    let (scanner, _) = make_scanner(vec![email_pattern(), ipv4_pattern()], config);

    let input = b"a@b.co 1.2.3.4 c@d.ef 5.6.7.8 g@h.ij";
    let (_, stats) = scanner.scan_bytes(input).unwrap();

    assert_eq!(stats.matches_found, 5);
    assert_eq!(*stats.pattern_counts.get("email").unwrap(), 3);
    assert_eq!(*stats.pattern_counts.get("ipv4").unwrap(), 2);
}

// ===========================================================================
// 8. Strategy integration (StrategyGenerator + Scanner)
// ===========================================================================

#[test]
fn scanner_with_strategy_generator() {
    use scour_secrets::strategy::{EntropyMode, RandomString, StrategyGenerator};

    let strat = Box::new(RandomString::new());
    let gen = Arc::new(StrategyGenerator::new(
        strat,
        EntropyMode::Deterministic { key: [99u8; 32] },
    ));
    let store = Arc::new(MappingStore::new(gen, None));

    let pattern = ScanPattern::from_regex(
        r"\bSECRET_[A-Z0-9]{8}\b",
        Category::Custom("secret_token".into()),
        "secret_token",
    )
    .unwrap();

    let scanner = StreamScanner::new(vec![pattern], store, ScanConfig::new(128, 32)).unwrap();

    let input = b"Token1=SECRET_ABCD1234 Token2=SECRET_WXYZ9876";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("SECRET_ABCD1234"));
    assert!(!out_str.contains("SECRET_WXYZ9876"));
}

#[test]
fn scanner_with_category_aware_strategy() {
    use scour_secrets::strategy::{CategoryAwareStrategy, EntropyMode, StrategyGenerator};

    let gen = Arc::new(StrategyGenerator::new(
        Box::new(CategoryAwareStrategy::new()),
        EntropyMode::Deterministic { key: [42u8; 32] },
    ));
    let store = Arc::new(MappingStore::new(gen, None));

    let pattern =
        ScanPattern::from_literal("alice@corp.com", Category::Email, "test_email").unwrap();
    let scanner =
        StreamScanner::new(vec![pattern], Arc::clone(&store), ScanConfig::new(128, 32)).unwrap();

    let input = b"Contact alice@corp.com for help.";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    let out_str = String::from_utf8(output).unwrap();

    assert_eq!(stats.replacements_applied, 1, "email must be replaced once");
    assert!(
        !out_str.contains("alice@corp.com"),
        "original must not appear in output"
    );
    assert!(out_str.contains('@'), "replacement must be email-shaped");
    assert_eq!(out_str.len(), input.len(), "byte length must be preserved");
}

// ===========================================================================
// 9. Simulated multi-GB scan (logical, not actual)
// ===========================================================================

#[test]
fn simulated_large_file_with_cursor() {
    // We simulate many chunks being processed sequentially by using
    // io::Cursor over a large-ish buffer, verifying the scanner
    // processes it correctly via chunked I/O.
    use std::io::Cursor;

    let config = ScanConfig::new(512, 64);
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let scanner = StreamScanner::new(vec![email_pattern()], Arc::clone(&store), config).unwrap();

    // ~100 KiB of data with 500 unique emails.
    let mut data = Vec::new();
    for i in 0..500u32 {
        let line = format!(
            "Line {:05}: contact person_{}@enterprise.example.com for info.\n",
            i, i
        );
        data.extend_from_slice(line.as_bytes());
    }

    let reader = Cursor::new(&data);
    let mut output = Vec::new();
    let stats = scanner.scan_reader(reader, &mut output).unwrap();

    assert_eq!(stats.matches_found, 500);
    assert_eq!(store.len(), 500);

    let out_str = String::from_utf8_lossy(&output);
    for i in 0..500u32 {
        let email = format!("person_{}@enterprise.example.com", i);
        assert!(!out_str.contains(&email), "email '{}' not replaced", email);
    }
}

// ===========================================================================
// 10. Overlapping patterns (priority)
// ===========================================================================

#[test]
fn overlapping_patterns_leftmost_longest_wins() {
    // Two patterns that could match overlapping regions.
    // "abc@def.gh" matches both an email pattern and a literal "abc@def".
    // The email pattern is longer, so it should win.
    let email = email_pattern();
    let literal =
        ScanPattern::from_literal("abc@def", Category::Custom("partial".into()), "partial")
            .unwrap();

    let config = ScanConfig::new(128, 32);
    let (scanner, _) = make_scanner(vec![email, literal], config);

    let input = b"see abc@def.gh for info";
    let (_, stats) = scanner.scan_bytes(input).unwrap();

    // The email pattern should capture the whole match.
    assert_eq!(stats.matches_found, 1);
    assert_eq!(*stats.pattern_counts.get("email").unwrap(), 1);
}

// ===========================================================================
// 11. Capacity-exceeded error propagates cleanly
// ===========================================================================

/// A store capacity limit hit mid-scan must propagate as
/// `SanitizeError::CapacityExceeded` rather than silently producing partial
/// output or replacing fewer secrets than expected.
#[test]
fn capacity_exceeded_during_scan_returns_error() {
    let gen = Arc::new(HmacGenerator::new([55u8; 32]));
    // Allow only 2 unique mappings — a third distinct secret will overflow.
    let store = Arc::new(MappingStore::new(gen, Some(2)));
    let scanner = Arc::new(
        StreamScanner::new(
            vec![email_pattern()],
            Arc::clone(&store),
            ScanConfig::new(256, 32),
        )
        .unwrap(),
    );

    // Three distinct email addresses → three distinct store insertions needed.
    let input = b"a@one.com b@two.com c@three.com";
    let result = scanner.scan_bytes(input);

    assert!(result.is_err(), "expected CapacityExceeded error, got Ok");
    assert!(
        matches!(result.unwrap_err(), SanitizeError::CapacityExceeded { .. }),
        "error must be CapacityExceeded"
    );
}

/// Scanning the same two secrets repeatedly must succeed: the store returns
/// cached results and never exceeds the capacity.
#[test]
fn capacity_not_exceeded_for_repeated_secrets() {
    let gen = Arc::new(HmacGenerator::new([55u8; 32]));
    let store = Arc::new(MappingStore::new(gen, Some(2)));
    let scanner = Arc::new(
        StreamScanner::new(
            vec![email_pattern()],
            Arc::clone(&store),
            ScanConfig::new(64, 16),
        )
        .unwrap(),
    );

    // The same two emails repeated many times — only 2 distinct insertions needed.
    let input = b"a@one.com a@one.com b@two.com b@two.com a@one.com b@two.com";
    let (_, stats) = scanner
        .scan_bytes(input)
        .expect("should succeed: only 2 distinct secrets");

    assert_eq!(stats.matches_found, 6);
    assert_eq!(store.len(), 2);
}
