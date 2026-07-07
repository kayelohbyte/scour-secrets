//! Integration tests for optional unencrypted (plaintext) secrets support.
//!
//! Covers:
//! - Plaintext secrets parsing (JSON, YAML, TOML)
//! - Auto-detect: encrypted vs plaintext
//! - Replacement correctness with plaintext secrets
//! - Deterministic replacement mode with plaintext secrets
//! - Fail-on-match behaviour with plaintext secrets
//! - Zeroization / memory hygiene for plaintext entries
//! - Unified `load_secrets_auto` paths

use scour_secrets::category::Category;
use scour_secrets::generator::{HmacGenerator, RandomGenerator};
use scour_secrets::scanner::{ScanConfig, ScanPattern, SecretsLoadResult, StreamScanner};
use scour_secrets::secrets::{
    encrypt_secrets, load_plaintext_secrets, load_secrets_auto, looks_encrypted, parse_secrets,
    SecretsFormat,
};
use scour_secrets::store::MappingStore;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_hmac_store() -> Arc<MappingStore> {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    Arc::new(MappingStore::new(gen, None))
}

fn make_random_store() -> Arc<MappingStore> {
    let gen = Arc::new(RandomGenerator::new());
    Arc::new(MappingStore::new(gen, None))
}

fn sample_json() -> &'static str {
    r#"[
        {
            "pattern": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
            "kind": "regex",
            "category": "email",
            "label": "email_pattern"
        },
        {
            "pattern": "SUPER_SECRET_TOKEN_XYZ",
            "kind": "literal",
            "category": "custom:api_key",
            "label": "api_token"
        }
    ]"#
}

fn sample_yaml() -> &'static str {
    r#"- pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
  kind: regex
  category: email
  label: email_pattern
- pattern: SUPER_SECRET_TOKEN_XYZ
  kind: literal
  category: "custom:api_key"
  label: api_token
"#
}

fn sample_toml() -> &'static str {
    r#"[[secrets]]
pattern = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
kind = "regex"
category = "email"
label = "email_pattern"

[[secrets]]
pattern = "SUPER_SECRET_TOKEN_XYZ"
kind = "literal"
category = "custom:api_key"
label = "api_token"
"#
}

fn default_scan_config() -> ScanConfig {
    ScanConfig::new(256, 32)
}

// ===========================================================================
// 1. Plaintext secrets parsing (JSON, YAML, TOML)
// ===========================================================================

#[test]
fn plaintext_parse_json() {
    let entries = parse_secrets(sample_json().as_bytes(), Some(SecretsFormat::Json)).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].kind, "regex");
    assert_eq!(entries[0].category, "email");
    assert_eq!(entries[0].label, Some("email_pattern".into()));
    assert_eq!(entries[1].kind, "literal");
    assert_eq!(entries[1].pattern, "SUPER_SECRET_TOKEN_XYZ");
}

#[test]
fn plaintext_parse_yaml() {
    let entries = parse_secrets(sample_yaml().as_bytes(), Some(SecretsFormat::Yaml)).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].kind, "regex");
    assert_eq!(entries[1].pattern, "SUPER_SECRET_TOKEN_XYZ");
}

#[test]
fn plaintext_parse_toml() {
    let entries = parse_secrets(sample_toml().as_bytes(), Some(SecretsFormat::Toml)).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].category, "email");
    assert_eq!(entries[1].label, Some("api_token".into()));
}

#[test]
fn plaintext_parse_auto_detect_json() {
    // JSON starts with '[' — auto-detected.
    let entries = parse_secrets(sample_json().as_bytes(), None).unwrap();
    assert_eq!(entries.len(), 2);
}

#[test]
fn plaintext_parse_auto_detect_yaml() {
    // YAML starts with '-' — auto-detected.
    let entries = parse_secrets(sample_yaml().as_bytes(), None).unwrap();
    assert_eq!(entries.len(), 2);
}

// ===========================================================================
// 2. Auto-detect: encrypted vs plaintext (looks_encrypted)
// ===========================================================================

#[test]
fn looks_encrypted_detects_plaintext_json() {
    assert!(!looks_encrypted(sample_json().as_bytes()));
}

#[test]
fn looks_encrypted_detects_plaintext_yaml() {
    assert!(!looks_encrypted(sample_yaml().as_bytes()));
}

#[test]
fn looks_encrypted_detects_plaintext_toml() {
    assert!(!looks_encrypted(sample_toml().as_bytes()));
}

#[test]
fn looks_encrypted_detects_encrypted_blob() {
    let plaintext = sample_json().as_bytes();
    let encrypted = encrypt_secrets(plaintext, "test-password").unwrap();
    assert!(looks_encrypted(&encrypted));
}

#[test]
fn looks_encrypted_short_data_returns_false() {
    // Data shorter than MIN_ENCRYPTED_LEN cannot be a valid AES blob.
    assert!(!looks_encrypted(&[0u8; 10]));
}

#[test]
fn looks_encrypted_binary_garbage_returns_true() {
    // Random non-UTF-8 bytes ≥ MIN_ENCRYPTED_LEN.
    let mut data = vec![0xFFu8; 128];
    data[0] = 0x80;
    data[1] = 0xFE;
    assert!(looks_encrypted(&data));
}

// ===========================================================================
// 3. load_secrets_auto — unified loader
// ===========================================================================

#[test]
fn load_auto_plaintext_with_flag() {
    let data = sample_json().as_bytes();
    let (((patterns, errors), _allow), was_encrypted) =
        load_secrets_auto(data, None, Some(SecretsFormat::Json), true).unwrap();
    assert!(!was_encrypted);
    assert_eq!(patterns.len(), 2);
    assert!(errors.is_empty());
}

#[test]
fn load_auto_plaintext_auto_detect() {
    // No force_plaintext, but data is clearly plaintext JSON.
    let data = sample_json().as_bytes();
    let (((patterns, errors), _allow), was_encrypted) =
        load_secrets_auto(data, None, Some(SecretsFormat::Json), false).unwrap();
    assert!(!was_encrypted);
    assert_eq!(patterns.len(), 2);
    assert!(errors.is_empty());
}

#[test]
fn load_auto_encrypted_with_password() {
    let plaintext = sample_json().as_bytes();
    let encrypted = encrypt_secrets(plaintext, "pw123").unwrap();
    let (((patterns, errors), _allow), was_encrypted) =
        load_secrets_auto(&encrypted, Some("pw123"), Some(SecretsFormat::Json), false).unwrap();
    assert!(was_encrypted);
    assert_eq!(patterns.len(), 2);
    assert!(errors.is_empty());
}

#[test]
fn load_auto_encrypted_without_password_errors() {
    let plaintext = sample_json().as_bytes();
    let encrypted = encrypt_secrets(plaintext, "pw123").unwrap();
    let result = load_secrets_auto(&encrypted, None, Some(SecretsFormat::Json), false);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("no password"));
}

#[test]
fn load_auto_encrypted_force_plaintext_fails_gracefully() {
    // Forcing plaintext on encrypted data should fail at parse time.
    let plaintext = sample_json().as_bytes();
    let encrypted = encrypt_secrets(plaintext, "pw123").unwrap();
    let result = load_secrets_auto(&encrypted, None, None, true);
    // Encrypted binary can't parse as JSON/YAML/TOML.
    assert!(result.is_err());
}

// ===========================================================================
// 4. load_plaintext_secrets — pattern compilation
// ===========================================================================

#[test]
fn plaintext_load_json_compiles_patterns() {
    let ((patterns, errors), _allow) =
        load_plaintext_secrets(sample_json().as_bytes(), Some(SecretsFormat::Json)).unwrap();
    assert_eq!(patterns.len(), 2);
    assert!(errors.is_empty());
    assert_eq!(patterns[0].label(), "email_pattern");
    assert_eq!(patterns[1].label(), "api_token");
}

#[test]
fn plaintext_load_yaml_compiles_patterns() {
    let ((patterns, errors), _allow) =
        load_plaintext_secrets(sample_yaml().as_bytes(), Some(SecretsFormat::Yaml)).unwrap();
    assert_eq!(patterns.len(), 2);
    assert!(errors.is_empty());
}

#[test]
fn plaintext_load_toml_compiles_patterns() {
    let ((patterns, errors), _allow) =
        load_plaintext_secrets(sample_toml().as_bytes(), Some(SecretsFormat::Toml)).unwrap();
    assert_eq!(patterns.len(), 2);
    assert!(errors.is_empty());
}

#[test]
fn plaintext_load_bad_regex_returns_warnings() {
    let json = r#"[
        {"pattern": "[bad(regex", "kind": "regex", "category": "email"},
        {"pattern": "good-literal", "kind": "literal", "category": "custom:ok"}
    ]"#;
    let ((patterns, errors), _allow) =
        load_plaintext_secrets(json.as_bytes(), Some(SecretsFormat::Json)).unwrap();
    assert_eq!(patterns.len(), 1);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, 0); // first entry failed
}

// ===========================================================================
// 5. Replacement correctness with plaintext secrets
// ===========================================================================

#[test]
fn plaintext_secrets_replace_email() {
    let store = make_hmac_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        default_scan_config(),
        vec![],
    )
    .unwrap();

    let input = b"Contact alice@corp.com for help.";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("alice@corp.com"));
    assert!(out_str.contains("@corp.com"), "domain must be preserved");
}

#[test]
fn plaintext_secrets_replace_literal() {
    let store = make_hmac_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        default_scan_config(),
        vec![],
    )
    .unwrap();

    let input = b"Token: SUPER_SECRET_TOKEN_XYZ end";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    assert!(!output
        .windows(b"SUPER_SECRET_TOKEN_XYZ".len())
        .any(|w| w == b"SUPER_SECRET_TOKEN_XYZ"));
}

#[test]
fn plaintext_secrets_same_value_same_replacement() {
    let store = make_hmac_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        default_scan_config(),
        vec![],
    )
    .unwrap();

    let input = b"first: alice@corp.com second: alice@corp.com";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    // Both replaced the same way.
    let count = out_str.matches("@corp.com").count();
    assert_eq!(count, 2);
}

#[test]
fn plaintext_secrets_no_match_passes_through() {
    let store = make_hmac_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        default_scan_config(),
        vec![],
    )
    .unwrap();

    let input = b"No secrets here, just plain text.";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 0);
    assert_eq!(output, input);
}

// ===========================================================================
// 6. Deterministic replacement mode with plaintext secrets
// ===========================================================================

#[test]
fn plaintext_deterministic_same_seed_same_output() {
    let build_scanner = || {
        let gen = Arc::new(HmacGenerator::new([99u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
            sample_json().as_bytes(),
            Some(SecretsFormat::Json),
            store,
            default_scan_config(),
            vec![],
        )
        .unwrap();
        scanner
    };

    let scanner1 = build_scanner();
    let scanner2 = build_scanner();

    let input = b"Contact alice@corp.com about SUPER_SECRET_TOKEN_XYZ";
    let (out1, _) = scanner1.scan_bytes(input).unwrap();
    let (out2, _) = scanner2.scan_bytes(input).unwrap();

    // Same seed → identical output.
    assert_eq!(out1, out2);
}

#[test]
fn plaintext_deterministic_different_seeds_different_output() {
    let build_scanner_with_seed = |seed: [u8; 32]| {
        let gen = Arc::new(HmacGenerator::new(seed));
        let store = Arc::new(MappingStore::new(gen, None));
        let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
            sample_json().as_bytes(),
            Some(SecretsFormat::Json),
            store,
            default_scan_config(),
            vec![],
        )
        .unwrap();
        scanner
    };

    let scanner1 = build_scanner_with_seed([1u8; 32]);
    let scanner2 = build_scanner_with_seed([2u8; 32]);

    let input = b"Contact alice@corp.com about stuff";
    let (out1, _) = scanner1.scan_bytes(input).unwrap();
    let (out2, _) = scanner2.scan_bytes(input).unwrap();

    // Different seeds → (very likely) different output.
    assert_ne!(out1, out2);
}

// ===========================================================================
// 7. Random replacement mode with plaintext secrets
// ===========================================================================

#[test]
fn plaintext_random_mode_replaces_correctly() {
    let store = make_random_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        default_scan_config(),
        vec![],
    )
    .unwrap();

    let input = b"Token: SUPER_SECRET_TOKEN_XYZ end";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    assert!(!output
        .windows(b"SUPER_SECRET_TOKEN_XYZ".len())
        .any(|w| w == b"SUPER_SECRET_TOKEN_XYZ"));
}

// ===========================================================================
// 8. Plaintext secrets match encrypted secrets output
// ===========================================================================

#[test]
fn plaintext_and_encrypted_produce_same_patterns() {
    let plaintext = sample_json().as_bytes();
    let password = "match-test";
    let encrypted = encrypt_secrets(plaintext, password).unwrap();

    let ((pt_patterns, pt_errors), _) =
        load_plaintext_secrets(plaintext, Some(SecretsFormat::Json)).unwrap();
    let (((enc_patterns, enc_errors), _allow), was_enc) =
        load_secrets_auto(&encrypted, Some(password), Some(SecretsFormat::Json), false).unwrap();

    assert!(was_enc);
    assert_eq!(pt_patterns.len(), enc_patterns.len());
    assert_eq!(pt_errors.len(), enc_errors.len());

    // Labels must match.
    for (pt, enc) in pt_patterns.iter().zip(enc_patterns.iter()) {
        assert_eq!(pt.label(), enc.label());
    }
}

// ===========================================================================
// 9. Fail-on-match behaviour with plaintext secrets
// ===========================================================================

#[test]
fn plaintext_secrets_detects_matches_for_fail_on_match() {
    let store = make_hmac_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        default_scan_config(),
        vec![],
    )
    .unwrap();

    // Input with a secret.
    let input_with_secret = b"Config: SUPER_SECRET_TOKEN_XYZ end";
    let (_, stats) = scanner.scan_bytes(input_with_secret).unwrap();
    assert!(
        stats.matches_found > 0,
        "fail-on-match: expected matches to be detected"
    );

    // Input without secrets.
    let store2 = make_hmac_store();
    let SecretsLoadResult {
        scanner: scanner2, ..
    } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store2,
        default_scan_config(),
        vec![],
    )
    .unwrap();
    let input_clean = b"No secrets here at all";
    let (_, stats2) = scanner2.scan_bytes(input_clean).unwrap();
    assert_eq!(
        stats2.matches_found, 0,
        "fail-on-match: expected zero matches for clean input"
    );
}

// ===========================================================================
// 10. Zeroization for plaintext secrets
// ===========================================================================

#[test]
fn plaintext_load_does_not_panic_on_drop() {
    // Verifies that the zeroization code in load_plaintext_secrets
    // runs without error.
    let ((patterns, _), _allow) =
        load_plaintext_secrets(sample_json().as_bytes(), Some(SecretsFormat::Json)).unwrap();
    assert_eq!(patterns.len(), 2);
    drop(patterns);
    // If we get here without a panic, zeroization is safe.
}

#[test]
fn plaintext_auto_load_does_not_panic_on_drop() {
    let (((patterns, _), _allow), _) = load_secrets_auto(
        sample_json().as_bytes(),
        None,
        Some(SecretsFormat::Json),
        true,
    )
    .unwrap();
    assert_eq!(patterns.len(), 2);
    drop(patterns);
}

// ===========================================================================
// 11. Extra patterns work with plaintext secrets
// ===========================================================================

#[test]
fn plaintext_secrets_with_extra_patterns() {
    let extra = ScanPattern::from_regex(r"\b\d{3}-\d{2}-\d{4}\b", Category::Ssn, "ssn").unwrap();

    let store = make_hmac_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        default_scan_config(),
        vec![extra],
    )
    .unwrap();

    assert_eq!(scanner.pattern_count(), 3); // 2 from file + 1 extra

    let input = b"email: a@b.co ssn: 123-45-6789 token: SUPER_SECRET_TOKEN_XYZ";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 3);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("a@b.co"));
    assert!(!out_str.contains("123-45-6789"));
    assert!(!out_str.contains("SUPER_SECRET_TOKEN_XYZ"));
}

// ===========================================================================
// 12. Concurrent scans with plaintext secrets
// ===========================================================================

#[test]
fn plaintext_secrets_concurrent_scans() {
    use std::thread;

    let store = make_hmac_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        Arc::clone(&store),
        default_scan_config(),
        vec![],
    )
    .unwrap();

    let scanner = Arc::new(scanner);

    let mut handles = vec![];
    for t in 0..4 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            let mut input = Vec::new();
            for i in 0..25 {
                let line = format!("Thread {} user_t{}i{}@corp.com ", t, t, i);
                input.extend_from_slice(line.as_bytes());
            }
            let (output, stats) = scanner.scan_bytes(&input).unwrap();
            assert_eq!(stats.matches_found, 25, "thread {}", t);
            let out_str = String::from_utf8_lossy(&output);
            for i in 0..25 {
                let original_user = format!("user_t{}i{}", t, i);
                assert!(!out_str.contains(&original_user), "thread {} user {}", t, i);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ===========================================================================
// 13. File-backed plaintext secrets (no encryption)
// ===========================================================================

#[test]
fn file_backed_plaintext_secrets() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.json");

    // Write plaintext secrets file.
    fs::write(&secrets_path, sample_json()).unwrap();

    // Load directly — no encryption step.
    let data = fs::read(&secrets_path).unwrap();
    let store = make_hmac_store();
    let SecretsLoadResult {
        scanner, warnings, ..
    } = StreamScanner::from_plaintext_secrets(
        &data,
        Some(SecretsFormat::Json),
        store,
        ScanConfig::default(),
        vec![],
    )
    .unwrap();

    assert!(warnings.is_empty());
    assert_eq!(scanner.pattern_count(), 2);

    let input = b"alice@corp.com SUPER_SECRET_TOKEN_XYZ";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("alice@corp.com"));
    assert!(!out_str.contains("SUPER_SECRET_TOKEN_XYZ"));
}

// ===========================================================================
// 14. load_secrets_auto with YAML and TOML plaintext
// ===========================================================================

#[test]
fn load_auto_yaml_plaintext() {
    let data = sample_yaml().as_bytes();
    let (((patterns, errors), _allow), was_encrypted) =
        load_secrets_auto(data, None, Some(SecretsFormat::Yaml), false).unwrap();
    assert!(!was_encrypted);
    assert_eq!(patterns.len(), 2);
    assert!(errors.is_empty());
}

#[test]
fn load_auto_toml_plaintext() {
    let data = sample_toml().as_bytes();
    let (((patterns, errors), _allow), was_encrypted) =
        load_secrets_auto(data, None, Some(SecretsFormat::Toml), false).unwrap();
    assert!(!was_encrypted);
    assert_eq!(patterns.len(), 2);
    assert!(errors.is_empty());
}

// ===========================================================================
// 15. Large plaintext secrets file
// ===========================================================================

#[test]
fn plaintext_secrets_large_file_processing() {
    let store = make_hmac_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_plaintext_secrets(
        sample_json().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(4096, 256),
        vec![],
    )
    .unwrap();

    // Build ~100 KiB input with emails + literal secrets.
    let mut input = Vec::new();
    let filler = "The quick brown fox jumps over the lazy dog. ";
    for i in 0..250u32 {
        input.extend_from_slice(filler.as_bytes());
        if i % 5 == 0 {
            let email = format!("user{}@example.com ", i);
            input.extend_from_slice(email.as_bytes());
        }
        if i % 25 == 0 {
            input.extend_from_slice(b"SUPER_SECRET_TOKEN_XYZ ");
        }
    }

    let (output, stats) = scanner.scan_bytes(&input).unwrap();

    // 50 emails (0,5,10,...,245) + 10 literals (0,25,50,...,225)
    assert_eq!(stats.matches_found, 60);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("SUPER_SECRET_TOKEN_XYZ"));
}

#[test]
fn plaintext_load_allow_entries_populate_allow_patterns() {
    let secrets_yaml = b"\
- kind: allow\n  pattern: 'safe-value'\n\
- kind: allow\n  values: ['also-safe', 'another-safe']\n\
- pattern: 'catch-me'\n  kind: literal\n  category: auth_token\n";

    let store = make_hmac_store();
    let SecretsLoadResult {
        warnings,
        allow_patterns,
        ..
    } = StreamScanner::from_plaintext_secrets(
        secrets_yaml,
        Some(SecretsFormat::Yaml),
        store,
        default_scan_config(),
        vec![],
    )
    .unwrap();

    assert!(
        warnings.is_empty(),
        "no warnings expected; got: {warnings:?}"
    );
    assert!(
        allow_patterns.contains(&"safe-value".to_string()),
        "allow_patterns must include single-pattern allow entry; got: {allow_patterns:?}"
    );
    assert!(
        allow_patterns.contains(&"also-safe".to_string()),
        "allow_patterns must include first values-list entry; got: {allow_patterns:?}"
    );
    assert!(
        allow_patterns.contains(&"another-safe".to_string()),
        "allow_patterns must include second values-list entry; got: {allow_patterns:?}"
    );
}
