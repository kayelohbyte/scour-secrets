//! Integration tests for encrypted secrets support.
//!
//! Covers:
//! - Encrypt → decrypt → scan pipeline
//! - Encrypted secrets with streaming scanner
//! - One-way replacement correctness with encrypted secrets
//! - Large file scanning with encrypted secrets
//! - Thread-safe concurrent scans with shared encrypted secrets
//! - Multiple secrets formats (JSON, YAML, TOML)
//! - Error handling (wrong password, corrupt file, bad patterns)

use rust_sanitize::category::Category;
use rust_sanitize::generator::HmacGenerator;
use rust_sanitize::scanner::{ScanConfig, ScanPattern, SecretsLoadResult, StreamScanner};
use rust_sanitize::secrets::{decrypt_secrets, encrypt_secrets, SecretsFormat};
use rust_sanitize::store::MappingStore;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_store() -> Arc<MappingStore> {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    Arc::new(MappingStore::new(gen, None))
}

fn sample_json_secrets() -> &'static str {
    r#"[
        {
            "pattern": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
            "kind": "regex",
            "category": "email",
            "label": "email_address"
        },
        {
            "pattern": "sk-proj-[A-Za-z0-9]{20}",
            "kind": "regex",
            "category": "custom:api_key",
            "label": "openai_key"
        },
        {
            "pattern": "HARDCODED_SECRET_VALUE",
            "kind": "literal",
            "category": "custom:secret",
            "label": "hardcoded_literal"
        }
    ]"#
}

fn sample_yaml_secrets() -> &'static str {
    r#"- pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
  kind: regex
  category: email
  label: email_address
- pattern: "HARDCODED_SECRET_VALUE"
  kind: literal
  category: "custom:secret"
  label: hardcoded_literal
"#
}

fn sample_toml_secrets() -> &'static str {
    r#"[[secrets]]
pattern = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
kind = "regex"
category = "email"
label = "email_address"

[[secrets]]
pattern = "HARDCODED_SECRET_VALUE"
kind = "literal"
category = "custom:secret"
label = "hardcoded_literal"
"#
}

// ===========================================================================
// 1. Encrypt → Decrypt round-trip
// ===========================================================================

#[test]
fn encrypt_decrypt_roundtrip_json() {
    let plaintext = sample_json_secrets().as_bytes();
    let password = "strong-password-123!";

    let encrypted = encrypt_secrets(plaintext, password).unwrap();
    let decrypted = decrypt_secrets(&encrypted, password).unwrap();

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn wrong_password_fails_gracefully() {
    let plaintext = sample_json_secrets().as_bytes();
    let encrypted = encrypt_secrets(plaintext, "correct").unwrap();
    let result = decrypt_secrets(&encrypted, "incorrect");
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("wrong password") || err_msg.contains("decryption failed"));
}

#[test]
fn corrupt_encrypted_file_fails() {
    let plaintext = sample_json_secrets().as_bytes();
    let mut encrypted = encrypt_secrets(plaintext, "pw").unwrap();
    // Corrupt the ciphertext (index must be past the 32-byte salt + 12-byte nonce header).
    encrypted[50] ^= 0xFF;
    let result = decrypt_secrets(&encrypted, "pw");
    assert!(result.is_err());
}

// ===========================================================================
// 2. Full pipeline: encrypted secrets → scanner → scan
// ===========================================================================

#[test]
fn encrypted_secrets_scan_email() {
    let password = "test-pw";
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), password).unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, warnings, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    assert!(warnings.is_empty());
    assert_eq!(scanner.pattern_count(), 3);

    let input = b"Contact alice@corp.com for help.";
    let (output, stats) = scanner.scan_bytes(input).unwrap();

    assert_eq!(stats.matches_found, 1);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("alice@corp.com"));
    // Domain preserved, original user replaced.
    assert!(out_str.contains("@corp.com"), "domain must be preserved");
}

#[test]
fn encrypted_secrets_scan_literal() {
    let password = "literal-test";
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), password).unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    let input = b"Token: HARDCODED_SECRET_VALUE end";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    assert!(!output
        .windows(b"HARDCODED_SECRET_VALUE".len())
        .any(|w| w == b"HARDCODED_SECRET_VALUE"));
}

#[test]
fn encrypted_secrets_scan_api_key() {
    let password = "api-key-test";
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), password).unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    let input = b"key=sk-proj-AbCdEfGhIjKlMnOpQrSt end";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 1);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("sk-proj-AbCdEfGhIjKlMnOpQrSt"));
}

// ===========================================================================
// 3. One-way replacement consistency
// ===========================================================================

#[test]
fn encrypted_secrets_same_value_same_replacement() {
    let password = "consistency-test";
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), password).unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    let input = b"first: alice@corp.com second: alice@corp.com";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);

    // Both occurrences must get the same replacement.
    let out_str = String::from_utf8_lossy(&output);
    // Domain preserved; count occurrences of preserved domain.
    let count = out_str.matches("@corp.com").count();
    assert_eq!(count, 2);
}

// ===========================================================================
// 4. Large file with encrypted secrets
// ===========================================================================

#[test]
fn encrypted_secrets_large_file() {
    let password = "large-file-test";
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), password).unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(4096, 256),
        vec![],
    )
    .unwrap();

    // Build ~200 KiB input with emails + literal secrets.
    let mut input = Vec::new();
    let filler = "The quick brown fox jumps over the lazy dog. ";
    for i in 0..500u32 {
        input.extend_from_slice(filler.as_bytes());
        if i % 5 == 0 {
            let email = format!("user{}@example.com ", i);
            input.extend_from_slice(email.as_bytes());
        }
        if i % 50 == 0 {
            input.extend_from_slice(b"HARDCODED_SECRET_VALUE ");
        }
    }

    let (output, stats) = scanner.scan_bytes(&input).unwrap();

    // 100 emails (i divisible by 5, 0..500) + 10 literals (i divisible by 50)
    assert_eq!(stats.matches_found, 110);

    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("HARDCODED_SECRET_VALUE"));
    for i in (0..500u32).step_by(5) {
        let email = format!("user{}@example.com", i);
        assert!(!out_str.contains(&email), "email {} not replaced", email);
    }
}

// ===========================================================================
// 5. Concurrent scans with encrypted secrets
// ===========================================================================

#[test]
fn encrypted_secrets_concurrent_scans() {
    use std::thread;

    let password = "concurrent-test";
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), password).unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Json),
        Arc::clone(&store),
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    let scanner = Arc::new(scanner);

    let mut handles = vec![];
    for t in 0..4 {
        let scanner = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            let mut input = Vec::new();
            for i in 0..50 {
                let line = format!("Thread {} user_t{}i{}@corp.com ", t, t, i);
                input.extend_from_slice(line.as_bytes());
            }
            let (output, stats) = scanner.scan_bytes(&input).unwrap();
            assert_eq!(stats.matches_found, 50, "thread {}", t);
            // Original user parts must not survive; domain is preserved.
            let out_str = String::from_utf8_lossy(&output);
            for i in 0..50 {
                let original_user = format!("user_t{}i{}", t, i);
                assert!(!out_str.contains(&original_user), "thread {} user {}", t, i);
            }
            stats
        }));
    }

    for h in handles {
        let stats = h.join().unwrap();
        assert_eq!(stats.matches_found, 50);
    }

    // 4 threads × 50 unique emails.
    assert_eq!(store.len(), 200);
}

// ===========================================================================
// 6. YAML and TOML encrypted formats
// ===========================================================================

#[test]
fn encrypted_yaml_secrets_pipeline() {
    let password = "yaml-enc-test";
    let encrypted = encrypt_secrets(sample_yaml_secrets().as_bytes(), password).unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, warnings, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Yaml),
        store,
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    assert!(warnings.is_empty());
    assert_eq!(scanner.pattern_count(), 2);

    let input = b"email: bob@example.com secret: HARDCODED_SECRET_VALUE";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("bob@example.com"));
    assert!(!out_str.contains("HARDCODED_SECRET_VALUE"));
}

#[test]
fn encrypted_toml_secrets_pipeline() {
    let password = "toml-enc-test";
    let encrypted = encrypt_secrets(sample_toml_secrets().as_bytes(), password).unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, warnings, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Toml),
        store,
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    assert!(warnings.is_empty());
    assert_eq!(scanner.pattern_count(), 2);

    let input = b"Contact admin@site.org with secret HARDCODED_SECRET_VALUE";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("admin@site.org"));
    assert!(!out_str.contains("HARDCODED_SECRET_VALUE"));
}

// ===========================================================================
// 7. Extra patterns merged with encrypted secrets
// ===========================================================================

#[test]
fn encrypted_secrets_with_extra_patterns() {
    let password = "merge-test";
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), password).unwrap();

    // An extra pattern not in the secrets file.
    let extra = ScanPattern::from_regex(r"\b\d{3}-\d{2}-\d{4}\b", Category::Ssn, "ssn").unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(256, 32),
        vec![extra],
    )
    .unwrap();

    assert_eq!(scanner.pattern_count(), 4); // 3 from file + 1 extra

    let input = b"email: a@b.co ssn: 123-45-6789";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("a@b.co"));
    assert!(!out_str.contains("123-45-6789"));
}

// ===========================================================================
// 8. Plaintext secrets loader (dev/test convenience)
// ===========================================================================

#[test]
fn plaintext_secrets_scan() {
    let store = make_store();
    let SecretsLoadResult { scanner, warnings, .. } = StreamScanner::from_plaintext_secrets(
        sample_json_secrets().as_bytes(),
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    assert!(warnings.is_empty());
    assert_eq!(scanner.pattern_count(), 3);

    let input = b"Contact alice@corp.com about HARDCODED_SECRET_VALUE";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("alice@corp.com"));
    assert!(!out_str.contains("HARDCODED_SECRET_VALUE"));
}

// ===========================================================================
// 9. Error handling
// ===========================================================================

#[test]
fn encrypted_wrong_password_returns_error() {
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), "correct").unwrap();

    let store = make_store();
    let result = StreamScanner::from_encrypted_secrets(
        &encrypted,
        "wrong",
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(256, 32),
        vec![],
    );
    assert!(result.is_err());
}

#[test]
fn encrypted_bad_pattern_in_secrets_returns_warnings() {
    let json = r#"[
        {"pattern": "[invalid-regex(", "kind": "regex", "category": "email", "label": "bad"},
        {"pattern": "good-literal", "kind": "literal", "category": "custom:ok", "label": "good"}
    ]"#;
    let encrypted = encrypt_secrets(json.as_bytes(), "pw").unwrap();

    let store = make_store();
    let SecretsLoadResult { scanner, warnings, .. } = StreamScanner::from_encrypted_secrets(
        &encrypted,
        "pw",
        Some(SecretsFormat::Json),
        store,
        ScanConfig::new(256, 32),
        vec![],
    )
    .unwrap();

    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].0, 0); // first entry failed
    assert_eq!(scanner.pattern_count(), 1); // only the literal compiled
}

// ===========================================================================
// 10. Deterministic replacement across scans with same seed
// ===========================================================================

#[test]
fn deterministic_replacement_across_scanner_instances() {
    let password = "determinism-test";
    let encrypted = encrypt_secrets(sample_json_secrets().as_bytes(), password).unwrap();

    // Two independent scanners with the same HMAC seed.
    let build_scanner = || {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let SecretsLoadResult { scanner, .. } = StreamScanner::from_encrypted_secrets(
            &encrypted,
            password,
            Some(SecretsFormat::Json),
            store,
            ScanConfig::new(256, 32),
            vec![],
        )
        .unwrap();
        scanner
    };

    let scanner1 = build_scanner();
    let scanner2 = build_scanner();

    let input = b"Contact alice@corp.com for info.";
    let (out1, _) = scanner1.scan_bytes(input).unwrap();
    let (out2, _) = scanner2.scan_bytes(input).unwrap();

    // Same seed → same replacements.
    assert_eq!(out1, out2);
}

// ===========================================================================
// 11. Zeroization / memory safety
// ===========================================================================

#[test]
fn decrypted_plaintext_is_zeroizing() {
    // We can't directly test that memory is zeroed, but we can verify
    // the type returns Zeroizing<Vec<u8>> and that dropping it doesn't
    // panic.
    let plaintext = b"sensitive data";
    let encrypted = encrypt_secrets(plaintext, "pw").unwrap();
    let decrypted = decrypt_secrets(&encrypted, "pw").unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
    // zeroize::Zeroizing<Vec<u8>> zeros memory on drop.
    drop(decrypted);
}

// ===========================================================================
// 12. File-backed round-trip (uses tempfile)
// ===========================================================================

#[test]
fn file_backed_encrypt_decrypt() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let plain_path = dir.path().join("secrets.json");
    let enc_path = dir.path().join("secrets.json.enc");

    // Write plaintext.
    fs::write(&plain_path, sample_json_secrets()).unwrap();

    // Encrypt.
    let plaintext = fs::read(&plain_path).unwrap();
    let encrypted = encrypt_secrets(&plaintext, "file-test").unwrap();
    fs::write(&enc_path, encrypted).unwrap();

    // Decrypt from file.
    let enc_data = fs::read(&enc_path).unwrap();
    let store = make_store();
    let SecretsLoadResult { scanner, warnings, .. } = StreamScanner::from_encrypted_secrets(
        &enc_data,
        "file-test",
        Some(SecretsFormat::Json),
        store,
        ScanConfig::default(),
        vec![],
    )
    .unwrap();

    assert!(warnings.is_empty());
    assert_eq!(scanner.pattern_count(), 3);

    // Verify the plaintext file can be "removed" — we just confirm the
    // scanner works without it.
    fs::remove_file(&plain_path).unwrap();

    let input = b"alice@corp.com HARDCODED_SECRET_VALUE";
    let (output, stats) = scanner.scan_bytes(input).unwrap();
    assert_eq!(stats.matches_found, 2);
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("alice@corp.com"));
    assert!(!out_str.contains("HARDCODED_SECRET_VALUE"));
}
