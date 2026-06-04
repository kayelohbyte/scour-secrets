//! Integration tests for structured processors.
//!
//! Covers:
//! - Registry discovery and dispatch
//! - Key-value processor (gitlab.rb style)
//! - JSON, YAML, XML, CSV processors
//! - One-way replacement correctness
//! - Deterministic / dedup behavior across processors
//! - Fallback to None when no processor matches
//! - Integration with encrypted secrets (shared MappingStore)
//! - File-type profile matching

use rust_sanitize::category::Category;
use rust_sanitize::generator::HmacGenerator;
use rust_sanitize::processor::csv_proc::CsvProcessor;
use rust_sanitize::processor::json_proc::JsonProcessor;
use rust_sanitize::processor::key_value::KeyValueProcessor;
use rust_sanitize::processor::profile::{FieldRule, FileTypeProfile};
use rust_sanitize::processor::registry::ProcessorRegistry;
use rust_sanitize::processor::xml_proc::XmlProcessor;
use rust_sanitize::processor::yaml_proc::YamlProcessor;
use rust_sanitize::processor::Processor;
use rust_sanitize::scanner::{ScanConfig, ScanPattern, StreamScanner};
use rust_sanitize::secrets::{encrypt_secrets, SecretsFormat};
use rust_sanitize::store::MappingStore;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_store() -> Arc<MappingStore> {
    let gen = Arc::new(HmacGenerator::new([42u8; 32]));
    Arc::new(MappingStore::new(gen, None))
}

// ===========================================================================
// 1. Registry tests
// ===========================================================================

#[test]
fn registry_has_all_builtins() {
    let reg = ProcessorRegistry::with_builtins();
    assert_eq!(reg.len(), 11); // 10 processors + key-value alias for key_value
    assert!(reg.get("key_value").is_some());
    assert!(reg.get("key-value").is_some());
    assert!(reg.get("json").is_some());
    assert!(reg.get("jsonl").is_some());
    assert!(reg.get("yaml").is_some());
    assert!(reg.get("xml").is_some());
    assert!(reg.get("csv").is_some());
    assert!(reg.get("toml").is_some());
    assert!(reg.get("env").is_some());
    assert!(reg.get("ini").is_some());
    assert!(reg.get("log").is_some());
}

#[test]
fn registry_find_processor_by_profile_name() {
    let reg = ProcessorRegistry::with_builtins();
    let profile = FileTypeProfile::new("json", vec![]);

    let proc = reg.find_processor(b"{}", &profile);
    assert!(proc.is_some());
    assert_eq!(proc.unwrap().name(), "json");
}

#[test]
fn registry_returns_none_for_unknown_processor() {
    let reg = ProcessorRegistry::with_builtins();
    let profile = FileTypeProfile::new("unknown_format", vec![]);

    let result = reg
        .process(b"some content", &profile, &make_store())
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn registry_dispatch_processes_content() {
    let reg = ProcessorRegistry::with_builtins();
    let store = make_store();

    let content = br#"{"password": "s3cret"}"#;
    let profile = FileTypeProfile::new(
        "json",
        vec![FieldRule::new("password").with_category(Category::Custom("pw".into()))],
    )
    .with_option("compact", "true");

    let result = reg.process(content, &profile, &store).unwrap();
    assert!(result.is_some());
    let out = String::from_utf8(result.unwrap()).unwrap();
    assert!(!out.contains("s3cret"));
}

// ===========================================================================
// 2. Key-value processor (gitlab.rb style)
// ===========================================================================

#[test]
fn key_value_gitlab_rb_style() {
    let store = make_store();
    let proc = KeyValueProcessor;

    let content = br#"# GitLab configuration
# See https://docs.gitlab.com

gitlab_rails['smtp_password'] = "my_secret_password"
gitlab_rails['smtp_user_name'] = "admin@corp.com"
gitlab_rails['smtp_address'] = "smtp.corp.com"
gitlab_rails['smtp_port'] = 587
gitlab_rails['db_password'] = 'db_secret_pass'

# External URL
external_url 'https://gitlab.example.com'

# Monitoring
prometheus_monitoring['enable'] = true
"#;

    let profile = FileTypeProfile::new(
        "key_value",
        vec![
            FieldRule::new("gitlab_rails['smtp_password']")
                .with_category(Category::Custom("password".into()))
                .with_label("smtp_password"),
            FieldRule::new("gitlab_rails['smtp_user_name']")
                .with_category(Category::Email)
                .with_label("smtp_user"),
            FieldRule::new("gitlab_rails['smtp_address']")
                .with_category(Category::Hostname)
                .with_label("smtp_host"),
            FieldRule::new("gitlab_rails['db_password']")
                .with_category(Category::Custom("password".into()))
                .with_label("db_password"),
        ],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    // Secrets replaced.
    assert!(
        !out.contains("my_secret_password"),
        "smtp password should be replaced"
    );
    assert!(
        !out.contains("admin@corp.com"),
        "smtp user should be replaced"
    );
    assert!(
        !out.contains("smtp.corp.com"),
        "smtp address should be replaced"
    );
    assert!(
        !out.contains("db_secret_pass"),
        "db password should be replaced"
    );

    // Comments preserved.
    assert!(out.contains("# GitLab configuration"));
    assert!(out.contains("# See https://docs.gitlab.com"));
    assert!(out.contains("# External URL"));
    assert!(out.contains("# Monitoring"));

    // Non-matched keys preserved.
    assert!(out.contains("gitlab_rails['smtp_port'] = 587"));
    assert!(out.contains("prometheus_monitoring['enable'] = true"));

    // Double-quoted values remain double-quoted.
    let password_line = out.lines().find(|l| l.contains("smtp_password")).unwrap();
    assert!(
        password_line.contains('"'),
        "quoting style should be preserved"
    );

    // Single-quoted values remain single-quoted.
    let db_line = out.lines().find(|l| l.contains("db_password")).unwrap();
    assert!(
        db_line.contains('\''),
        "single-quote style should be preserved"
    );
}

#[test]
fn key_value_one_way_no_original_survives() {
    let store = make_store();
    let proc = KeyValueProcessor;

    let secrets = [
        ("key1", "super_secret_1"),
        ("key2", "api_token_xyz"),
        ("key3", "database_password_123"),
    ];

    let content: String = secrets.iter().fold(String::new(), |mut acc, (k, v)| {
        use std::fmt::Write;
        let _ = writeln!(acc, "{} = \"{}\"", k, v);
        acc
    });

    let profile = FileTypeProfile::new(
        "key_value",
        vec![
            FieldRule::new("key1").with_category(Category::Custom("s".into())),
            FieldRule::new("key2").with_category(Category::Custom("s".into())),
            FieldRule::new("key3").with_category(Category::Custom("s".into())),
        ],
    );

    let result = proc.process(content.as_bytes(), &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    for (_, secret) in &secrets {
        assert!(
            !out.contains(secret),
            "original secret '{}' must not appear in output",
            secret
        );
    }
}

#[test]
fn key_value_deterministic_across_calls() {
    let store = make_store();
    let proc = KeyValueProcessor;

    let content = b"password = secret_value\n";
    let profile = FileTypeProfile::new(
        "key_value",
        vec![FieldRule::new("password").with_category(Category::Custom("pw".into()))],
    );

    let result1 = proc.process(content, &profile, &store).unwrap();
    let result2 = proc.process(content, &profile, &store).unwrap();

    assert_eq!(result1, result2, "same input should produce same output");
}

// ===========================================================================
// 3. JSON processor
// ===========================================================================

#[test]
fn json_nested_object_replacement() {
    let store = make_store();
    let proc = JsonProcessor;

    let content = br#"{
  "production": {
    "database": {
      "host": "db.internal.corp.com",
      "password": "prod_db_pass_2024",
      "port": 5432
    },
    "redis": {
      "password": "redis_secret_key"
    },
    "app_name": "my-app"
  }
}"#;

    let profile = FileTypeProfile::new(
        "json",
        vec![
            FieldRule::new("*.password").with_category(Category::Custom("pw".into())),
            FieldRule::new("production.database.host").with_category(Category::Hostname),
        ],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    assert!(!out.contains("prod_db_pass_2024"));
    assert!(!out.contains("redis_secret_key"));
    assert!(!out.contains("db.internal.corp.com"));
    assert!(out.contains("5432"));
    assert!(out.contains("my-app"));
}

// ===========================================================================
// 4. YAML processor
// ===========================================================================

#[test]
fn yaml_nested_replacement() {
    let store = make_store();
    let proc = YamlProcessor;

    let content = b"production:\n  database:\n    host: db.corp.com\n    password: yaml_secret\n  app_name: my-app\n";
    let profile = FileTypeProfile::new(
        "yaml",
        vec![
            FieldRule::new("production.database.password")
                .with_category(Category::Custom("pw".into())),
            FieldRule::new("production.database.host").with_category(Category::Hostname),
        ],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    assert!(!out.contains("yaml_secret"));
    assert!(!out.contains("db.corp.com"));
    assert!(out.contains("my-app"));
}

// ===========================================================================
// 5. XML processor
// ===========================================================================

#[test]
fn xml_mixed_elements_and_attributes() {
    let store = make_store();
    let proc = XmlProcessor;

    let content = br#"<config>
  <database host="db.corp.com" port="5432">
    <password>xml_secret_pass</password>
  </database>
  <app>
    <name>my-app</name>
  </app>
</config>"#;

    let profile = FileTypeProfile::new(
        "xml",
        vec![
            FieldRule::new("config/database/password").with_category(Category::Custom("pw".into())),
            FieldRule::new("config/database/@host").with_category(Category::Hostname),
        ],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    assert!(!out.contains("xml_secret_pass"));
    assert!(!out.contains("db.corp.com"));
    assert!(out.contains("5432"));
    assert!(out.contains("my-app"));
}

// ===========================================================================
// 6. CSV processor
// ===========================================================================

#[test]
fn csv_multi_column_replacement() {
    let store = make_store();
    let proc = CsvProcessor;

    let content = b"name,email,department,salary\n\
        Alice,alice@corp.com,Engineering,100000\n\
        Bob,bob@corp.com,Sales,95000\n";

    let profile = FileTypeProfile::new(
        "csv",
        vec![
            FieldRule::new("name").with_category(Category::Name),
            FieldRule::new("email").with_category(Category::Email),
        ],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    assert!(!out.contains("Alice"));
    assert!(!out.contains("Bob"));
    assert!(!out.contains("alice@corp.com"));
    assert!(!out.contains("bob@corp.com"));
    assert!(out.contains("Engineering"));
    assert!(out.contains("Sales"));
    assert!(out.contains("100000"));
}

// ===========================================================================
// 7. Cross-processor dedup consistency
// ===========================================================================

#[test]
fn shared_store_dedup_across_processors() {
    let store = make_store();
    let json_proc = JsonProcessor;
    let yaml_proc = YamlProcessor;

    let json_content = br#"{"password": "shared_secret"}"#;
    let yaml_content = b"password: shared_secret\n";

    let json_profile = FileTypeProfile::new(
        "json",
        vec![FieldRule::new("password").with_category(Category::Custom("pw".into()))],
    )
    .with_option("compact", "true");

    let yaml_profile = FileTypeProfile::new(
        "yaml",
        vec![FieldRule::new("password").with_category(Category::Custom("pw".into()))],
    );

    let json_result = json_proc
        .process(json_content, &json_profile, &store)
        .unwrap();
    let yaml_result = yaml_proc
        .process(yaml_content, &yaml_profile, &store)
        .unwrap();

    let json_out: serde_json::Value = serde_json::from_slice(&json_result).unwrap();
    let yaml_out: serde_yaml_ng::Value = serde_yaml_ng::from_slice(&yaml_result).unwrap();

    let json_val = json_out["password"].as_str().unwrap();
    let yaml_val = yaml_out["password"].as_str().unwrap();

    // Same original + same category → same replacement regardless of format.
    assert_eq!(json_val, yaml_val, "dedup should work across processors");
    assert_ne!(json_val, "shared_secret");
}

// ===========================================================================
// 8. Fallback: registry returns None, use StreamScanner
// ===========================================================================

#[test]
fn fallback_to_stream_scanner_when_no_processor_matches() {
    let store = make_store();
    let reg = ProcessorRegistry::with_builtins();

    let content = b"Contact alice@corp.com for details about server 10.0.1.42.";
    let profile = FileTypeProfile::new("unknown_format", vec![]);

    // Registry returns None.
    let proc_result = reg.process(content, &profile, &store).unwrap();
    assert!(proc_result.is_none(), "unknown format should not match");

    // Fall back to streaming scanner.
    let patterns = vec![
        ScanPattern::from_regex(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Category::Email,
            "email",
        )
        .unwrap(),
        ScanPattern::from_regex(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            Category::IpV4,
            "ipv4",
        )
        .unwrap(),
    ];

    let scanner = StreamScanner::new(patterns, store, ScanConfig::default()).unwrap();
    let (output, stats) = scanner.scan_bytes(content).unwrap();
    let out = String::from_utf8_lossy(&output);

    assert_eq!(stats.matches_found, 2);
    assert!(!out.contains("alice@corp.com"));
    assert!(!out.contains("10.0.1.42"));
}

// ===========================================================================
// 9. Integration with encrypted secrets + structured processor
// ===========================================================================

#[test]
fn processor_with_encrypted_secrets_shared_store() {
    // Encrypt a secrets file.
    let secrets_json = r#"[
        {
            "pattern": "corp_api_key_12345",
            "kind": "literal",
            "category": "custom:api_key",
            "label": "api_key"
        }
    ]"#;
    let password = "test-password-123!";
    let encrypted = encrypt_secrets(secrets_json.as_bytes(), password).unwrap();

    // Build a shared store.
    let store = make_store();

    // Build a scanner from encrypted secrets (for fallback).
    let scanner = StreamScanner::from_encrypted_secrets(
        &encrypted,
        password,
        Some(SecretsFormat::Json),
        Arc::clone(&store),
        ScanConfig::default(),
        vec![],
    )
    .unwrap()
    .0;

    // Also process a structured JSON config through the processor.
    let json_proc = JsonProcessor;
    let config_content = br#"{"api_key": "corp_api_key_12345", "port": 8080}"#;
    let profile = FileTypeProfile::new(
        "json",
        vec![FieldRule::new("api_key").with_category(Category::Custom("api_key".into()))],
    )
    .with_option("compact", "true");

    // Process the structured config.
    let proc_result = json_proc.process(config_content, &profile, &store).unwrap();
    let proc_out = String::from_utf8(proc_result).unwrap();
    assert!(!proc_out.contains("corp_api_key_12345"));

    // Also scan an unstructured file with the same store.
    let raw_content = b"The API key is corp_api_key_12345 in the config.";
    let (scan_output, stats) = scanner.scan_bytes(raw_content).unwrap();
    let scan_out = String::from_utf8_lossy(&scan_output);
    assert_eq!(stats.matches_found, 1);
    assert!(!scan_out.contains("corp_api_key_12345"));
}

// ===========================================================================
// 10. Profile matching by filename
// ===========================================================================

#[test]
fn profile_matches_by_extension() {
    let profile = FileTypeProfile::new("key_value", vec![])
        .with_extension(".rb")
        .with_extension(".conf");

    assert!(profile.matches_filename("gitlab.rb"));
    assert!(profile.matches_filename("/etc/app.conf"));
    assert!(!profile.matches_filename("config.json"));
    assert!(!profile.matches_filename("notes.txt"));
}

// ===========================================================================
// 11. Custom processor registration
// ===========================================================================

/// A dummy custom processor for testing extensibility.
struct DummyProcessor;

impl Processor for DummyProcessor {
    fn name(&self) -> &'static str {
        "dummy"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "dummy"
    }

    fn process(
        &self,
        content: &[u8],
        _profile: &FileTypeProfile,
        _store: &MappingStore,
    ) -> rust_sanitize::Result<Vec<u8>> {
        // Just uppercases everything (for testing).
        let text = String::from_utf8_lossy(content).to_uppercase();
        Ok(text.into_bytes())
    }
}

#[test]
fn custom_processor_registration() {
    let mut reg = ProcessorRegistry::with_builtins();
    reg.register(Arc::new(DummyProcessor));

    assert_eq!(reg.len(), 12); // 11 entries (10 processors + key-value alias) + dummy
    assert!(reg.get("dummy").is_some());

    let profile = FileTypeProfile::new("dummy", vec![]);
    let store = make_store();

    let result = reg.process(b"hello", &profile, &store).unwrap();
    assert_eq!(result.unwrap(), b"HELLO");
}

// ===========================================================================
// 12. One-way: replaced values are non-reversible
// ===========================================================================

#[test]
fn one_way_replacement_not_reversible() {
    let store = make_store();
    let proc = KeyValueProcessor;

    let content = b"password = original_secret_value\n";
    let profile = FileTypeProfile::new(
        "key_value",
        vec![FieldRule::new("password").with_category(Category::Custom("pw".into()))],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    // Extract the replacement.
    let replaced = out.split(" = ").nth(1).unwrap().trim();

    // There is no reverse lookup — MappingStore only has forward mapping.
    let reverse = store.forward_lookup(&Category::Custom("pw".into()), replaced);
    assert!(
        reverse.is_none(),
        "one-way store must not have reverse mapping from replacement to original"
    );
}

// ===========================================================================
// 13. CSV edge cases
// ===========================================================================

#[test]
fn csv_embedded_newlines_in_quoted_field() {
    let store = make_store();
    let proc = CsvProcessor;

    let content = b"name,email,note\n\"Alice\nBob\",alice@corp.com,\"line1\nline2\"\n";
    let profile = FileTypeProfile::new(
        "csv",
        vec![FieldRule::new("email").with_category(Category::Email)],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    // Email should be replaced.
    assert!(!out.contains("alice@corp.com"), "email must be replaced");
    // Multiline name field should be preserved (not mangled).
    assert!(
        out.contains("Alice\nBob") || out.contains("Alice\r\nBob"),
        "embedded newlines in name field should be preserved"
    );
    // Note field should be preserved.
    assert!(
        out.contains("line1\nline2") || out.contains("line1\r\nline2"),
        "embedded newlines in note field should be preserved"
    );
    // Header preserved.
    assert!(out.starts_with("name,email,note"));
}

#[test]
fn csv_quoted_empty_fields() {
    let store = make_store();
    let proc = CsvProcessor;

    let content = b"name,email\n\"\",alice@corp.com\nBob,\"\"\n";
    let profile = FileTypeProfile::new(
        "csv",
        vec![FieldRule::new("email").with_category(Category::Email)],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    // Email in first data row replaced.
    assert!(!out.contains("alice@corp.com"), "email must be replaced");
    // Bob preserved (name column not targeted).
    assert!(out.contains("Bob"), "non-targeted name should be preserved");
    // No crash, no malformed output.
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.len() >= 3, "should have header + 2 data rows");
}

#[test]
fn csv_crlf_line_endings() {
    let store = make_store();
    let proc = CsvProcessor;

    let content = b"name,email\r\nAlice,alice@corp.com\r\nBob,bob@corp.com\r\n";
    let profile = FileTypeProfile::new(
        "csv",
        vec![FieldRule::new("email").with_category(Category::Email)],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    assert!(
        !out.contains("alice@corp.com"),
        "first email must be replaced"
    );
    assert!(
        !out.contains("bob@corp.com"),
        "second email must be replaced"
    );
    assert!(out.contains("Alice"), "name should be preserved");
    assert!(out.contains("Bob"), "name should be preserved");
    // Output should be parseable CSV.
    let mut rdr = csv::ReaderBuilder::new().from_reader(out.as_bytes());
    let records: Vec<_> = rdr.records().collect();
    assert_eq!(records.len(), 2, "should have 2 data rows");
}

// ===========================================================================
// 14. XML edge cases
// ===========================================================================

#[test]
fn xml_billion_laughs_rejected() {
    let store = make_store();
    let proc = XmlProcessor;

    // Simplified billion-laughs-style payload with recursive entity expansion.
    let content = br#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root><value>&lol4;</value></root>"#;

    let profile = FileTypeProfile::new(
        "xml",
        vec![FieldRule::new("root/value").with_category(Category::Custom("val".into()))],
    );

    // The processor should either return an error or produce output quickly
    // (quick_xml does not expand external/parameter entities by default).
    // It must NOT hang or exhaust memory.
    let result = proc.process(content, &profile, &store);
    // We accept either an error (parse rejection) or successful processing
    // (entities treated as literal text). Either is safe.
    match result {
        Ok(output) => {
            // If it succeeded, it finished quickly and didn't blow up memory.
            assert!(output.len() < 1_000_000, "output must not explode in size");
        }
        Err(_) => {
            // Parse error is also acceptable — means the DOCTYPE was rejected.
        }
    }
}

#[test]
fn xml_html_entities_roundtrip() {
    let store = make_store();
    let proc = XmlProcessor;

    let content = br#"<config>
  <url>https://example.com?a=1&amp;b=2</url>
  <description>Use &lt;tag&gt; for &quot;escaping&quot;</description>
  <name>safe-value</name>
</config>"#;

    let profile = FileTypeProfile::new(
        "xml",
        vec![
            FieldRule::new("config/url").with_category(Category::Url),
            FieldRule::new("config/description").with_category(Category::Custom("desc".into())),
        ],
    );

    let result = proc.process(content, &profile, &store).unwrap();
    let out = String::from_utf8(result).unwrap();

    // Original values should be replaced.
    assert!(!out.contains("example.com"), "URL value should be replaced");
    assert!(
        !out.contains("escaping"),
        "description value should be replaced"
    );
    // Non-targeted field preserved.
    assert!(out.contains("safe-value"), "name should be preserved");
    // Output should be well-formed XML (no bare & or < in text).
    // Verify by re-parsing.
    let mut reader = quick_xml::Reader::from_str(&out);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => panic!("Output is not well-formed XML: {}", e),
            _ => {}
        }
        buf.clear();
    }
}
