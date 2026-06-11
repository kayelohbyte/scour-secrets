//! Integration tests for archive processing.
//!
//! Tests cover:
//! - Tar, tar.gz, and zip archives
//! - Structured processor dispatch (JSON inside archive)
//! - Streaming scanner fallback (plain text inside archive)
//! - Metadata preservation (timestamps, permissions)
//! - Dedup consistency across entries (same secret → same replacement)
//! - Mixed file types inside a single archive
//! - Empty archives
//! - Directory / non-file entry pass-through
//! - Secrets from memory (decrypted patterns via ScanPattern)
//! - Format auto-detection

use rust_sanitize::category::Category;
use rust_sanitize::generator::HmacGenerator;
use rust_sanitize::processor::archive::{ArchiveFilter, ArchiveFormat, ArchiveProcessor};
use rust_sanitize::processor::profile::{FieldRule, FileTypeProfile};
use rust_sanitize::processor::registry::ProcessorRegistry;
use rust_sanitize::scanner::{ScanConfig, ScanPattern, StreamScanner};
use rust_sanitize::store::MappingStore;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an `ArchiveProcessor` with email + literal patterns and a JSON profile.
fn make_processor() -> ArchiveProcessor {
    let gen = Arc::new(HmacGenerator::new([99u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));

    // Simulate "decrypted secrets from memory" — these are the same
    // patterns that would come from `DecryptedSecrets::into_patterns`.
    let patterns = vec![
        ScanPattern::from_regex(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Category::Email,
            "email",
        )
        .unwrap(),
        ScanPattern::from_literal(
            "TOP_SECRET_KEY_12345",
            Category::Custom("api_key".into()),
            "api_key",
        )
        .unwrap(),
        ScanPattern::from_regex(r"\b\d{3}-\d{2}-\d{4}\b", Category::Ssn, "ssn").unwrap(),
    ];

    let scanner =
        Arc::new(StreamScanner::new(patterns, Arc::clone(&store), ScanConfig::default()).unwrap());
    let registry = Arc::new(ProcessorRegistry::with_builtins());

    let profiles = vec![
        FileTypeProfile::new(
            "json",
            vec![FieldRule::new("*").with_category(Category::Custom("field".into()))],
        )
        .with_extension(".json"),
        FileTypeProfile::new(
            "yaml",
            vec![FieldRule::new("*").with_category(Category::Custom("field".into()))],
        )
        .with_extension(".yml")
        .with_extension(".yaml"),
    ];

    ArchiveProcessor::new(registry, scanner, store, profiles)
}

/// Build a tar archive from `(filename, content)` pairs.
fn make_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        for (name, data) in entries {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_mtime(1_700_000_000);
            hdr.set_cksum();
            builder.append_data(&mut hdr, *name, *data).unwrap();
        }
        builder.finish().unwrap();
    }
    buf
}

/// Build a zip archive from `(filename, content)` pairs.
fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        for (name, data) in entries {
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip.start_file(*name, opts).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    buf.into_inner()
}

/// Build a tar.gz archive from `(filename, content)` pairs.
fn make_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let tar_data = make_tar(entries);
    let mut gz_buf = Vec::new();
    {
        let mut enc = flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::fast());
        enc.write_all(&tar_data).unwrap();
        enc.finish().unwrap();
    }
    gz_buf
}

/// Read all file entries from a tar as `(name, content)` pairs.
fn read_tar(data: &[u8]) -> Vec<(String, String)> {
    let mut archive = tar::Archive::new(data);
    let mut out = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut e = entry.unwrap();
        if e.header().entry_type().is_file() {
            let name = e.path().unwrap().to_string_lossy().to_string();
            let mut content = String::new();
            e.read_to_string(&mut content).unwrap();
            out.push((name, content));
        }
    }
    out
}

/// Read all file entries from a zip as `(name, content)` pairs.
fn read_zip(data: &[u8]) -> Vec<(String, String)> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).unwrap();
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        if !entry.is_dir() {
            let name = entry.name().to_string();
            let mut content = String::new();
            entry.read_to_string(&mut content).unwrap();
            out.push((name, content));
        }
    }
    out
}

// ===========================================================================
// 1. Tar — scanner fallback (no profile match)
// ===========================================================================

#[test]
fn tar_scanner_replaces_email() {
    let proc = make_processor();
    let input = make_tar(&[("log.txt", b"User alice@corp.com logged in")]);

    let mut output = Vec::new();
    let stats = proc.process_tar(&input[..], &mut output).unwrap();

    assert_eq!(stats.files_processed, 1);
    assert_eq!(stats.scanner_fallback, 1);

    let files = read_tar(&output);
    assert!(!files[0].1.contains("alice@corp.com"));
}

#[test]
fn tar_scanner_replaces_literal_secret() {
    let proc = make_processor();
    let input = make_tar(&[("env.txt", b"API_KEY=TOP_SECRET_KEY_12345")]);

    let mut output = Vec::new();
    let _stats = proc.process_tar(&input[..], &mut output).unwrap();

    let files = read_tar(&output);
    assert!(!files[0].1.contains("TOP_SECRET_KEY_12345"));
}

#[test]
fn tar_scanner_replaces_ssn() {
    let proc = make_processor();
    let input = make_tar(&[("pii.csv", b"name,ssn\nAlice,123-45-6789\n")]);

    let mut output = Vec::new();
    proc.process_tar(&input[..], &mut output).unwrap();

    let files = read_tar(&output);
    assert!(!files[0].1.contains("123-45-6789"));
}

// ===========================================================================
// 2. Tar — structured processor (JSON profile)
// ===========================================================================

#[test]
fn tar_structured_json() {
    let proc = make_processor();
    let json = br#"{"user": "alice@corp.com", "token": "TOP_SECRET_KEY_12345"}"#;
    let input = make_tar(&[("config.json", json)]);

    let mut output = Vec::new();
    let stats = proc.process_tar(&input[..], &mut output).unwrap();

    assert_eq!(stats.structured_hits, 1);
    assert_eq!(stats.scanner_fallback, 0);

    let files = read_tar(&output);
    assert!(!files[0].1.contains("alice@corp.com"));
    assert!(!files[0].1.contains("TOP_SECRET_KEY_12345"));
}

// ===========================================================================
// 3. Tar — mixed file types
// ===========================================================================

#[test]
fn tar_mixed_files() {
    let proc = make_processor();
    let input = make_tar(&[
        ("readme.md", b"Email: alice@corp.com"),
        ("settings.json", br#"{"db_pass": "s3cret"}"#),
        ("notes.txt", b"SSN is 123-45-6789"),
    ]);

    let mut output = Vec::new();
    let stats = proc.process_tar(&input[..], &mut output).unwrap();

    assert_eq!(stats.files_processed, 3);
    assert_eq!(stats.structured_hits, 1); // JSON
    assert_eq!(stats.scanner_fallback, 2); // .md + .txt

    let files = read_tar(&output);
    assert!(!files[0].1.contains("alice@corp.com"));
    assert!(!files[2].1.contains("123-45-6789"));
}

// ===========================================================================
// 4. Tar — metadata preservation
// ===========================================================================

#[test]
fn tar_preserves_mtime_and_mode() {
    let proc = make_processor();
    let input = make_tar(&[("secret.txt", b"TOP_SECRET_KEY_12345")]);

    let mut output = Vec::new();
    proc.process_tar(&input[..], &mut output).unwrap();

    let mut archive = tar::Archive::new(&output[..]);
    for entry in archive.entries().unwrap() {
        let e = entry.unwrap();
        assert_eq!(e.header().mode().unwrap(), 0o644);
        assert_eq!(e.header().mtime().unwrap(), 1_700_000_000);
    }
}

// ===========================================================================
// 5. Tar — dedup consistency
// ===========================================================================

#[test]
fn tar_dedup_same_secret_same_replacement() {
    let proc = make_processor();
    let input = make_tar(&[("a.txt", b"alice@corp.com"), ("b.txt", b"alice@corp.com")]);

    let mut output = Vec::new();
    proc.process_tar(&input[..], &mut output).unwrap();

    let files = read_tar(&output);
    assert_eq!(files[0].1, files[1].1, "same secret → same replacement");
    assert!(!files[0].1.contains("alice@corp.com"));
}

// ===========================================================================
// 6. Tar.gz — full round-trip
// ===========================================================================

#[test]
fn tar_gz_sanitizes_and_preserves_format() {
    let proc = make_processor();
    let input = make_tar_gz(&[(
        "data.txt",
        b"Contact alice@corp.com with key TOP_SECRET_KEY_12345",
    )]);

    let mut output = Vec::new();
    let stats = proc.process_tar_gz(&input[..], &mut output).unwrap();

    assert_eq!(stats.files_processed, 1);

    // Decompress output and verify.
    let decoder = flate2::read::GzDecoder::new(&output[..]);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().unwrap() {
        let mut e = entry.unwrap();
        let mut content = String::new();
        e.read_to_string(&mut content).unwrap();
        assert!(!content.contains("alice@corp.com"));
        assert!(!content.contains("TOP_SECRET_KEY_12345"));
    }
}

#[test]
fn tar_gz_preserves_metadata() {
    let proc = make_processor();
    let input = make_tar_gz(&[("f.txt", b"hello world")]);

    let mut output = Vec::new();
    proc.process_tar_gz(&input[..], &mut output).unwrap();

    let decoder = flate2::read::GzDecoder::new(&output[..]);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().unwrap() {
        let e = entry.unwrap();
        assert_eq!(e.header().mode().unwrap(), 0o644);
        assert_eq!(e.header().mtime().unwrap(), 1_700_000_000);
    }
}

// ===========================================================================
// 7. Zip — scanner fallback
// ===========================================================================

#[test]
fn zip_scanner_replaces_secrets() {
    let proc = make_processor();
    let input = make_zip(&[("report.txt", b"SSN: 123-45-6789, Email: alice@corp.com")]);

    let reader = Cursor::new(input);
    let mut writer = Cursor::new(Vec::new());
    let stats = proc.process_zip(reader, &mut writer).unwrap();

    assert_eq!(stats.files_processed, 1);
    assert_eq!(stats.scanner_fallback, 1);

    let files = read_zip(&writer.into_inner());
    assert!(!files[0].1.contains("123-45-6789"));
    assert!(!files[0].1.contains("alice@corp.com"));
}

// ===========================================================================
// 8. Zip — structured processor (JSON)
// ===========================================================================

#[test]
fn zip_structured_json() {
    let proc = make_processor();
    let json = br#"{"api_key": "TOP_SECRET_KEY_12345"}"#;
    let input = make_zip(&[("config.json", json)]);

    let reader = Cursor::new(input);
    let mut writer = Cursor::new(Vec::new());
    let stats = proc.process_zip(reader, &mut writer).unwrap();

    assert_eq!(stats.structured_hits, 1);

    let files = read_zip(&writer.into_inner());
    assert!(!files[0].1.contains("TOP_SECRET_KEY_12345"));
}

// ===========================================================================
// 9. Zip — mixed files + dedup
// ===========================================================================

#[test]
fn zip_mixed_dedup() {
    let proc = make_processor();
    let input = make_zip(&[
        ("a.txt", b"alice@corp.com"),
        ("b.json", br#"{"email": "alice@corp.com"}"#),
        ("c.txt", b"alice@corp.com"),
    ]);

    let reader = Cursor::new(input);
    let mut writer = Cursor::new(Vec::new());
    let stats = proc.process_zip(reader, &mut writer).unwrap();

    assert_eq!(stats.files_processed, 3);
    assert_eq!(stats.structured_hits, 1);
    assert_eq!(stats.scanner_fallback, 2);

    let files = read_zip(&writer.into_inner());
    // a.txt and c.txt should have the same replacement.
    assert_eq!(files[0].1, files[2].1);
    assert!(!files[0].1.contains("alice@corp.com"));
}

// ===========================================================================
// 10. Zip — directory pass-through
// ===========================================================================

#[test]
fn zip_directory_passthrough() {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        zip.add_directory("mydir/", zip::write::SimpleFileOptions::default())
            .unwrap();
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("mydir/data.txt", opts).unwrap();
        zip.write_all(b"alice@corp.com").unwrap();
        zip.finish().unwrap();
    }

    let proc = make_processor();
    let reader = Cursor::new(buf.into_inner());
    let mut writer = Cursor::new(Vec::new());
    let stats = proc.process_zip(reader, &mut writer).unwrap();

    assert_eq!(stats.entries_skipped, 1);
    assert_eq!(stats.files_processed, 1);
}

// ===========================================================================
// 11. Format detection
// ===========================================================================

#[test]
fn archive_format_detection() {
    assert_eq!(ArchiveFormat::from_path("a.tar"), Some(ArchiveFormat::Tar));
    assert_eq!(
        ArchiveFormat::from_path("a.tar.gz"),
        Some(ArchiveFormat::TarGz)
    );
    assert_eq!(
        ArchiveFormat::from_path("a.tgz"),
        Some(ArchiveFormat::TarGz)
    );
    assert_eq!(ArchiveFormat::from_path("a.zip"), Some(ArchiveFormat::Zip));
    assert_eq!(
        ArchiveFormat::from_path("A.TAR.GZ"),
        Some(ArchiveFormat::TarGz)
    );
    assert_eq!(ArchiveFormat::from_path("photo.jpg"), None);
    assert_eq!(ArchiveFormat::from_path(""), None);
}

// ===========================================================================
// 12. Empty archives
// ===========================================================================

#[test]
fn tar_empty() {
    let proc = make_processor();
    let input = make_tar(&[]);
    let mut output = Vec::new();
    let stats = proc.process_tar(&input[..], &mut output).unwrap();
    assert_eq!(stats.files_processed, 0);
}

#[test]
fn zip_empty() {
    let proc = make_processor();
    let input = make_zip(&[]);
    let reader = Cursor::new(input);
    let mut writer = Cursor::new(Vec::new());
    let stats = proc.process_zip(reader, &mut writer).unwrap();
    assert_eq!(stats.files_processed, 0);
}

#[test]
fn tar_gz_empty() {
    let proc = make_processor();
    let input = make_tar_gz(&[]);
    let mut output = Vec::new();
    let stats = proc.process_tar_gz(&input[..], &mut output).unwrap();
    assert_eq!(stats.files_processed, 0);
}

// ===========================================================================
// 13. Auto-dispatch via ArchiveFormat
// ===========================================================================

#[test]
fn auto_dispatch_tar() {
    let proc = make_processor();
    let tar_data = make_tar(&[("f.txt", b"TOP_SECRET_KEY_12345")]);
    let reader = Cursor::new(tar_data);
    let writer = Cursor::new(Vec::new());
    let stats = proc.process(reader, writer, ArchiveFormat::Tar).unwrap();
    assert_eq!(stats.files_processed, 1);
}

#[test]
fn auto_dispatch_zip() {
    let proc = make_processor();
    let zip_data = make_zip(&[("f.txt", b"TOP_SECRET_KEY_12345")]);
    let reader = Cursor::new(zip_data);
    let mut writer = Cursor::new(Vec::new());
    let stats = proc
        .process(reader, &mut writer, ArchiveFormat::Zip)
        .unwrap();
    assert_eq!(stats.files_processed, 1);
}

// ===========================================================================
// 14. One-way only — no original data in output
// ===========================================================================

#[test]
fn one_way_no_original_data_in_tar_output() {
    let proc = make_processor();
    let secrets = b"alice@corp.com\n123-45-6789\nTOP_SECRET_KEY_12345\n";
    let input = make_tar(&[("all_secrets.txt", secrets)]);

    let mut output = Vec::new();
    proc.process_tar(&input[..], &mut output).unwrap();

    let raw = String::from_utf8_lossy(&output);
    assert!(!raw.contains("alice@corp.com"));
    assert!(!raw.contains("123-45-6789"));
    assert!(!raw.contains("TOP_SECRET_KEY_12345"));
}

#[test]
fn one_way_no_original_data_in_zip_output() {
    let proc = make_processor();
    let secrets = b"alice@corp.com\n123-45-6789\nTOP_SECRET_KEY_12345\n";
    let input = make_zip(&[("all_secrets.txt", secrets)]);

    let reader = Cursor::new(input);
    let mut writer = Cursor::new(Vec::new());
    proc.process_zip(reader, &mut writer).unwrap();

    let out = writer.into_inner();
    // Check within the extracted content.
    let files = read_zip(&out);
    assert!(!files[0].1.contains("alice@corp.com"));
    assert!(!files[0].1.contains("123-45-6789"));
    assert!(!files[0].1.contains("TOP_SECRET_KEY_12345"));
}

// ===========================================================================
// 15. Tar — symlink entry preservation
// ===========================================================================

#[test]
fn tar_symlink_preserved() {
    // Build a tar with a regular file and a symlink entry.
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);

        // Regular file with a secret.
        let data = b"Contact alice@corp.com for help";
        let mut hdr = tar::Header::new_gnu();
        hdr.set_size(data.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_mtime(1_700_000_000);
        hdr.set_entry_type(tar::EntryType::Regular);
        hdr.set_cksum();
        builder
            .append_data(&mut hdr, "data.txt", &data[..])
            .unwrap();

        // Symlink entry pointing to data.txt.
        let mut sym_hdr = tar::Header::new_gnu();
        sym_hdr.set_size(0);
        sym_hdr.set_mode(0o777);
        sym_hdr.set_mtime(1_700_000_000);
        sym_hdr.set_entry_type(tar::EntryType::Symlink);
        sym_hdr.set_link_name("data.txt").unwrap();
        sym_hdr.set_cksum();
        builder
            .append_data(&mut sym_hdr, "link.txt", &[][..])
            .unwrap();

        builder.finish().unwrap();
    }

    let proc = make_processor();
    let mut output = Vec::new();
    let stats = proc.process_tar(&buf[..], &mut output).unwrap();

    // The regular file should be processed.
    assert!(stats.files_processed >= 1);

    // Read back and verify symlink is preserved in output.
    let mut archive = tar::Archive::new(&output[..]);
    let mut found_regular = false;
    let mut found_symlink = false;
    for entry in archive.entries().unwrap() {
        let e = entry.unwrap();
        let path = e.path().unwrap().to_string_lossy().to_string();
        match e.header().entry_type() {
            tar::EntryType::Regular => {
                assert_eq!(path, "data.txt");
                found_regular = true;
            }
            tar::EntryType::Symlink => {
                assert_eq!(path, "link.txt");
                let link = e.link_name().unwrap().unwrap();
                assert_eq!(link.to_string_lossy(), "data.txt");
                found_symlink = true;
            }
            _ => {}
        }
    }
    assert!(found_regular, "regular file should be in output");
    assert!(found_symlink, "symlink should be preserved in output");
}

// ===========================================================================
// 16. Nested archive — recursive processing
// ===========================================================================

#[test]
fn nested_tar_gz_in_zip_sanitized() {
    // Create an inner tar.gz containing secrets.
    let inner_tar_gz = make_tar_gz(&[(
        "secret.txt",
        b"The key is TOP_SECRET_KEY_12345 and email alice@corp.com",
    )]);

    // Wrap it in a zip.
    let zip_data = make_zip(&[
        ("inner.tar.gz", &inner_tar_gz),
        ("plain.txt", b"Contact bob@corp.com"),
    ]);

    let proc = make_processor();
    let reader = Cursor::new(zip_data);
    let mut writer = Cursor::new(Vec::new());
    let stats = proc.process_zip(reader, &mut writer).unwrap();

    // plain.txt counts as files_processed; inner.tar.gz is a nested archive
    // whose inner file also counts.
    assert!(
        stats.files_processed >= 2,
        "both outer and inner files processed"
    );
    assert_eq!(stats.nested_archives, 1, "one nested archive detected");

    // Read back the output zip.
    let out_data = writer.into_inner();
    let mut out_zip = zip::ZipArchive::new(Cursor::new(&out_data)).unwrap();

    // The plain text file should have its email replaced.
    {
        let mut entry = out_zip.by_name("plain.txt").unwrap();
        let mut content = String::new();
        entry.read_to_string(&mut content).unwrap();
        assert!(
            !content.contains("bob@corp.com"),
            "plain.txt email should be replaced"
        );
    }

    // The inner tar.gz should now be recursively sanitized.
    {
        let mut entry = out_zip.by_name("inner.tar.gz").unwrap();
        let mut inner_bytes = Vec::new();
        entry.read_to_end(&mut inner_bytes).unwrap();

        // Decompress the inner tar.gz.
        let decoder = flate2::read::GzDecoder::new(&inner_bytes[..]);
        let mut inner_archive = tar::Archive::new(decoder);
        for inner_entry in inner_archive.entries().unwrap() {
            let mut e = inner_entry.unwrap();
            let mut content = String::new();
            e.read_to_string(&mut content).unwrap();
            assert!(
                !content.contains("TOP_SECRET_KEY_12345"),
                "nested archive secrets SHOULD be sanitized"
            );
            assert!(
                !content.contains("alice@corp.com"),
                "nested archive emails SHOULD be sanitized"
            );
        }
    }
}

#[test]
fn nested_zip_in_tar_sanitized() {
    // Create an inner zip containing a secret.
    let inner_zip = make_zip(&[("inner_secret.txt", b"token TOP_SECRET_KEY_12345 here")]);

    // Wrap it in a tar.
    let tar_data = make_tar(&[
        ("inner.zip", &inner_zip),
        ("outer.txt", b"email alice@corp.com"),
    ]);

    let proc = make_processor();
    let mut output = Vec::new();
    let stats = proc.process_tar(&tar_data[..], &mut output).unwrap();

    assert!(stats.files_processed >= 2);
    assert_eq!(stats.nested_archives, 1);

    // Read back the tar output.
    let mut archive = tar::Archive::new(&output[..]);
    for entry in archive.entries().unwrap() {
        let mut e = entry.unwrap();
        let path = e.path().unwrap().to_string_lossy().to_string();
        if path == "outer.txt" {
            let mut content = String::new();
            e.read_to_string(&mut content).unwrap();
            assert!(
                !content.contains("alice@corp.com"),
                "outer email should be sanitized"
            );
        } else if path == "inner.zip" {
            let mut inner_bytes = Vec::new();
            e.read_to_end(&mut inner_bytes).unwrap();
            let files = read_zip(&inner_bytes);
            for (name, content) in &files {
                assert!(
                    !content.contains("TOP_SECRET_KEY_12345"),
                    "nested zip entry '{name}' secret should be sanitized"
                );
            }
        }
    }
}

#[test]
fn nested_dedup_consistency_across_levels() {
    // Same secret at outer and inner levels should get the same replacement.
    let inner_tar = make_tar(&[("inner.txt", b"secret alice@corp.com in inner")]);
    let inner_tar_gz = {
        let mut gz_buf = Vec::new();
        let mut enc = flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::fast());
        enc.write_all(&inner_tar).unwrap();
        enc.finish().unwrap();
        gz_buf
    };

    let zip_data = make_zip(&[
        ("nested.tar.gz", &inner_tar_gz),
        ("outer.txt", b"contact alice@corp.com here"),
    ]);

    let proc = make_processor();
    let reader = Cursor::new(zip_data);
    let mut writer = Cursor::new(Vec::new());
    proc.process_zip(reader, &mut writer).unwrap();

    let out_data = writer.into_inner();
    let mut out_zip = zip::ZipArchive::new(Cursor::new(&out_data)).unwrap();

    // Extract outer replacement.
    let outer_content = {
        let mut entry = out_zip.by_name("outer.txt").unwrap();
        let mut s = String::new();
        entry.read_to_string(&mut s).unwrap();
        s
    };

    // Extract inner replacement.
    let inner_content = {
        let mut entry = out_zip.by_name("nested.tar.gz").unwrap();
        let mut inner_bytes = Vec::new();
        entry.read_to_end(&mut inner_bytes).unwrap();
        let decoder = flate2::read::GzDecoder::new(&inner_bytes[..]);
        let mut inner_archive = tar::Archive::new(decoder);
        let mut content = String::new();
        for inner_entry in inner_archive.entries().unwrap() {
            let mut e = inner_entry.unwrap();
            e.read_to_string(&mut content).unwrap();
        }
        content
    };

    // Neither should contain the original.
    assert!(!outer_content.contains("alice@corp.com"));
    assert!(!inner_content.contains("alice@corp.com"));

    // Both should contain the same replacement (dedup via shared MappingStore).
    // Extract the replacement by finding what replaced alice@corp.com.
    // The replacement has the same length as "alice@corp.com" (14 chars) and
    // contains "@corp.com" (email category preserves domain).
    // We just verify neither contains the original and both share a common
    // non-trivial substring (the replacement).
    let outer_words: Vec<&str> = outer_content.split_whitespace().collect();
    let inner_words: Vec<&str> = inner_content.split_whitespace().collect();
    // Find the email-like word in each.
    let outer_email = outer_words.iter().find(|w| w.contains('@')).unwrap();
    let inner_email = inner_words.iter().find(|w| w.contains('@')).unwrap();
    assert_eq!(
        outer_email, inner_email,
        "same secret → same replacement at all nesting levels"
    );
}

#[test]
fn nested_archive_stats_aggregated() {
    // inner tar.gz has 2 files; outer zip has 1 plain file + the nested archive.
    let inner_tar_gz = make_tar_gz(&[
        ("a.txt", b"secret alice@corp.com"),
        ("b.txt", b"token TOP_SECRET_KEY_12345"),
    ]);

    let zip_data = make_zip(&[
        ("archive.tar.gz", &inner_tar_gz),
        ("plain.txt", b"contact bob@corp.com"),
    ]);

    let proc = make_processor();
    let reader = Cursor::new(zip_data);
    let mut writer = Cursor::new(Vec::new());
    let stats = proc.process_zip(reader, &mut writer).unwrap();

    // plain.txt (1) + inner files (2) + nested entry itself (1) = 4 files_processed
    assert_eq!(stats.files_processed, 4, "files from all levels counted");
    assert_eq!(stats.nested_archives, 1, "one nested archive entry");
    assert!(
        stats.file_methods.contains_key("archive.tar.gz"),
        "nested entry recorded in file_methods"
    );
    assert!(
        stats.file_methods["archive.tar.gz"].starts_with("nested:"),
        "method should be nested:*"
    );
}

#[test]
fn nested_archive_depth_limit_exceeded() {
    // Build a deeply nested archive that exceeds the default max_depth of 5.
    // Nesting: outer_zip(0) → l1.tar.gz(1) → l2.zip(2) → l3.tar(3) → l4.zip(4) → l5.tar.gz(5) → l6.zip
    // At depth 5, l6.zip triggers the check: depth(5) >= max_depth(5) → error.
    let l6_zip = make_zip(&[("deep.txt", b"TOP_SECRET_KEY_12345")]);
    let l5_tar_gz = {
        let l5_tar = make_tar(&[("l6.zip", &l6_zip)]);
        let mut gz_buf = Vec::new();
        let mut enc = flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::fast());
        enc.write_all(&l5_tar).unwrap();
        enc.finish().unwrap();
        gz_buf
    };
    let l4_zip = make_zip(&[("l5.tar.gz", &l5_tar_gz)]);
    let l3_tar = make_tar(&[("l4.zip", &l4_zip)]);
    let l2_zip = make_zip(&[("l3.tar", &l3_tar)]);
    let l1_tar_gz = {
        let l1_tar = make_tar(&[("l2.zip", &l2_zip)]);
        let mut gz_buf = Vec::new();
        let mut enc = flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::fast());
        enc.write_all(&l1_tar).unwrap();
        enc.finish().unwrap();
        gz_buf
    };
    let outer_zip = make_zip(&[("l1.tar.gz", &l1_tar_gz)]);

    let proc = make_processor(); // default max_depth = 5
    let reader = Cursor::new(outer_zip);
    let mut writer = Cursor::new(Vec::new());
    let result = proc.process_zip(reader, &mut writer);

    assert!(result.is_err(), "should fail when nesting depth exceeded");
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("nesting depth"),
        "error message should mention nesting depth: {msg}"
    );
}

#[test]
fn nested_archive_custom_depth_limit() {
    // Same 6-level archive that fails with the default max_depth=5,
    // but with max_depth=7 → should succeed.
    let l6_zip = make_zip(&[("deep.txt", b"TOP_SECRET_KEY_12345")]);
    let l5_tar_gz = {
        let l5_tar = make_tar(&[("l6.zip", &l6_zip)]);
        let mut gz_buf = Vec::new();
        let mut enc = flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::fast());
        enc.write_all(&l5_tar).unwrap();
        enc.finish().unwrap();
        gz_buf
    };
    let l4_zip = make_zip(&[("l5.tar.gz", &l5_tar_gz)]);
    let l3_tar = make_tar(&[("l4.zip", &l4_zip)]);
    let l2_zip = make_zip(&[("l3.tar", &l3_tar)]);
    let l1_tar_gz = {
        let l1_tar = make_tar(&[("l2.zip", &l2_zip)]);
        let mut gz_buf = Vec::new();
        let mut enc = flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::fast());
        enc.write_all(&l1_tar).unwrap();
        enc.finish().unwrap();
        gz_buf
    };
    let outer_zip = make_zip(&[("l1.tar.gz", &l1_tar_gz)]);

    let gen = Arc::new(rust_sanitize::generator::HmacGenerator::new([99u8; 32]));
    let store = Arc::new(rust_sanitize::store::MappingStore::new(gen, None));
    let patterns = vec![ScanPattern::from_literal(
        "TOP_SECRET_KEY_12345",
        Category::Custom("api_key".into()),
        "api_key",
    )
    .unwrap()];
    let scanner = Arc::new(
        rust_sanitize::scanner::StreamScanner::new(
            patterns,
            Arc::clone(&store),
            ScanConfig::default(),
        )
        .unwrap(),
    );
    let registry = Arc::new(rust_sanitize::processor::registry::ProcessorRegistry::with_builtins());
    let proc = ArchiveProcessor::new(registry, scanner, store, vec![]).with_max_depth(7);

    let reader = Cursor::new(outer_zip);
    let mut writer = Cursor::new(Vec::new());
    let result = proc.process_zip(reader, &mut writer);

    assert!(
        result.is_ok(),
        "should succeed with depth limit 7: {:?}",
        result.err()
    );
    let stats = result.unwrap();
    assert!(
        stats.nested_archives >= 5,
        "5+ nested archives processed (l1.tar.gz through l5.tar.gz): got {}",
        stats.nested_archives
    );
}

#[test]
fn nested_archive_metadata_preserved() {
    // Verify that metadata (mtime, mode) is preserved for the nested entry
    // in the outer archive.
    let inner_tar_gz = make_tar_gz(&[("secret.txt", b"email alice@corp.com")]);

    // Build tar with specific metadata for the nested entry.
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        let mut hdr = tar::Header::new_gnu();
        hdr.set_size(inner_tar_gz.len() as u64);
        hdr.set_mode(0o755);
        hdr.set_mtime(1_700_000_000);
        hdr.set_cksum();
        builder
            .append_data(&mut hdr, "nested.tar.gz", &inner_tar_gz[..])
            .unwrap();
        builder.finish().unwrap();
    }

    let proc = make_processor();
    let mut output = Vec::new();
    proc.process_tar(&buf[..], &mut output).unwrap();

    // Verify metadata in output.
    let mut archive = tar::Archive::new(&output[..]);
    for entry in archive.entries().unwrap() {
        let e = entry.unwrap();
        let hdr = e.header();
        let path = e.path().unwrap().to_string_lossy().to_string();
        if path == "nested.tar.gz" {
            assert_eq!(hdr.mode().unwrap(), 0o755, "mode preserved");
            assert_eq!(hdr.mtime().unwrap(), 1_700_000_000, "mtime preserved");
        }
    }
}

// ===========================================================================
// ArchiveFilter tests
// ===========================================================================

/// Helper: make a bare ArchiveProcessor with no secrets patterns (filter tests
/// only care about which entries survive, not their content).
fn make_filter_processor(filter: ArchiveFilter) -> ArchiveProcessor {
    let gen = Arc::new(HmacGenerator::new([1u8; 32]));
    let store = Arc::new(MappingStore::new(gen, None));
    let scanner =
        Arc::new(StreamScanner::new(vec![], Arc::clone(&store), ScanConfig::default()).unwrap());
    let registry = Arc::new(ProcessorRegistry::with_builtins());
    ArchiveProcessor::new(registry, scanner, store, vec![]).with_filter(filter)
}

fn entry_names(files: &[(String, String)]) -> Vec<&str> {
    files.iter().map(|(n, _)| n.as_str()).collect()
}

#[test]
fn tar_only_exact_path() {
    let proc = make_filter_processor(ArchiveFilter::new(vec!["a.txt".into()], vec![]).unwrap());
    let input = make_tar(&[("a.txt", b"hello"), ("b.txt", b"world")]);
    let mut out = Vec::new();
    let stats = proc.process_tar(&input[..], &mut out).unwrap();
    let files = read_tar(&out);
    assert_eq!(entry_names(&files), vec!["a.txt"]);
    assert_eq!(stats.entries_filtered, 1);
    assert_eq!(stats.files_processed, 1);
}

#[test]
fn tar_exclude_exact_path() {
    let proc = make_filter_processor(ArchiveFilter::new(vec![], vec!["b.txt".into()]).unwrap());
    let input = make_tar(&[("a.txt", b"hello"), ("b.txt", b"world")]);
    let mut out = Vec::new();
    let stats = proc.process_tar(&input[..], &mut out).unwrap();
    let files = read_tar(&out);
    assert_eq!(entry_names(&files), vec!["a.txt"]);
    assert_eq!(stats.entries_filtered, 1);
}

#[test]
fn tar_only_glob_star() {
    // *.json matches root-level json only (does NOT cross /)
    let proc = make_filter_processor(ArchiveFilter::new(vec!["*.json".into()], vec![]).unwrap());
    let input = make_tar(&[
        ("a.json", b"{}"),
        ("b.txt", b"text"),
        ("sub/c.json", b"{}"), // should NOT match *.json
    ]);
    let mut out = Vec::new();
    let stats = proc.process_tar(&input[..], &mut out).unwrap();
    let files = read_tar(&out);
    assert_eq!(entry_names(&files), vec!["a.json"]);
    assert_eq!(stats.entries_filtered, 2);
}

#[test]
fn tar_only_glob_double_star() {
    // **/*.json matches json at any depth
    let proc = make_filter_processor(ArchiveFilter::new(vec!["**/*.json".into()], vec![]).unwrap());
    let input = make_tar(&[
        ("a.json", b"{}"),
        ("sub/b.json", b"{}"),
        ("sub/c.txt", b"text"),
    ]);
    let mut out = Vec::new();
    let stats = proc.process_tar(&input[..], &mut out).unwrap();
    let files = read_tar(&out);
    let names = entry_names(&files);
    assert!(names.contains(&"a.json"), "a.json missing: {names:?}");
    assert!(
        names.contains(&"sub/b.json"),
        "sub/b.json missing: {names:?}"
    );
    assert!(
        !names.contains(&"sub/c.txt"),
        "sub/c.txt should be filtered: {names:?}"
    );
    assert_eq!(stats.entries_filtered, 1);
}

#[test]
fn tar_only_directory_prefix() {
    // "config/" prefix: keeps entries under config/, not at root level
    let proc = make_filter_processor(ArchiveFilter::new(vec!["config/".into()], vec![]).unwrap());
    let input = make_tar(&[
        ("config/a.txt", b"cfg"),
        ("config/sub/b.txt", b"cfg2"),
        ("other.txt", b"other"),
    ]);
    let mut out = Vec::new();
    let stats = proc.process_tar(&input[..], &mut out).unwrap();
    let files = read_tar(&out);
    let names = entry_names(&files);
    assert!(names.contains(&"config/a.txt"));
    assert!(names.contains(&"config/sub/b.txt"));
    assert!(!names.contains(&"other.txt"));
    assert_eq!(stats.entries_filtered, 1);
}

#[test]
fn tar_only_and_exclude_combined() {
    // --only "*.json" --exclude "secret.json": all json except secret.json
    let proc = make_filter_processor(
        ArchiveFilter::new(vec!["*.json".into()], vec!["secret.json".into()]).unwrap(),
    );
    let input = make_tar(&[
        ("data.json", b"{}"),
        ("secret.json", b"{}"),
        ("readme.txt", b"text"),
    ]);
    let mut out = Vec::new();
    let stats = proc.process_tar(&input[..], &mut out).unwrap();
    let files = read_tar(&out);
    let names = entry_names(&files);
    assert_eq!(names, vec!["data.json"]);
    assert_eq!(stats.entries_filtered, 2);
}

#[test]
fn zip_only_exact_path() {
    let proc = make_filter_processor(ArchiveFilter::new(vec!["a.txt".into()], vec![]).unwrap());
    let input = make_zip(&[("a.txt", b"hello"), ("b.txt", b"world")]);
    let mut out = Cursor::new(Vec::new());
    let stats = proc
        .process_zip(&mut Cursor::new(&input), &mut out)
        .unwrap();
    let files = read_zip(out.get_ref());
    assert_eq!(entry_names(&files), vec!["a.txt"]);
    assert_eq!(stats.entries_filtered, 1);
}

#[test]
fn zip_exclude_directory_prefix() {
    let proc = make_filter_processor(ArchiveFilter::new(vec![], vec!["logs/".into()]).unwrap());
    let input = make_zip(&[
        ("logs/app.log", b"log line"),
        ("logs/err.log", b"error line"),
        ("config.txt", b"cfg"),
    ]);
    let mut out = Cursor::new(Vec::new());
    let stats = proc
        .process_zip(&mut Cursor::new(&input), &mut out)
        .unwrap();
    let files = read_zip(out.get_ref());
    let names = entry_names(&files);
    assert!(!names.contains(&"logs/app.log"));
    assert!(!names.contains(&"logs/err.log"));
    assert!(names.contains(&"config.txt"));
    assert_eq!(stats.entries_filtered, 2);
}

#[test]
fn tar_dir_entries_pass_through_despite_filter() {
    // Directory entries must always appear in the output regardless of filter.
    // Use --exclude "config/" which would filter the files inside config/,
    // but the explicit directory entry config/ itself must still pass through.
    let proc = make_filter_processor(ArchiveFilter::new(vec![], vec!["config/".into()]).unwrap());

    // Build a tar that has an explicit directory entry followed by file entries.
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        // Explicit directory entry.
        let mut dir_hdr = tar::Header::new_gnu();
        dir_hdr.set_entry_type(tar::EntryType::Directory);
        dir_hdr.set_size(0);
        dir_hdr.set_mode(0o755);
        dir_hdr.set_mtime(1_700_000_000);
        dir_hdr.set_cksum();
        builder
            .append_data(&mut dir_hdr, "config/", &[][..])
            .unwrap();
        // File entries: one inside config/ (excluded), one outside (kept).
        let mut f_hdr = tar::Header::new_gnu();
        f_hdr.set_size(2);
        f_hdr.set_mode(0o644);
        f_hdr.set_mtime(1_700_000_000);
        f_hdr.set_cksum();
        builder
            .append_data(&mut f_hdr, "config/a.json", &b"{}"[..])
            .unwrap();
        let mut f2_hdr = tar::Header::new_gnu();
        f2_hdr.set_size(6);
        f2_hdr.set_mode(0o644);
        f2_hdr.set_mtime(1_700_000_000);
        f2_hdr.set_cksum();
        builder
            .append_data(&mut f2_hdr, "root.txt", &b"rootok"[..])
            .unwrap();
        builder.finish().unwrap();
    }

    let mut out = Vec::new();
    proc.process_tar(&buf[..], &mut out).unwrap();

    // Collect all entries (including dirs).
    let mut archive = tar::Archive::new(&out[..]);
    let mut entry_names_all: Vec<String> = Vec::new();
    for entry in archive.entries().unwrap() {
        let e = entry.unwrap();
        entry_names_all.push(e.path().unwrap().to_string_lossy().to_string());
    }

    // The directory entry must survive (filter only applies to file entries).
    assert!(
        entry_names_all
            .iter()
            .any(|n| n == "config/" || n == "config"),
        "directory entry missing from output: {entry_names_all:?}"
    );
    // config/a.json is a file entry inside the excluded prefix — it is dropped.
    assert!(
        !entry_names_all.contains(&"config/a.json".to_string()),
        "config/a.json should be filtered: {entry_names_all:?}"
    );
    // root.txt is outside the excluded prefix — it survives.
    assert!(
        entry_names_all.contains(&"root.txt".to_string()),
        "root.txt should be present: {entry_names_all:?}"
    );
}

#[test]
fn tar_filter_default_passes_all() {
    // ArchiveFilter::default() must not filter anything.
    let proc = make_filter_processor(ArchiveFilter::default());
    let input = make_tar(&[
        ("a.txt", b"hello"),
        ("b.json", b"{}"),
        ("sub/c.yaml", b"key: value"),
    ]);
    let mut out = Vec::new();
    let stats = proc.process_tar(&input[..], &mut out).unwrap();
    let files = read_tar(&out);
    assert_eq!(files.len(), 3);
    assert_eq!(stats.entries_filtered, 0);
    assert_eq!(stats.files_processed, 3);
}

// ===========================================================================
// Parallel tar processing
// ===========================================================================

/// Force the parallel path by lowering the threshold to 1.
fn make_parallel_processor() -> ArchiveProcessor {
    make_processor().with_parallel_threshold(1)
}

#[test]
fn tar_parallel_replaces_secrets_in_all_entries() {
    // Four entries — all contain a pattern match. Parallel path must sanitize
    // every one of them, not just the first batch.
    let proc = make_parallel_processor();
    let input = make_tar(&[
        ("a.txt", b"alice@corp.com"),
        ("b.txt", b"bob@corp.com"),
        ("c.txt", b"carol@corp.com"),
        ("d.txt", b"alice@corp.com"),
    ]);

    let mut output = Vec::new();
    let stats = proc.process_tar(&input[..], &mut output).unwrap();

    let files = read_tar(&output);
    assert_eq!(files.len(), 4, "all entries must appear in output");
    for (name, content) in &files {
        assert!(
            !content.contains("alice@corp.com")
                && !content.contains("bob@corp.com")
                && !content.contains("carol@corp.com"),
            "entry '{name}' still contains raw email: {content}"
        );
    }
    assert_eq!(stats.files_processed, 4);
}

#[test]
fn tar_parallel_entry_order_preserved() {
    // Parallel processing must not reorder entries in the output archive.
    let proc = make_parallel_processor();
    let input = make_tar(&[
        ("first.txt", b"alice@corp.com"),
        ("second.txt", b"hello world"),
        ("third.txt", b"bob@corp.com"),
        ("fourth.txt", b"no secrets here"),
    ]);

    let mut output = Vec::new();
    proc.process_tar(&input[..], &mut output).unwrap();

    let files = read_tar(&output);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["first.txt", "second.txt", "third.txt", "fourth.txt"]
    );
}

#[test]
fn tar_parallel_dedup_same_secret_same_replacement() {
    // Same value appearing in two entries must map to the same replacement,
    // even when both entries are sanitized concurrently.
    let proc = make_parallel_processor();
    let input = make_tar(&[
        ("a.txt", b"alice@corp.com"),
        ("b.txt", b"alice@corp.com"),
        ("c.txt", b"alice@corp.com"),
        ("d.txt", b"alice@corp.com"),
    ]);

    let mut output = Vec::new();
    proc.process_tar(&input[..], &mut output).unwrap();

    let files = read_tar(&output);
    let replacements: std::collections::HashSet<&str> =
        files.iter().map(|(_, c)| c.as_str()).collect();
    assert_eq!(
        replacements.len(),
        1,
        "same secret should produce one unique replacement across all entries; got: {replacements:?}"
    );
    assert!(!files[0].1.contains("alice@corp.com"));
}

#[test]
fn tar_parallel_preserves_passthrough_content() {
    // Entries without matches must appear in output unchanged.
    let proc = make_parallel_processor();
    let input = make_tar(&[
        ("clean1.txt", b"nothing sensitive"),
        ("clean2.txt", b"also fine"),
        ("secret.txt", b"alice@corp.com"),
        ("clean3.txt", b"still clean"),
    ]);

    let mut output = Vec::new();
    proc.process_tar(&input[..], &mut output).unwrap();

    let files = read_tar(&output);
    let by_name: std::collections::HashMap<&str, &str> = files
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_str()))
        .collect();
    assert_eq!(by_name["clean1.txt"], "nothing sensitive");
    assert_eq!(by_name["clean2.txt"], "also fine");
    assert_eq!(by_name["clean3.txt"], "still clean");
    assert!(!by_name["secret.txt"].contains("alice@corp.com"));
}

// ===========================================================================
// Zip-slip: end-to-end path traversal sanitization
// ===========================================================================

/// A zip archive containing entries with path-traversal names must be
/// processed safely: the output archive must contain only sanitized paths
/// with no `..` components, and the file content must still be sanitized.
#[test]
fn zip_slip_entry_path_sanitized_in_output() {
    let proc = make_processor();

    // Build a zip where every entry has a traversal path.
    let traversal_entries: &[(&str, &[u8])] = &[
        ("../../etc/passwd", b"alice@corp.com sensitive"),
        ("../../../root/.ssh/id_rsa", b"TOP_SECRET_KEY_12345"),
        ("/absolute/path/file.txt", b"other content"),
        ("normal/safe.txt", b"safe@safe.com"),
    ];
    let input = make_zip(traversal_entries);

    let mut writer = Cursor::new(Vec::new());
    proc.process_zip(Cursor::new(&input[..]), &mut writer).unwrap();
    let entries = read_zip(&writer.into_inner());

    // No output entry path may contain `..` or start with `/`.
    for (name, _) in &entries {
        assert!(
            !name.contains(".."),
            "output entry must not contain '..': {name}"
        );
        assert!(
            !name.starts_with('/'),
            "output entry must not start with '/': {name}"
        );
    }

    // Content must still be sanitized.
    let by_name: std::collections::HashMap<&str, &str> =
        entries.iter().map(|(n, c)| (n.as_str(), c.as_str())).collect();

    // `../../etc/passwd` → sanitized to `etc/passwd`
    assert!(
        by_name.contains_key("etc/passwd"),
        "traversal path must be sanitized to 'etc/passwd', got keys: {:?}",
        by_name.keys().collect::<Vec<_>>()
    );
    assert!(
        !by_name["etc/passwd"].contains("alice@corp.com"),
        "content in traversal entry must be sanitized"
    );

    // `../../../root/.ssh/id_rsa` → sanitized to `root/.ssh/id_rsa`
    assert!(
        by_name.contains_key("root/.ssh/id_rsa"),
        "deep traversal must be sanitized"
    );
    assert!(
        !by_name["root/.ssh/id_rsa"].contains("TOP_SECRET_KEY_12345"),
        "literal secret in traversal entry must be sanitized"
    );

    // `/absolute/path/file.txt` → sanitized to `absolute/path/file.txt`
    assert!(
        by_name.contains_key("absolute/path/file.txt"),
        "absolute path must be made relative"
    );

    // Normal entry untouched path-wise, content sanitized.
    assert!(
        by_name.contains_key("normal/safe.txt"),
        "clean path must be preserved"
    );
    assert!(
        !by_name["normal/safe.txt"].contains("safe@safe.com"),
        "email in clean entry must be sanitized"
    );
}

// Note: tar traversal-path sanitization is tested at the function level in
// `src/processor/archive.rs` (see `sanitize_tar_entry_name` unit tests).
// The `tar` crate itself refuses to construct archives with `..` path
// components, so an end-to-end integration test would require crafting raw
// tar bytes, which is out of scope here.
