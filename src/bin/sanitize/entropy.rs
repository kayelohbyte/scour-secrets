use rust_sanitize::secrets::{parse_category, SecretEntry};
use rust_sanitize::{Category, MappingStore, ScanStats, StreamScanner};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EntropyCharset {
    Alphanumeric,
    Base64,
    Hex,
    Any,
}

impl EntropyCharset {
    fn from_str(s: &str) -> Self {
        match s {
            "base64" => Self::Base64,
            "hex" => Self::Hex,
            "any" => Self::Any,
            _ => Self::Alphanumeric,
        }
    }

    pub(crate) fn describe(&self) -> &'static str {
        match self {
            Self::Alphanumeric => "alphanumeric",
            Self::Base64 => "base64",
            Self::Hex => "hex",
            Self::Any => "any printable",
        }
    }

    pub(crate) fn matches_all(&self, token: &[u8]) -> bool {
        token.iter().all(|&b| match self {
            Self::Alphanumeric => b.is_ascii_alphanumeric(),
            Self::Base64 => b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=',
            Self::Hex => b.is_ascii_hexdigit(),
            Self::Any => b.is_ascii_graphic(),
        })
    }
}

/// Configuration for one entropy-detection pass. Produced from `kind: entropy`
/// secrets-file entries and from the `--entropy-threshold` CLI flag.
#[derive(Debug, Clone)]
pub(crate) struct EntropyConfig {
    pub(crate) min_length: usize,
    pub(crate) max_length: usize,
    pub(crate) threshold: f64,
    pub(crate) charset: EntropyCharset,
    pub(crate) label: String,
    pub(crate) category: Category,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            min_length: 20,
            max_length: 200,
            threshold: 4.5,
            charset: EntropyCharset::Alphanumeric,
            label: "high_entropy_token".into(),
            category: Category::AuthToken,
        }
    }
}

/// Standard entropy thresholds used for calibration histograms.
pub(crate) const HISTOGRAM_THRESHOLDS: [f64; 6] = [3.0, 3.5, 4.0, 4.5, 5.0, 5.5];

/// Candidate token counts bucketed by entropy level, for calibration output.
/// Token values are never stored — only counts.
#[derive(Debug, Default, Clone)]
pub(crate) struct EntropyBuckets {
    /// Count of candidates with entropy >= HISTOGRAM_THRESHOLDS\[i\].
    pub(crate) counts: [u64; 6],
    /// Total tokens examined that met the charset/length constraints.
    pub(crate) total_candidates: u64,
    pub(crate) label: String,
    pub(crate) configured_threshold: f64,
    pub(crate) min_length: usize,
    pub(crate) max_length: usize,
    pub(crate) charset_desc: &'static str,
}

impl EntropyBuckets {
    pub(crate) fn merge(&mut self, other: &Self) {
        for (a, b) in self.counts.iter_mut().zip(other.counts.iter()) {
            *a += b;
        }
        self.total_candidates += other.total_candidates;
    }
}

/// Scan `input` for candidate tokens and bucket them by entropy level.
///
/// Produces one `EntropyBuckets` per config. Token values are never stored
/// or returned — only per-threshold counts and the total candidate tally.
/// Intended for calibration output in dry-run mode.
pub(crate) fn entropy_histogram_bytes(
    input: &[u8],
    configs: &[EntropyConfig],
) -> Vec<EntropyBuckets> {
    let mut results: Vec<EntropyBuckets> = configs
        .iter()
        .map(|cfg| EntropyBuckets {
            counts: [0u64; 6],
            total_candidates: 0,
            label: cfg.label.clone(),
            configured_threshold: cfg.threshold,
            min_length: cfg.min_length,
            max_length: cfg.max_length,
            charset_desc: cfg.charset.describe(),
        })
        .collect();

    if results.is_empty() || input.is_empty() {
        return results;
    }

    let mut pos = 0;
    while pos < input.len() {
        let token_end = input[pos..]
            .iter()
            .position(|b| ENTROPY_DELIMITERS.contains(b))
            .map(|p| pos + p)
            .unwrap_or(input.len());

        let token = &input[pos..token_end];

        if !token.is_empty() {
            let mut bits_opt: Option<f64> = None;
            for (cfg, bucket) in configs.iter().zip(results.iter_mut()) {
                if token.len() >= cfg.min_length
                    && token.len() <= cfg.max_length
                    && cfg.charset.matches_all(token)
                {
                    let bits = *bits_opt.get_or_insert_with(|| shannon_entropy(token));
                    bucket.total_candidates += 1;
                    for (j, &thresh) in HISTOGRAM_THRESHOLDS.iter().enumerate() {
                        if bits >= thresh {
                            bucket.counts[j] += 1;
                        }
                    }
                }
            }
        }

        if token_end < input.len() {
            pos = token_end + 1;
        } else {
            pos = token_end;
        }
    }

    results
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Build `EntropyConfig`s from `kind: entropy` entries in the secrets file.
pub(crate) fn entropy_configs_from_entries(entries: &[SecretEntry]) -> Vec<EntropyConfig> {
    entries
        .iter()
        .filter(|e| e.kind == "entropy")
        .map(|e| EntropyConfig {
            min_length: e.min_length.unwrap_or(20),
            max_length: e.max_length.unwrap_or(200),
            threshold: e.threshold.unwrap_or(4.5),
            charset: EntropyCharset::from_str(e.charset.as_deref().unwrap_or("alphanumeric")),
            label: e
                .label
                .clone()
                .unwrap_or_else(|| "high_entropy_token".into()),
            category: parse_category(&e.category),
        })
        .collect()
}

/// Byte values that delimit tokens for entropy analysis.
const ENTROPY_DELIMITERS: &[u8] = b" \t\n\r\"'`=:,;()[]{}|<>@#\\/^~!?&%$*";

/// Scan `input` for high-entropy tokens and replace them using `store`.
/// Returns `(output_bytes, per_label_counts)`.
///
/// Runs AFTER the main scanner so tokens already replaced (now placeholders)
/// won't double-fire — placeholders have low entropy by design.
pub(crate) fn entropy_scan_bytes(
    input: &[u8],
    configs: &[EntropyConfig],
    store: &Arc<MappingStore>,
) -> (Vec<u8>, HashMap<String, u64>) {
    if configs.is_empty() || input.is_empty() {
        return (input.to_vec(), HashMap::new());
    }

    let mut output = Vec::with_capacity(input.len());
    let mut label_counts: HashMap<String, u64> = HashMap::new();
    let mut pos = 0;

    while pos < input.len() {
        let token_start = pos;
        let token_end = input[pos..]
            .iter()
            .position(|b| ENTROPY_DELIMITERS.contains(b))
            .map(|p| pos + p)
            .unwrap_or(input.len());

        let token = &input[token_start..token_end];

        let replaced = if !token.is_empty() {
            let hit = configs.iter().find(|cfg| {
                token.len() >= cfg.min_length
                    && token.len() <= cfg.max_length
                    && cfg.charset.matches_all(token)
                    && shannon_entropy(token) >= cfg.threshold
            });

            if let Some(cfg) = hit {
                if let Ok(token_str) = std::str::from_utf8(token) {
                    if let Ok(replacement) = store.get_or_insert(&cfg.category, token_str) {
                        output.extend_from_slice(replacement.as_bytes());
                    } else {
                        output.extend_from_slice(token);
                    }
                    *label_counts.entry(cfg.label.clone()).or_insert(0) += 1;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if !replaced {
            output.extend_from_slice(token);
        }

        if token_end < input.len() {
            output.push(input[token_end]);
            pos = token_end + 1;
        } else {
            pos = token_end;
        }
    }

    (output, label_counts)
}

pub(crate) fn scanner_fallback(
    scanner: &StreamScanner,
    input: &[u8],
) -> Result<(Vec<u8>, ScanStats), String> {
    scanner
        .scan_bytes(input)
        .map_err(|e| format!("scanner error: {e}"))
}

/// A `Write + Seek` sink that discards all bytes.
///
/// Used for dry-run zip processing: `ZipWriter` requires `Seek` to finalize
/// the central directory, so `io::sink()` alone is insufficient.
pub(crate) struct NullSeekWriter {
    pub(crate) pos: u64,
    pub(crate) len: u64,
}

impl io::Write for NullSeekWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len() as u64;
        self.pos += n;
        if self.pos > self.len {
            self.len = self.pos;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Seek for NullSeekWriter {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        let new_pos: u64 = match from {
            io::SeekFrom::Start(n) => n,
            io::SeekFrom::Current(n) => {
                if n >= 0 {
                    self.pos.saturating_add(n as u64)
                } else {
                    self.pos.saturating_sub((-n) as u64)
                }
            }
            io::SeekFrom::End(n) => {
                if n >= 0 {
                    self.len.saturating_add(n as u64)
                } else {
                    self.len.saturating_sub((-n) as u64)
                }
            }
        };
        self.pos = new_pos;
        if new_pos > self.len {
            self.len = new_pos;
        }
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_sanitize::secrets::SecretEntry;
    use rust_sanitize::{MappingStore, RandomGenerator};
    use std::sync::Arc;

    fn test_store() -> Arc<MappingStore> {
        Arc::new(MappingStore::new(Arc::new(RandomGenerator::new()), None))
    }

    fn make_entropy_entry(
        label: Option<&str>,
        min: Option<usize>,
        max: Option<usize>,
        threshold: Option<f64>,
        charset: Option<&str>,
    ) -> SecretEntry {
        SecretEntry {
            pattern: String::new(),
            kind: "entropy".into(),
            category: "auth_token".into(),
            label: label.map(|s| s.into()),
            values: vec![],
            min_length: min,
            max_length: max,
            threshold,
            charset: charset.map(|s| s.into()),
        }
    }

    // ── EntropyCharset::from_str ─────────────────────────────────────────────

    #[test]
    fn charset_from_str_all_variants() {
        assert_eq!(EntropyCharset::from_str("base64"), EntropyCharset::Base64);
        assert_eq!(EntropyCharset::from_str("hex"), EntropyCharset::Hex);
        assert_eq!(EntropyCharset::from_str("any"), EntropyCharset::Any);
        assert_eq!(
            EntropyCharset::from_str("alphanumeric"),
            EntropyCharset::Alphanumeric
        );
        assert_eq!(
            EntropyCharset::from_str("unknown"),
            EntropyCharset::Alphanumeric,
            "unrecognised values default to alphanumeric"
        );
    }

    // ── EntropyCharset::describe ─────────────────────────────────────────────

    #[test]
    fn charset_describe_all_variants() {
        assert_eq!(EntropyCharset::Alphanumeric.describe(), "alphanumeric");
        assert_eq!(EntropyCharset::Base64.describe(), "base64");
        assert_eq!(EntropyCharset::Hex.describe(), "hex");
        assert_eq!(EntropyCharset::Any.describe(), "any printable");
    }

    // ── EntropyCharset::matches_all ──────────────────────────────────────────

    #[test]
    fn alphanumeric_accepts_alnum_rejects_special() {
        assert!(EntropyCharset::Alphanumeric.matches_all(b"abc123XYZ"));
        assert!(!EntropyCharset::Alphanumeric.matches_all(b"abc+def"));
        assert!(!EntropyCharset::Alphanumeric.matches_all(b"abc/def"));
    }

    #[test]
    fn base64_accepts_valid_chars_rejects_invalid() {
        assert!(EntropyCharset::Base64.matches_all(b"abc+/=XYZ012"));
        assert!(!EntropyCharset::Base64.matches_all(b"abc!"));
        assert!(!EntropyCharset::Base64.matches_all(b"abc "));
    }

    #[test]
    fn hex_accepts_hex_digits_rejects_others() {
        assert!(EntropyCharset::Hex.matches_all(b"0123456789abcdefABCDEF"));
        assert!(!EntropyCharset::Hex.matches_all(b"0xdeadbeefg"));
        assert!(!EntropyCharset::Hex.matches_all(b"xyz"));
    }

    #[test]
    fn any_accepts_printable_rejects_control_chars() {
        assert!(EntropyCharset::Any.matches_all(b"hello!@#$%^&*()-+="));
        assert!(!EntropyCharset::Any.matches_all(b"hello\x00world"));
        assert!(!EntropyCharset::Any.matches_all(b"hello\x01world"));
        assert!(!EntropyCharset::Any.matches_all(b"hello\x1bworld"));
    }

    #[test]
    fn empty_slice_matches_all_charsets() {
        assert!(EntropyCharset::Alphanumeric.matches_all(b""));
        assert!(EntropyCharset::Base64.matches_all(b""));
        assert!(EntropyCharset::Hex.matches_all(b""));
        assert!(EntropyCharset::Any.matches_all(b""));
    }

    // ── EntropyBuckets::merge ────────────────────────────────────────────────

    #[test]
    fn buckets_merge_sums_counts_and_total() {
        let mut a = EntropyBuckets {
            counts: [1, 2, 3, 4, 5, 6],
            total_candidates: 10,
            label: "a".into(),
            configured_threshold: 4.5,
            min_length: 20,
            max_length: 200,
            charset_desc: "alphanumeric",
        };
        let b = EntropyBuckets {
            counts: [10, 20, 30, 40, 50, 60],
            total_candidates: 5,
            label: "b".into(),
            configured_threshold: 4.5,
            min_length: 20,
            max_length: 200,
            charset_desc: "alphanumeric",
        };
        a.merge(&b);
        assert_eq!(a.counts, [11, 22, 33, 44, 55, 66]);
        assert_eq!(a.total_candidates, 15);
    }

    // ── entropy_histogram_bytes ──────────────────────────────────────────────

    #[test]
    fn histogram_empty_input_zero_candidates() {
        let result = entropy_histogram_bytes(b"", &[EntropyConfig::default()]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].total_candidates, 0);
        assert_eq!(result[0].counts, [0u64; 6]);
    }

    #[test]
    fn histogram_empty_configs_returns_empty_vec() {
        let result = entropy_histogram_bytes(b"AKIAIOSFODNN7EXAMPLE", &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn histogram_token_too_short_not_counted() {
        let cfg = EntropyConfig {
            min_length: 50,
            ..EntropyConfig::default()
        };
        let result = entropy_histogram_bytes(b"AKIAIOSFODNN7EXAMPLE", &[cfg]);
        assert_eq!(result[0].total_candidates, 0);
    }

    #[test]
    fn histogram_high_entropy_token_bucketed() {
        let cfg = EntropyConfig {
            min_length: 20,
            max_length: 200,
            threshold: 4.5,
            ..EntropyConfig::default()
        };
        let result = entropy_histogram_bytes(b"AKIAIOSFODNN7EXAMPLE", &[cfg]);
        assert!(
            result[0].total_candidates >= 1,
            "token should be a candidate"
        );
        // 3.0-bit bucket should be set
        assert!(
            result[0].counts[0] >= 1,
            "should have a count at >=3.0 bits"
        );
    }

    #[test]
    fn histogram_charset_filters_non_matching_tokens() {
        let cfg = EntropyConfig {
            min_length: 3,
            max_length: 200,
            charset: EntropyCharset::Hex,
            ..EntropyConfig::default()
        };
        // "hello" contains non-hex chars, "deadbeef" is valid hex
        let result = entropy_histogram_bytes(b"hello deadbeef", &[cfg]);
        // "deadbeef" (8 chars, all hex) should be counted; "hello" should not
        // min_length is 3 so deadbeef qualifies
        assert_eq!(
            result[0].total_candidates, 1,
            "only hex token should be a candidate"
        );
    }

    // ── entropy_configs_from_entries ─────────────────────────────────────────

    #[test]
    fn configs_from_entries_ignores_non_entropy_kinds() {
        let entries = vec![SecretEntry {
            pattern: "foo".into(),
            kind: "regex".into(),
            category: "auth_token".into(),
            label: None,
            values: vec![],
            min_length: None,
            max_length: None,
            threshold: None,
            charset: None,
        }];
        assert!(entropy_configs_from_entries(&entries).is_empty());
    }

    #[test]
    fn configs_from_entries_extracts_all_fields() {
        let entries = vec![make_entropy_entry(
            Some("my_token"),
            Some(16),
            Some(64),
            Some(4.0),
            Some("hex"),
        )];
        let configs = entropy_configs_from_entries(&entries);
        assert_eq!(configs.len(), 1);
        let cfg = &configs[0];
        assert_eq!(cfg.label, "my_token");
        assert_eq!(cfg.min_length, 16);
        assert_eq!(cfg.max_length, 64);
        assert_eq!(cfg.threshold, 4.0);
        assert_eq!(cfg.charset, EntropyCharset::Hex);
    }

    #[test]
    fn configs_from_entries_applies_defaults() {
        let entries = vec![make_entropy_entry(None, None, None, None, None)];
        let configs = entropy_configs_from_entries(&entries);
        assert_eq!(configs.len(), 1);
        let cfg = &configs[0];
        assert_eq!(cfg.min_length, 20);
        assert_eq!(cfg.max_length, 200);
        assert_eq!(cfg.threshold, 4.5);
        assert_eq!(cfg.charset, EntropyCharset::Alphanumeric);
        assert_eq!(cfg.label, "high_entropy_token");
    }

    // ── entropy_scan_bytes ───────────────────────────────────────────────────

    #[test]
    fn scan_bytes_empty_input_returns_empty() {
        let (out, counts) = entropy_scan_bytes(b"", &[EntropyConfig::default()], &test_store());
        assert!(out.is_empty());
        assert!(counts.is_empty());
    }

    #[test]
    fn scan_bytes_empty_configs_passthrough() {
        let input = b"AKIAIOSFODNN7EXAMPLE";
        let (out, counts) = entropy_scan_bytes(input, &[], &test_store());
        assert_eq!(out, input);
        assert!(counts.is_empty());
    }

    #[test]
    fn scan_bytes_token_too_short_not_replaced() {
        let cfg = EntropyConfig {
            min_length: 100,
            ..EntropyConfig::default()
        };
        let input = b"AKIAIOSFODNN7EXAMPLE";
        let (out, counts) = entropy_scan_bytes(input, &[cfg], &test_store());
        assert_eq!(out, input);
        assert!(counts.is_empty());
    }

    #[test]
    fn scan_bytes_replaces_high_entropy_token() {
        let cfg = EntropyConfig {
            min_length: 20,
            max_length: 200,
            threshold: 3.5,
            ..EntropyConfig::default()
        };
        // 20-char mixed-case+digit token with decent Shannon entropy
        let input = b"token=AKIAIOSFODNN7EXAMPLE end";
        let (out, counts) = entropy_scan_bytes(input, &[cfg], &test_store());
        let s = String::from_utf8_lossy(&out);
        assert!(
            !s.contains("AKIAIOSFODNN7EXAMPLE"),
            "high-entropy token should be replaced; got: {s}"
        );
        assert_eq!(*counts.get("high_entropy_token").unwrap_or(&0), 1);
    }

    #[test]
    fn scan_bytes_preserves_surrounding_text_and_delimiters() {
        let cfg = EntropyConfig {
            min_length: 100,
            ..EntropyConfig::default()
        };
        let input = b"key=value foo bar\n";
        let (out, _) = entropy_scan_bytes(input, &[cfg], &test_store());
        assert_eq!(out, input);
    }

    #[test]
    fn scan_bytes_non_matching_charset_not_replaced() {
        let cfg = EntropyConfig {
            min_length: 20,
            max_length: 200,
            threshold: 3.5,
            charset: EntropyCharset::Hex,
            ..EntropyConfig::default()
        };
        // AKIAIOSFODNN7EXAMPLE contains non-hex chars (G, H, etc.)
        let input = b"AKIAIOSFODNN7EXAMPLE";
        let (out, counts) = entropy_scan_bytes(input, &[cfg], &test_store());
        assert_eq!(
            out, input,
            "non-hex token should not be replaced by hex config"
        );
        assert!(counts.is_empty());
    }

    // ── NullSeekWriter ───────────────────────────────────────────────────────

    #[test]
    fn null_seek_writer_write_advances_position_and_length() {
        use std::io::Write;
        let mut w = NullSeekWriter { pos: 0, len: 0 };
        let n = w.write(b"hello world").unwrap();
        assert_eq!(n, 11);
        assert_eq!(w.pos, 11);
        assert_eq!(w.len, 11);
        w.flush().unwrap();
    }

    #[test]
    fn null_seek_writer_seek_from_start() {
        use std::io::{Seek, SeekFrom, Write};
        let mut w = NullSeekWriter { pos: 0, len: 0 };
        w.write_all(b"hello world").unwrap(); // pos=11, len=11
        let pos = w.seek(SeekFrom::Start(3)).unwrap();
        assert_eq!(pos, 3);
        assert_eq!(w.pos, 3);
        assert_eq!(w.len, 11, "len unchanged by backward seek");
    }

    #[test]
    fn null_seek_writer_seek_from_current_positive_and_negative() {
        use std::io::{Seek, SeekFrom, Write};
        let mut w = NullSeekWriter { pos: 0, len: 0 };
        w.write_all(b"hello").unwrap(); // pos=5
        let pos = w.seek(SeekFrom::Current(3)).unwrap();
        assert_eq!(pos, 8);
        let pos = w.seek(SeekFrom::Current(-4)).unwrap();
        assert_eq!(pos, 4);
    }

    #[test]
    fn null_seek_writer_seek_from_end() {
        use std::io::{Seek, SeekFrom, Write};
        let mut w = NullSeekWriter { pos: 0, len: 0 };
        w.write_all(b"hello world").unwrap(); // len=11
        let pos = w.seek(SeekFrom::End(-2)).unwrap();
        assert_eq!(pos, 9);
        let pos = w.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(pos, 11);
    }

    #[test]
    fn null_seek_writer_seek_beyond_end_extends_len() {
        use std::io::{Seek, SeekFrom};
        let mut w = NullSeekWriter { pos: 0, len: 5 };
        let pos = w.seek(SeekFrom::Start(10)).unwrap();
        assert_eq!(pos, 10);
        assert_eq!(w.len, 10, "seeking past end should extend len");
    }
}
