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
