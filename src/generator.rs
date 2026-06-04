//! Replacement generation strategies.
//!
//! Two concrete implementations:
//! - `HmacGenerator`: Deterministic, seeded with a 32-byte key. Same seed + same
//!   input = same output across runs. Uses HMAC-SHA256 for domain separation.
//! - `RandomGenerator`: Cryptographically random replacements. Non-deterministic.
//!
//! Both produce category-aware, format-preserving replacements.
//!
//! # Design Note
//!
//! This module contains the category-aware formatters used by the CLI binary.
//! For an extensible strategy API that allows custom replacement logic, see
//! the [`crate::strategy`] module.

use crate::category::Category;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Strategy for generating a sanitized replacement value.
///
/// Implementations MUST be deterministic to their inputs: given the same
/// `(category, original)` pair (and same internal state / seed), the output
/// must be identical. This is what enables per-run consistency when backed
/// by a `MappingStore` that calls `generate` only once per unique value.
pub trait ReplacementGenerator: Send + Sync {
    /// Produce a sanitized replacement for `original` classified as `category`.
    fn generate(&self, category: &Category, original: &str) -> String;
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 deterministic generator
// ---------------------------------------------------------------------------

/// Deterministic replacement generator seeded with a 32-byte key.
///
/// ```text
/// replacement = format(category, HMAC-SHA256(key, category_tag || "\x00" || original))
/// ```
///
/// The same key + same `(category, original)` always yields the same output.
/// Different keys yield completely different outputs with overwhelming probability.
pub struct HmacGenerator {
    key: [u8; 32],
}

impl Drop for HmacGenerator {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl HmacGenerator {
    /// Create a new generator from a 32-byte seed.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Create a generator from a byte slice (must be exactly 32 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::InvalidSeedLength`](crate::error::SanitizeError::InvalidSeedLength) if `bytes.len() != 32`.
    pub fn from_slice(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() != 32 {
            return Err(crate::error::SanitizeError::InvalidSeedLength(bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    /// Derive the raw 32-byte HMAC digest for `(category, original)`.
    fn derive(&self, category: &Category, original: &str) -> [u8; 32] {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        let tag = category.domain_tag_hmac();
        mac.update(tag.as_bytes());
        mac.update(b"\x00"); // domain separator
        mac.update(original.as_bytes());
        let result = mac.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result.into_bytes());
        out
    }
}

impl ReplacementGenerator for HmacGenerator {
    fn generate(&self, category: &Category, original: &str) -> String {
        let hash = self.derive(category, original);
        format_replacement(category, &hash, original)
    }
}

// ---------------------------------------------------------------------------
// Cryptographically-random generator (non-deterministic)
// ---------------------------------------------------------------------------

/// Random replacement generator using OS CSPRNG.
///
/// Each call to `generate` produces a fresh random value. Determinism is
/// achieved externally by the `MappingStore`, which calls `generate` only
/// once per unique `(category, original)` pair and caches the result.
pub struct RandomGenerator;

impl RandomGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RandomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplacementGenerator for RandomGenerator {
    fn generate(&self, category: &Category, original: &str) -> String {
        let mut rng = rand::rng();
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        format_replacement(category, &hash, original)
    }
}

// ---------------------------------------------------------------------------
// Category-aware formatting helpers
// ---------------------------------------------------------------------------

/// Format a 32-byte hash into a length-preserving replacement whose
/// byte length exactly matches `original.len()`. The shape is
/// category-aware and deterministic for the same `(hash, original)` pair.
fn format_replacement(category: &Category, hash: &[u8; 32], original: &str) -> String {
    let target = original.len();
    if target == 0 {
        return String::new();
    }
    let hex = hex_bytes(hash);
    match category {
        Category::Email => format_email_lp(&hex, original, target),
        Category::Name => format_name_lp(hash, &hex, target),
        Category::Phone | Category::CreditCard | Category::IpV4 => {
            format_digits_lp(hash, original, target)
        }
        Category::IpV6 | Category::MacAddress | Category::Uuid | Category::ContainerId => {
            format_hex_digits_lp(hash, original, target)
        }
        Category::Ssn => format_ssn_lp(hash, original, target),
        Category::Hostname => format_hostname_lp(&hex, original, target),
        Category::Jwt => format_jwt_lp(hash, original, target),
        Category::FilePath => format_filepath_lp(&hex, original, target),
        Category::WindowsSid => format_windows_sid_lp(hash, original, target),
        Category::Url => format_url_lp(&hex, original, target),
        Category::AwsArn => format_arn_lp(&hex, original, target),
        Category::AzureResourceId => format_azure_resource_id_lp(&hex, original, target),
        Category::AuthToken | Category::Custom(_) => format_custom_lp(&hex, target),
    }
}

// ---------------------------------------------------------------------------
// Length-preserving helpers
// ---------------------------------------------------------------------------

/// Pad `s` with deterministic hex characters from `hex`, or truncate,
/// to reach exactly `target` bytes.  All generated content is ASCII so
/// byte length equals character count for the produced output.
fn pad_or_truncate(s: &str, target: usize, hex: &[u8; 64]) -> String {
    let slen = s.len();
    if slen == target {
        return s.to_string();
    }
    if slen > target {
        return s[..target].to_string();
    }
    let mut buf = String::with_capacity(target);
    buf.push_str(s);
    for i in 0..target.saturating_sub(slen) {
        buf.push(hex[i % 64] as char);
    }
    buf
}

/// Length-preserving email replacement.
/// Preserves the domain from the original; generates a hex username
/// sized so the total byte length matches the original.
fn format_email_lp(hex: &[u8; 64], original: &str, target: usize) -> String {
    let domain = original
        .rfind('@')
        .map_or("x.co", |pos| &original[pos + 1..]);
    let at_domain = 1 + domain.len(); // "@" + domain
    if target <= at_domain {
        // Too short to fit @domain — use hex fallback.
        return pad_or_truncate("", target, hex);
    }
    let user_len = target - at_domain;
    let mut buf = String::with_capacity(target);
    for i in 0..user_len {
        buf.push(hex[i % 64] as char);
    }
    buf.push('@');
    buf.push_str(domain);
    buf
}

/// Length-preserving name replacement.
/// Generates a synthetic name via the hash-indexed table, then
/// truncates or pads to match `target` bytes.
fn format_name_lp(hash: &[u8; 32], hex: &[u8; 64], target: usize) -> String {
    let raw = format_name(hash);
    pad_or_truncate(&raw, target, hex)
}

/// Replace each character matching `is_replaceable` with a deterministic
/// character produced by `replacement(original_char, hash[hi % 32])`.
/// All other characters are preserved as-is.
/// Returns `None` if no replaceable characters were found (caller falls back).
fn format_char_class_lp(
    hash: &[u8; 32],
    original: &str,
    is_replaceable: impl Fn(char) -> bool,
    replacement: impl Fn(char, u8) -> char,
) -> Option<String> {
    let mut buf = String::with_capacity(original.len());
    let mut hi = 0usize;
    let mut had_replaceable = false;
    for ch in original.chars() {
        if is_replaceable(ch) {
            buf.push(replacement(ch, hash[hi % 32]));
            hi += 1;
            had_replaceable = true;
        } else {
            buf.push(ch);
        }
    }
    had_replaceable.then_some(buf)
}

/// Length-preserving digit replacement.
/// Preserves every non-digit character in `original`; replaces each
/// ASCII digit with a deterministic digit derived from `hash`.
/// Falls back to hex if the original contains no digits.
fn format_digits_lp(hash: &[u8; 32], original: &str, target: usize) -> String {
    format_char_class_lp(
        hash,
        original,
        |c| c.is_ascii_digit(),
        |_, b| (b'0' + b % 10) as char,
    )
    .unwrap_or_else(|| pad_or_truncate("", target, &hex_bytes(hash)))
}

/// Length-preserving hex-digit replacement (for IPv6, UUID, MAC, container ID).
/// Preserves non-hex characters (colons, dashes, etc.); replaces each
/// ASCII hex digit with a deterministic hex digit from `hash`, preserving case.
fn format_hex_digits_lp(hash: &[u8; 32], original: &str, target: usize) -> String {
    let hex = hex_bytes(hash);
    format_char_class_lp(
        hash,
        original,
        |c| c.is_ascii_hexdigit(),
        |ch, b| {
            let nibble = b % 16;
            if ch.is_ascii_uppercase() {
                b"0123456789ABCDEF"[nibble as usize] as char
            } else {
                b"0123456789abcdef"[nibble as usize] as char
            }
        },
    )
    .unwrap_or_else(|| pad_or_truncate("", target, &hex))
}

/// Length-preserving SSN replacement.
/// Preserves all non-digit characters.  The first three digit positions
/// are forced to '0' (never-issued area code, clearly synthetic).
/// Remaining digit positions are filled with deterministic digits.
fn format_ssn_lp(hash: &[u8; 32], original: &str, target: usize) -> String {
    let has_digit = original.chars().any(|c| c.is_ascii_digit());
    if !has_digit {
        let hex = hex_bytes(hash);
        return pad_or_truncate("", target, &hex);
    }
    let mut buf = String::with_capacity(target);
    let mut digit_idx = 0usize;
    for ch in original.chars() {
        if ch.is_ascii_digit() {
            if digit_idx < 3 {
                buf.push('0');
            } else {
                buf.push((b'0' + hash[(digit_idx - 3) % 32] % 10) as char);
            }
            digit_idx += 1;
        } else {
            buf.push(ch);
        }
    }
    buf
}

/// Length-preserving hostname replacement.
/// Preserves the suffix (everything from the first `.` onward) and
/// fills the prefix with deterministic hex characters to match `target`.
fn format_hostname_lp(hex: &[u8; 64], original: &str, target: usize) -> String {
    let suffix = original.find('.').map_or("", |p| &original[p..]);
    let prefix_len = target.saturating_sub(suffix.len());
    if prefix_len == 0 {
        return pad_or_truncate("", target, hex);
    }
    let mut buf = String::with_capacity(target);
    for i in 0..prefix_len {
        buf.push(hex[i % 64] as char);
    }
    buf.push_str(suffix);
    buf
}

/// Length-preserving custom replacement.
/// Uses `__SANITIZED_<hex>__` format when the target is long enough;
/// falls back to bare hex for short targets.
fn format_custom_lp(hex: &[u8; 64], target: usize) -> String {
    let prefix = "__SANITIZED_";
    let suffix = "__";
    let overhead = prefix.len() + suffix.len(); // 14
    if target <= overhead {
        return pad_or_truncate("", target, hex);
    }
    let hex_len = target - overhead;
    let mut buf = String::with_capacity(target);
    buf.push_str(prefix);
    for i in 0..hex_len {
        buf.push(hex[i % 64] as char);
    }
    buf.push_str(suffix);
    buf
}

/// Length-preserving JWT replacement.
/// Preserves `.` separators; replaces base64url characters
/// (`[A-Za-z0-9_-]`) with deterministic base64url characters.
fn format_jwt_lp(hash: &[u8; 32], original: &str, target: usize) -> String {
    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut buf = String::with_capacity(target);
    let mut hi = 0usize;
    let mut had_b64 = false;
    for ch in original.chars() {
        if ch == '.' || ch == '=' {
            buf.push(ch);
        } else if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            buf.push(B64URL[hash[hi % 32] as usize % B64URL.len()] as char);
            hi += 1;
            had_b64 = true;
        } else {
            // Non-base64url, non-structural: emit byte-preserving replacement.
            for _ in 0..ch.len_utf8() {
                buf.push(B64URL[hash[hi % 32] as usize % B64URL.len()] as char);
                hi += 1;
            }
            had_b64 = true;
        }
    }
    if !had_b64 {
        let hex = hex_bytes(hash);
        return pad_or_truncate("", target, &hex);
    }
    buf
}

/// Length-preserving file path replacement.
/// Preserves separators (`/`, `\`) and the final extension (from last `.`
/// in the last segment). Replaces other characters with deterministic hex.
fn format_filepath_lp(hex: &[u8; 64], original: &str, target: usize) -> String {
    // Find the last path separator position to identify the filename segment.
    let last_sep = original.rfind(['/', '\\']).map_or(0, |p| p + 1);
    let filename = &original[last_sep..];
    // Find extension in the filename (last `.` that isn't at position 0).
    let ext_start = filename.rfind('.').filter(|&p| p > 0).map(|p| last_sep + p);

    let mut buf = String::with_capacity(target);
    let mut hi = 0usize;

    for (i, ch) in original.char_indices() {
        if matches!(ch, '/' | '\\') || ext_start.is_some_and(|es| i >= es) {
            // Preserve separators and the file extension.
            buf.push(ch);
        } else {
            // Emit as many ASCII hex bytes as the original char's UTF-8 length.
            for _ in 0..ch.len_utf8() {
                buf.push(hex[hi % 64] as char);
                hi += 1;
            }
        }
    }
    // Ensure exact length (should be equal for ASCII, but guard anyway).
    if buf.len() != target {
        return pad_or_truncate(&buf, target, hex);
    }
    buf
}

/// Length-preserving Windows SID replacement.
/// Preserves the `S-` prefix and `-` separators; replaces digit groups
/// with deterministic digits.
fn format_windows_sid_lp(hash: &[u8; 32], original: &str, target: usize) -> String {
    let has_digit = original.chars().any(|c| c.is_ascii_digit());
    if !has_digit {
        let hex = hex_bytes(hash);
        return pad_or_truncate("", target, &hex);
    }
    let mut buf = String::with_capacity(target);
    let mut hi = 0usize;
    for ch in original.chars() {
        if ch == 'S' || ch == '-' {
            buf.push(ch);
        } else if ch.is_ascii_digit() {
            buf.push((b'0' + hash[hi % 32] % 10) as char);
            hi += 1;
        } else {
            // Non-digit, non-structural: emit byte-count-preserving hex.
            for _ in 0..ch.len_utf8() {
                buf.push((b'0' + hash[hi % 32] % 10) as char);
                hi += 1;
            }
        }
    }
    buf
}

/// Shared core for length-preserving hex replacement where a caller-supplied
/// predicate identifies "structural" characters to preserve as-is.
///
/// All non-structural characters are replaced byte-by-byte with deterministic
/// hex characters derived from `hex`.  Returns `None` if the original
/// contained no replaceable content (caller should fall back to
/// [`pad_or_truncate`]).
fn format_preserving_hex_lp(
    hex: &[u8; 64],
    original: &str,
    target: usize,
    is_structural: impl Fn(char) -> bool,
) -> Option<String> {
    let mut buf = String::with_capacity(target);
    let mut hi = 0usize;
    let mut had_content = false;

    for ch in original.chars() {
        if is_structural(ch) {
            buf.push(ch);
        } else {
            for _ in 0..ch.len_utf8() {
                buf.push(hex[hi % 64] as char);
                hi += 1;
            }
            had_content = true;
        }
    }

    had_content.then_some(buf)
}

/// Length-preserving URL replacement.
/// Preserves scheme prefix and structural characters
/// (`://`, `/`, `?`, `=`, `&`, `#`, `:`); replaces content characters
/// with deterministic hex.
fn format_url_lp(hex: &[u8; 64], original: &str, target: usize) -> String {
    format_preserving_hex_lp(hex, original, target, |ch| "/:?=&#@.".contains(ch))
        .unwrap_or_else(|| pad_or_truncate("", target, hex))
}

/// Length-preserving AWS ARN replacement.
/// Preserves `:` and `/` separators; replaces alphanumeric content
/// in account/resource segments with deterministic hex.
fn format_arn_lp(hex: &[u8; 64], original: &str, target: usize) -> String {
    format_preserving_hex_lp(hex, original, target, |ch| ch == ':' || ch == '/')
        .unwrap_or_else(|| pad_or_truncate("", target, hex))
}

/// Length-preserving Azure Resource ID replacement.
/// Preserves `/` path separators and well-known Azure segment names
/// (`subscriptions`, `resourceGroups`, `providers`, `resourcegroups`).
/// Replaces variable segments (IDs, names) with deterministic hex.
fn format_azure_resource_id_lp(hex: &[u8; 64], original: &str, target: usize) -> String {
    const KNOWN_SEGMENTS: &[&str] = &[
        "subscriptions",
        "resourceGroups",
        "resourcegroups",
        "providers",
    ];

    let mut buf = String::with_capacity(target);
    let mut hi = 0usize;

    // Split on `/`, rebuild with deterministic replacement for non-known segments.
    let mut prev_was_providers = false;
    for (pi, part) in original.split('/').enumerate() {
        if pi > 0 {
            buf.push('/');
        }
        // Dotted segments (e.g. `Microsoft.Compute`) are only preserved when
        // they immediately follow a `providers` segment. Preserving all dotted
        // segments would accidentally pass through IPs or hostnames that appear
        // elsewhere in the path.
        let is_provider_namespace = prev_was_providers && part.contains('.');
        if part.is_empty() || KNOWN_SEGMENTS.contains(&part) || is_provider_namespace {
            buf.push_str(part);
        } else {
            // Replace this segment character-by-character to preserve byte length.
            for ch in part.chars() {
                for _ in 0..ch.len_utf8() {
                    buf.push(hex[hi % 64] as char);
                    hi += 1;
                }
            }
        }
        prev_was_providers = part == "providers" || part == "Providers";
    }
    if buf.len() != target {
        return pad_or_truncate(&buf, target, hex);
    }
    buf
}

/// Deterministic synthetic name from hash bytes.
fn format_name(hash: &[u8; 32]) -> String {
    // We use a small, fixed table of first/last name fragments.
    // The hash selects indices. This is NOT meant to be realistic — it's
    // meant to be obviously synthetic while remaining structurally plausible.
    const FIRST: &[&str] = &[
        "Alex", "Blake", "Casey", "Dana", "Ellis", "Finley", "Gray", "Harper", "Ira", "Jordan",
        "Kai", "Lane", "Morgan", "Noel", "Oakley", "Parker", "Quinn", "Reese", "Sage", "Taylor",
        "Uri", "Val", "Wren", "Xen", "Yael", "Zion", "Arden", "Blair", "Corin", "Drew", "Emery",
        "Frost",
    ];
    const LAST: &[&str] = &[
        "Ashford",
        "Blackwell",
        "Crawford",
        "Dalton",
        "Eastwood",
        "Fairbanks",
        "Garrison",
        "Hartley",
        "Irvine",
        "Jensen",
        "Kendrick",
        "Langley",
        "Mercer",
        "Newland",
        "Oakwood",
        "Preston",
        "Quinlan",
        "Redmond",
        "Shepard",
        "Thornton",
        "Underwood",
        "Vance",
        "Whitmore",
        "Xavier",
        "Yardley",
        "Zimmer",
        "Ashton",
        "Beckett",
        "Calloway",
        "Dempsey",
        "Eldridge",
        "Fletcher",
    ];
    let fi = hash[0] as usize % FIRST.len();
    let li = hash[1] as usize % LAST.len();
    format!("{} {}", FIRST[fi], LAST[li])
}

/// Encode 32 bytes as 64 lowercase hex ASCII bytes on the stack.
fn hex_bytes(bytes: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0xf) as usize];
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_deterministic_same_input() {
        let gen = HmacGenerator::new([42u8; 32]);
        let a = gen.generate(&Category::Email, "alice@corp.com");
        let b = gen.generate(&Category::Email, "alice@corp.com");
        assert_eq!(a, b, "same seed + same input must produce same output");
    }

    #[test]
    fn hmac_different_inputs_differ() {
        let gen = HmacGenerator::new([42u8; 32]);
        let a = gen.generate(&Category::Email, "alice@corp.com");
        let b = gen.generate(&Category::Email, "bob@corp.com");
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_different_seeds_differ() {
        let g1 = HmacGenerator::new([1u8; 32]);
        let g2 = HmacGenerator::new([2u8; 32]);
        let a = g1.generate(&Category::Email, "alice@corp.com");
        let b = g2.generate(&Category::Email, "alice@corp.com");
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_different_categories_differ() {
        let gen = HmacGenerator::new([42u8; 32]);
        let a = gen.generate(&Category::Email, "test");
        let b = gen.generate(&Category::Name, "test");
        assert_ne!(a, b, "different categories must produce different outputs");
    }

    #[test]
    fn email_format() {
        let gen = HmacGenerator::new([0u8; 32]);
        let orig = "alice@corp.com";
        let out = gen.generate(&Category::Email, orig);
        assert!(out.contains('@'), "email must contain @");
        assert!(out.ends_with("@corp.com"), "email must preserve domain");
        assert_eq!(out.len(), orig.len(), "email must preserve length");
    }

    #[test]
    fn ipv4_format() {
        let gen = HmacGenerator::new([0u8; 32]);
        let orig = "192.168.1.1";
        let out = gen.generate(&Category::IpV4, orig);
        // Dots preserved, length preserved.
        let parts: Vec<&str> = out.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(out.len(), orig.len(), "ipv4 must preserve length");
    }

    #[test]
    fn ssn_format() {
        let gen = HmacGenerator::new([7u8; 32]);
        let orig = "123-45-6789";
        let out = gen.generate(&Category::Ssn, orig);
        assert!(out.starts_with("000-"), "SSN must start with 000");
        assert_eq!(out.len(), orig.len(), "SSN must preserve length");
    }

    #[test]
    fn phone_format() {
        let gen = HmacGenerator::new([3u8; 32]);
        let orig = "+1-212-555-0100";
        let out = gen.generate(&Category::Phone, orig);
        // Formatting characters preserved.
        assert!(out.starts_with('+'));
        assert_eq!(
            out.chars().filter(|c| *c == '-').count(),
            orig.chars().filter(|c| *c == '-').count(),
            "dashes must be preserved"
        );
        assert_eq!(out.len(), orig.len(), "phone must preserve length");
    }

    #[test]
    fn hostname_format() {
        let gen = HmacGenerator::new([5u8; 32]);
        let orig = "db-prod-01.internal";
        let out = gen.generate(&Category::Hostname, orig);
        assert!(out.ends_with(".internal"), "hostname must preserve suffix");
        assert_eq!(out.len(), orig.len(), "hostname must preserve length");
    }

    #[test]
    fn custom_format() {
        let gen = HmacGenerator::new([9u8; 32]);
        let cat = Category::Custom("api_key".into());
        // Use an input long enough for the __SANITIZED_..__ wrapper (>14 chars).
        let orig = "sk-abc123-very-long-key";
        let out = gen.generate(&cat, orig);
        assert!(out.starts_with("__SANITIZED_"));
        assert!(out.ends_with("__"));
        assert_eq!(out.len(), orig.len(), "custom must preserve length");
    }

    #[test]
    fn custom_format_short() {
        let gen = HmacGenerator::new([9u8; 32]);
        let cat = Category::Custom("api_key".into());
        // Short input falls back to hex.
        let orig = "sk-abc123";
        let out = gen.generate(&cat, orig);
        assert_eq!(
            out.len(),
            orig.len(),
            "custom must preserve length even for short inputs"
        );
    }

    #[test]
    fn random_generator_produces_valid_format() {
        let gen = RandomGenerator::new();
        let orig = "test@example.com";
        let out = gen.generate(&Category::Email, orig);
        assert!(out.contains('@'));
        assert_eq!(
            out.len(),
            orig.len(),
            "random generator must preserve length"
        );
    }

    #[test]
    fn from_slice_rejects_bad_length() {
        let result = HmacGenerator::from_slice(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn credit_card_format() {
        let gen = HmacGenerator::new([11u8; 32]);
        let orig = "4111-1111-1111-1111";
        let out = gen.generate(&Category::CreditCard, orig);
        // Should be ####-####-####-####
        let parts: Vec<&str> = out.split('-').collect();
        assert_eq!(parts.len(), 4);
        for part in &parts {
            assert_eq!(part.len(), 4);
            assert!(part.chars().all(|c| c.is_ascii_digit()));
        }
        assert_eq!(out.len(), orig.len(), "credit card must preserve length");
    }

    #[test]
    fn name_format() {
        let gen = HmacGenerator::new([0u8; 32]);
        let orig = "John Doe";
        let out = gen.generate(&Category::Name, orig);
        assert_eq!(out.len(), orig.len(), "name must preserve length");
    }

    #[test]
    fn ipv6_format() {
        let gen = HmacGenerator::new([0u8; 32]);
        let orig = "fd00:abcd:1234:5678::1";
        let out = gen.generate(&Category::IpV6, orig);
        // Colons and :: preserved, length preserved.
        assert_eq!(
            out.chars().filter(|c| *c == ':').count(),
            orig.chars().filter(|c| *c == ':').count(),
            "colons must be preserved"
        );
        assert_eq!(out.len(), orig.len(), "ipv6 must preserve length");
    }

    #[test]
    fn length_preserved_all_categories() {
        let gen = HmacGenerator::new([42u8; 32]);
        let cases: Vec<(Category, &str)> = vec![
            (Category::Email, "alice@corp.com"),
            (Category::Name, "John Doe"),
            (Category::Phone, "+1-212-555-0100"),
            (Category::IpV4, "192.168.1.1"),
            (Category::IpV6, "fd00::1"),
            (Category::CreditCard, "4111-1111-1111-1111"),
            (Category::Ssn, "123-45-6789"),
            (Category::Hostname, "db-prod-01.internal"),
            (Category::MacAddress, "AA:BB:CC:DD:EE:FF"),
            (Category::ContainerId, "a1b2c3d4e5f6"),
            (Category::Uuid, "550e8400-e29b-41d4-a716-446655440000"),
            (Category::Jwt, "eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeK"),
            (Category::AuthToken, "ghp_abc123secrettoken"),
            (Category::FilePath, "/home/jsmith/config.yaml"),
            (Category::WindowsSid, "S-1-5-21-3623811015-3361044348"),
            (Category::Url, "https://internal.corp.com/api"),
            (Category::AwsArn, "arn:aws:iam::123456789012:user/admin"),
            (
                Category::AzureResourceId,
                "/subscriptions/550e8400/resourceGroups/rg-prod",
            ),
            (Category::Custom("key".into()), "some-secret-value-here"),
        ];
        for (cat, orig) in &cases {
            let out = gen.generate(cat, orig);
            assert_eq!(
                out.len(),
                orig.len(),
                "length mismatch for {:?}: '{}' ({}) -> '{}' ({})",
                cat,
                orig,
                orig.len(),
                out,
                out.len()
            );
        }
    }

    #[test]
    fn mac_address_format() {
        let gen = HmacGenerator::new([7u8; 32]);
        let orig = "AA:BB:CC:DD:EE:FF";
        let out = gen.generate(&Category::MacAddress, orig);
        assert_eq!(out.len(), orig.len(), "mac must preserve length");
        assert_eq!(
            out.chars().filter(|c| *c == ':').count(),
            5,
            "mac must preserve colons"
        );
    }

    #[test]
    fn mac_address_dash_format() {
        let gen = HmacGenerator::new([7u8; 32]);
        let orig = "AA-BB-CC-DD-EE-FF";
        let out = gen.generate(&Category::MacAddress, orig);
        assert_eq!(out.len(), orig.len());
        assert_eq!(out.chars().filter(|c| *c == '-').count(), 5);
    }

    #[test]
    fn uuid_format() {
        let gen = HmacGenerator::new([3u8; 32]);
        let orig = "550e8400-e29b-41d4-a716-446655440000";
        let out = gen.generate(&Category::Uuid, orig);
        assert_eq!(out.len(), orig.len(), "uuid must preserve length");
        assert_eq!(
            out.chars().filter(|c| *c == '-').count(),
            4,
            "uuid must preserve dashes"
        );
    }

    #[test]
    fn container_id_format() {
        let gen = HmacGenerator::new([5u8; 32]);
        let orig = "a1b2c3d4e5f6";
        let out = gen.generate(&Category::ContainerId, orig);
        assert_eq!(out.len(), orig.len(), "container id must preserve length");
        assert!(out.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn jwt_format() {
        let gen = HmacGenerator::new([11u8; 32]);
        let orig = "eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeK";
        let out = gen.generate(&Category::Jwt, orig);
        assert_eq!(out.len(), orig.len(), "jwt must preserve length");
        let orig_dots = orig.chars().filter(|c| *c == '.').count();
        let out_dots = out.chars().filter(|c| *c == '.').count();
        assert_eq!(out_dots, orig_dots, "jwt must preserve dots");
    }

    #[test]
    fn auth_token_format() {
        let gen = HmacGenerator::new([9u8; 32]);
        let orig = "ghp_abc123secrettoken";
        let out = gen.generate(&Category::AuthToken, orig);
        assert!(out.starts_with("__SANITIZED_"));
        assert!(out.ends_with("__"));
        assert_eq!(out.len(), orig.len(), "auth_token must preserve length");
    }

    #[test]
    fn filepath_unix_format() {
        let gen = HmacGenerator::new([13u8; 32]);
        let orig = "/home/jsmith/config.yaml";
        let out = gen.generate(&Category::FilePath, orig);
        assert_eq!(out.len(), orig.len(), "filepath must preserve length");
        assert_eq!(
            std::path::Path::new(&out)
                .extension()
                .and_then(|e| e.to_str()),
            Some("yaml"),
            "filepath must preserve extension"
        );
        assert_eq!(
            out.chars().filter(|c| *c == '/').count(),
            orig.chars().filter(|c| *c == '/').count(),
            "filepath must preserve separators"
        );
    }

    #[test]
    fn filepath_windows_format() {
        let gen = HmacGenerator::new([13u8; 32]);
        let orig = "C:\\Users\\admin\\secrets.txt";
        let out = gen.generate(&Category::FilePath, orig);
        assert_eq!(out.len(), orig.len(), "filepath must preserve length");
        assert_eq!(
            std::path::Path::new(&out)
                .extension()
                .and_then(|e| e.to_str()),
            Some("txt"),
            "filepath must preserve extension"
        );
        assert_eq!(
            out.chars().filter(|c| *c == '\\').count(),
            orig.chars().filter(|c| *c == '\\').count(),
            "filepath must preserve backslashes"
        );
    }

    #[test]
    fn windows_sid_format() {
        let gen = HmacGenerator::new([7u8; 32]);
        let orig = "S-1-5-21-3623811015-3361044348-30300820-1013";
        let out = gen.generate(&Category::WindowsSid, orig);
        assert_eq!(out.len(), orig.len(), "SID must preserve length");
        assert!(out.starts_with("S-"), "SID must start with S-");
        assert_eq!(
            out.chars().filter(|c| *c == '-').count(),
            orig.chars().filter(|c| *c == '-').count(),
            "SID must preserve dashes"
        );
    }

    #[test]
    fn url_format() {
        let gen = HmacGenerator::new([5u8; 32]);
        let orig = "https://internal.corp.com/api/users?token=abc123";
        let out = gen.generate(&Category::Url, orig);
        assert_eq!(out.len(), orig.len(), "url must preserve length");
        // Structural characters preserved.
        assert!(out.contains("://"));
        assert!(out.contains('?'));
        assert!(out.contains('='));
    }

    #[test]
    fn aws_arn_format() {
        let gen = HmacGenerator::new([3u8; 32]);
        let orig = "arn:aws:iam::123456789012:user/admin";
        let out = gen.generate(&Category::AwsArn, orig);
        assert_eq!(out.len(), orig.len(), "ARN must preserve length");
        assert_eq!(
            out.chars().filter(|c| *c == ':').count(),
            orig.chars().filter(|c| *c == ':').count(),
            "ARN must preserve colons"
        );
        assert!(out.contains('/'), "ARN must preserve slash");
    }

    #[test]
    fn azure_resource_id_format() {
        let gen = HmacGenerator::new([11u8; 32]);
        let orig = "/subscriptions/550e8400-e29b/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01";
        let out = gen.generate(&Category::AzureResourceId, orig);
        assert_eq!(
            out.len(),
            orig.len(),
            "Azure resource ID must preserve length"
        );
        assert!(
            out.contains("/subscriptions/"),
            "must preserve 'subscriptions'"
        );
        assert!(
            out.contains("/resourceGroups/"),
            "must preserve 'resourceGroups'"
        );
        assert!(out.contains("/providers/"), "must preserve 'providers'");
        assert!(
            out.contains("Microsoft.Compute"),
            "must preserve dotted provider name"
        );
    }

    #[test]
    fn azure_dotted_segment_outside_providers_is_replaced() {
        let gen = HmacGenerator::new([11u8; 32]);
        // A dotted segment that is NOT immediately after `providers/` must be
        // treated as a variable component and replaced, not passed through.
        // Before the fix, part.contains('.') caused this to be preserved.
        let orig = "/subscriptions/10.0.0.1/resourceGroups/rg-prod";
        let out = gen.generate(&Category::AzureResourceId, orig);
        assert_eq!(out.len(), orig.len(), "length must be preserved");
        assert!(out.contains("/subscriptions/"), "subscriptions preserved");
        assert!(out.contains("/resourceGroups/"), "resourceGroups preserved");
        assert!(
            !out.contains("10.0.0.1"),
            "dotted non-provider segment must be replaced, got: {out}"
        );
        assert!(
            !out.contains("rg-prod"),
            "variable resource group name must be replaced, got: {out}"
        );
    }
}
