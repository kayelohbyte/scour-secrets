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

/// Controls whether a replacement preserves the original's byte length or draws
/// a fresh, category-appropriate length independent of it.
///
/// `Preserve` (the default) keeps today's behavior: the replacement's byte
/// length exactly matches the original, so length and rough structure are
/// retained. `Randomized` instead picks each replacement's length from a
/// per-category band derived from the hash, uncorrelated to the original — the
/// output stays type-valid (digits stay digits, an email stays an email) but no
/// longer leaks the original's length. Non-secret structure that is copied
/// verbatim (email domain, hostname suffix, file extension, ARN/Azure known
/// segments) is unaffected by this policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum LengthPolicy {
    /// Output byte length exactly matches the original (default).
    #[default]
    Preserve,
    /// Output length is drawn from a per-category band, hiding the original's
    /// length.
    Randomized,
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
    policy: LengthPolicy,
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
        Self {
            key,
            policy: LengthPolicy::Preserve,
        }
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
        Ok(Self {
            key,
            policy: LengthPolicy::Preserve,
        })
    }

    /// Set the [`LengthPolicy`] for this generator (builder style).
    #[must_use]
    pub fn with_length_policy(mut self, policy: LengthPolicy) -> Self {
        self.policy = policy;
        self
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
        format_replacement(category, &hash, original, self.policy)
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
pub struct RandomGenerator {
    policy: LengthPolicy,
}

impl RandomGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: LengthPolicy::Preserve,
        }
    }

    /// Set the [`LengthPolicy`] for this generator (builder style).
    #[must_use]
    pub fn with_length_policy(mut self, policy: LengthPolicy) -> Self {
        self.policy = policy;
        self
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
        format_replacement(category, &hash, original, self.policy)
    }
}

// ---------------------------------------------------------------------------
// Category-aware formatting helpers
// ---------------------------------------------------------------------------

/// Format a 32-byte hash into a category-aware replacement.
///
/// Under [`LengthPolicy::Preserve`] (default) the output's byte length exactly
/// matches `original.len()`. Under [`LengthPolicy::Randomized`] the length is
/// drawn from a per-category band (see [`randomized_target`]) so it no longer
/// leaks the original's length, while the output stays type-valid. The shape is
/// deterministic for the same `(hash, original, policy)` triple.
pub(crate) fn format_replacement(
    category: &Category,
    hash: &[u8; 32],
    original: &str,
    policy: LengthPolicy,
) -> String {
    let randomized = matches!(policy, LengthPolicy::Randomized);
    let target = match policy {
        LengthPolicy::Preserve => original.len(),
        LengthPolicy::Randomized => {
            randomized_target(category, hash, original).unwrap_or(original.len())
        }
    };
    if target == 0 {
        return String::new();
    }
    let hex = hex_bytes(hash);
    match category {
        Category::Email => format_email_lp(&hex, original, target),
        Category::Name => format_name_lp(hash, &hex, target),
        // Digit categories with no canonical length: under `Randomized` we emit a
        // fresh run of `target` digits (separators dropped); IPv4 stays canonical.
        Category::Phone | Category::CreditCard if randomized => {
            format_digits_synth(hash, target, false)
        }
        Category::Ssn if randomized => format_digits_synth(hash, target, true),
        Category::Phone | Category::CreditCard | Category::IpV4 => {
            format_digits_lp(hash, original, target)
        }
        Category::IpV6 | Category::MacAddress | Category::Uuid | Category::ContainerId => {
            format_hex_digits_lp(hash, original, target)
        }
        Category::Ssn => format_ssn_lp(hash, original, target),
        Category::Hostname => format_hostname_lp(&hex, original, target),
        Category::Jwt => format_jwt_lp(hash, original, target),
        Category::FilePath => format_filepath_lp(&hex, original, target, randomized),
        Category::WindowsSid => format_windows_sid_lp(hash, original, target),
        Category::Url => format_url_lp(&hex, original, target, randomized),
        Category::AwsArn => format_arn_lp(&hex, original, target, randomized),
        Category::AzureResourceId => {
            format_azure_resource_id_lp(&hex, original, target, randomized)
        }
        Category::AuthToken | Category::Custom(_) => format_custom_lp(&hex, target),
    }
}

// ---------------------------------------------------------------------------
// Length-randomizing helpers (LengthPolicy::Randomized)
// ---------------------------------------------------------------------------

// Per-category length bands for `LengthPolicy::Randomized`. Tunable in one
// place. Digits cap at 18 so the value stays parseable as an `i64`.
const DIGITS_BAND: (usize, usize) = (8, 18);
const EMAIL_USER_BAND: (usize, usize) = (6, 16);
const HOSTNAME_PREFIX_BAND: (usize, usize) = (6, 16);
const NAME_BAND: (usize, usize) = (12, 28);
const TOKEN_BAND: (usize, usize) = (24, 48);
const SEGMENT_BAND: (usize, usize) = (6, 20);

/// Pick a length in `[lo, hi]` deterministically from `bytes`, mixing in `idx`
/// so callers can draw independent lengths for successive segments. Stable for
/// the same `(bytes, idx)`, so per-value consistency is preserved.
fn band_pick(bytes: &[u8], idx: usize, lo: usize, hi: usize) -> usize {
    debug_assert!(lo <= hi);
    debug_assert!(!bytes.is_empty());
    let span = (hi - lo + 1) as u64;
    let mut w = 0u64;
    for k in 0..8 {
        let b = bytes[(idx.wrapping_mul(8).wrapping_add(k)) % bytes.len()];
        w = (w << 8) | u64::from(b);
    }
    #[allow(clippy::cast_possible_truncation)] // (w % span) < span <= band max, fits usize
    let offset = (w % span) as usize;
    lo + offset
}

/// Total target byte length for a category under [`LengthPolicy::Randomized`].
///
/// Returns `None` for categories whose length must not change — canonical /
/// fixed-shape values (UUID, MAC, IPv4/6, container ID, Windows SID), JWT
/// (deliberate exception), and the variable-segment categories
/// (file path / URL / ARN / Azure) whose lengths are synthesized per-segment
/// inside their own formatters. For the remaining free-length categories it
/// returns a band-derived total that includes any verbatim structural overhead
/// (the `@domain`, hostname suffix, or `__SANITIZED_…__` wrapper) so the
/// existing generate-to-target formatters can be reused unchanged.
fn randomized_target(category: &Category, hash: &[u8; 32], original: &str) -> Option<usize> {
    match category {
        Category::Phone | Category::CreditCard | Category::Ssn => {
            Some(band_pick(hash, 0, DIGITS_BAND.0, DIGITS_BAND.1))
        }
        Category::Name => Some(band_pick(hash, 0, NAME_BAND.0, NAME_BAND.1)),
        Category::AuthToken | Category::Custom(_) => {
            let overhead = "__SANITIZED_".len() + "__".len();
            Some(band_pick(hash, 0, TOKEN_BAND.0, TOKEN_BAND.1) + overhead)
        }
        Category::Email => {
            let domain = original.rfind('@').map_or("x.co", |p| &original[p + 1..]);
            Some(band_pick(hash, 0, EMAIL_USER_BAND.0, EMAIL_USER_BAND.1) + 1 + domain.len())
        }
        Category::Hostname => {
            let suffix = original.find('.').map_or("", |p| &original[p..]);
            Some(band_pick(hash, 0, HOSTNAME_PREFIX_BAND.0, HOSTNAME_PREFIX_BAND.1) + suffix.len())
        }
        // Variable-segment categories synthesize per-segment lengths in their own
        // formatters; canonical/fixed-shape categories and JWT never randomize.
        Category::FilePath
        | Category::Url
        | Category::AwsArn
        | Category::AzureResourceId
        | Category::Uuid
        | Category::MacAddress
        | Category::IpV4
        | Category::IpV6
        | Category::ContainerId
        | Category::WindowsSid
        | Category::Jwt => None,
    }
}

/// Emit a fresh run of `target` deterministic digits (length-randomized digit
/// categories). When `ssn` is set the leading digit is forced to `0`, keeping
/// the value clearly synthetic.
fn format_digits_synth(hash: &[u8; 32], target: usize, ssn: bool) -> String {
    let mut buf = String::with_capacity(target);
    for i in 0..target {
        if ssn && i == 0 {
            buf.push('0');
        } else {
            buf.push((b'0' + hash[i % 32] % 10) as char);
        }
    }
    buf
}

/// Randomized variant of [`format_preserving_hex_lp`]: copy structural
/// characters verbatim, but replace each maximal run of non-structural
/// ("variable") characters with a band-derived-length hex run. Segment lengths
/// are independent of the original, so per-segment length no longer leaks.
fn format_preserving_hex_rand(
    hex: &[u8; 64],
    original: &str,
    is_structural: impl Fn(char) -> bool,
) -> String {
    let mut buf = String::with_capacity(original.len());
    let mut seg_idx = 0usize;
    let mut hi = 0usize;
    let mut in_var = false;
    for ch in original.chars() {
        if is_structural(ch) {
            buf.push(ch);
            in_var = false;
        } else if !in_var {
            // Start of a new variable segment: emit one synth-length hex run and
            // suppress the original characters of this segment.
            let seg_len = band_pick(hex, seg_idx + 1, SEGMENT_BAND.0, SEGMENT_BAND.1);
            for _ in 0..seg_len {
                buf.push(hex[hi % 64] as char);
                hi += 1;
            }
            seg_idx += 1;
            in_var = true;
        }
    }
    buf
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

/// File path replacement.
/// Preserves separators (`/`, `\`) and the final extension (from last `.`
/// in the last segment). Replaces other characters with deterministic hex.
///
/// Under `randomized`, the filename **stem** (between the last separator and the
/// extension) is emitted as a band-derived-length hex run instead of being
/// length-preserving, so the stem length no longer leaks. Other path segments
/// stay length-preserving; separators and the trailing extension stay verbatim
/// (and in place — this is the fix for the trailing-pad bug that would otherwise
/// append filler *after* the extension for a longer target).
fn format_filepath_lp(hex: &[u8; 64], original: &str, target: usize, randomized: bool) -> String {
    // Find the last path separator position to identify the filename segment.
    let last_sep = original.rfind(['/', '\\']).map_or(0, |p| p + 1);
    let filename = &original[last_sep..];
    // Find extension in the filename (last `.` that isn't at position 0).
    let ext_start = filename.rfind('.').filter(|&p| p > 0).map(|p| last_sep + p);

    if randomized {
        let mut buf = String::new();
        let mut hi = 0usize;
        // Directory prefix (up to and including the last separator): preserve
        // separators, replace other characters byte-for-byte.
        for ch in original[..last_sep].chars() {
            if matches!(ch, '/' | '\\') {
                buf.push(ch);
            } else {
                for _ in 0..ch.len_utf8() {
                    buf.push(hex[hi % 64] as char);
                    hi += 1;
                }
            }
        }
        // Filename stem: band-derived length.
        let stem_len = band_pick(hex, 0, SEGMENT_BAND.0, SEGMENT_BAND.1);
        for _ in 0..stem_len {
            buf.push(hex[hi % 64] as char);
            hi += 1;
        }
        // Extension (from the `.` to end of the original), verbatim.
        if let Some(es) = ext_start {
            buf.push_str(&original[es..]);
        }
        return buf;
    }

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

/// URL replacement.
/// Preserves scheme prefix and structural characters
/// (`://`, `/`, `?`, `=`, `&`, `#`, `:`); replaces content characters
/// with deterministic hex. Under `randomized`, each variable segment is
/// emitted with a band-derived length instead of being length-preserving.
fn format_url_lp(hex: &[u8; 64], original: &str, target: usize, randomized: bool) -> String {
    let is_structural = |ch| "/:?=&#@.".contains(ch);
    if randomized {
        return format_preserving_hex_rand(hex, original, is_structural);
    }
    format_preserving_hex_lp(hex, original, target, is_structural)
        .unwrap_or_else(|| pad_or_truncate("", target, hex))
}

/// AWS ARN replacement.
/// Preserves `:` and `/` separators; replaces alphanumeric content
/// in account/resource segments with deterministic hex. Under `randomized`,
/// each variable segment is emitted with a band-derived length.
fn format_arn_lp(hex: &[u8; 64], original: &str, target: usize, randomized: bool) -> String {
    let is_structural = |ch| ch == ':' || ch == '/';
    if randomized {
        return format_preserving_hex_rand(hex, original, is_structural);
    }
    format_preserving_hex_lp(hex, original, target, is_structural)
        .unwrap_or_else(|| pad_or_truncate("", target, hex))
}

/// Length-preserving Azure Resource ID replacement.
/// Preserves `/` path separators and well-known Azure segment names
/// (`subscriptions`, `resourceGroups`, `providers`, `resourcegroups`).
/// Replaces variable segments (IDs, names) with deterministic hex.
fn format_azure_resource_id_lp(
    hex: &[u8; 64],
    original: &str,
    target: usize,
    randomized: bool,
) -> String {
    const KNOWN_SEGMENTS: &[&str] = &[
        "subscriptions",
        "resourceGroups",
        "resourcegroups",
        "providers",
    ];

    let mut buf = String::with_capacity(target);
    let mut hi = 0usize;
    let mut seg_idx = 0usize;

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
        } else if randomized {
            // Emit a band-derived-length hex run so the variable segment's length
            // no longer leaks.
            let seg_len = band_pick(hex, seg_idx + 1, SEGMENT_BAND.0, SEGMENT_BAND.1);
            for _ in 0..seg_len {
                buf.push(hex[hi % 64] as char);
                hi += 1;
            }
            seg_idx += 1;
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
    if !randomized && buf.len() != target {
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

    // -----------------------------------------------------------------------
    // LengthPolicy::Randomized
    // -----------------------------------------------------------------------

    fn rand_gen(seed: u8) -> HmacGenerator {
        HmacGenerator::new([seed; 32]).with_length_policy(LengthPolicy::Randomized)
    }

    #[test]
    fn randomized_digits_decoupled_from_input_length() {
        let gen = rand_gen(42);
        for cat in [Category::Phone, Category::CreditCard, Category::Ssn] {
            for len in 1..40usize {
                // Build a digit input of byte length `len`.
                let orig: String = "1234567890".chars().cycle().take(len).collect();
                let out = gen.generate(&cat, &orig);
                assert!(
                    out.chars().all(|c| c.is_ascii_digit()),
                    "{cat:?} output must be all digits: {out}"
                );
                assert!(
                    out.len() >= DIGITS_BAND.0 && out.len() <= DIGITS_BAND.1,
                    "{cat:?} length {} out of band for input len {len}",
                    out.len()
                );
                if cat == Category::Ssn {
                    assert!(out.starts_with('0'), "ssn must start with 0: {out}");
                }
            }
        }
    }

    #[test]
    fn randomized_is_stable_per_value() {
        let gen = rand_gen(7);
        for (cat, orig) in [
            (Category::Phone, "+1-212-555-0100"),
            (Category::Email, "alice@corp.com"),
            (Category::Hostname, "db-prod-01.internal"),
            (Category::FilePath, "/home/jsmith/config.yaml"),
            (Category::AuthToken, "ghp_abc123secrettoken"),
        ] {
            let a = gen.generate(&cat, orig);
            let b = gen.generate(&cat, orig);
            assert_eq!(a, b, "{cat:?} must be stable for the same value");
        }
    }

    #[test]
    fn randomized_email_keeps_domain_varies_user() {
        let gen = rand_gen(3);
        // Same domain, many username lengths → output user length stays in band,
        // independent of the input's username length.
        for ulen in 1..30usize {
            let user = "a".repeat(ulen);
            let orig = format!("{user}@corp.com");
            let out = gen.generate(&Category::Email, &orig);
            assert!(out.ends_with("@corp.com"), "domain must be preserved: {out}");
            assert!(out.contains('@'));
            let out_user = out.split('@').next().unwrap().len();
            assert!(
                out_user >= EMAIL_USER_BAND.0 && out_user <= EMAIL_USER_BAND.1,
                "email user length {out_user} out of band for input ulen {ulen}"
            );
        }
    }

    #[test]
    fn randomized_hostname_keeps_suffix() {
        let gen = rand_gen(5);
        let out = gen.generate(&Category::Hostname, "db-prod-01.internal");
        assert!(out.ends_with(".internal"), "suffix must be preserved: {out}");
        let prefix = out.strip_suffix(".internal").unwrap().len();
        assert!(prefix >= HOSTNAME_PREFIX_BAND.0 && prefix <= HOSTNAME_PREFIX_BAND.1);
    }

    #[test]
    fn randomized_filepath_keeps_extension_and_separators() {
        let gen = rand_gen(13);
        let orig = "/home/jsmith/config.yaml";
        let out = gen.generate(&Category::FilePath, orig);
        assert_eq!(
            std::path::Path::new(&out)
                .extension()
                .and_then(|e| e.to_str()),
            Some("yaml"),
            "extension must stay at the end: {out}"
        );
        assert_eq!(
            out.chars().filter(|c| *c == '/').count(),
            orig.chars().filter(|c| *c == '/').count(),
            "separators must be preserved: {out}"
        );
        assert!(
            !out.ends_with("yaml") || out.contains(".yaml"),
            "must contain the .yaml extension verbatim: {out}"
        );
    }

    #[test]
    fn randomized_url_arn_keep_structure() {
        let gen = rand_gen(9);
        let url = gen.generate(&Category::Url, "https://internal.corp.com/api/users?token=abc123");
        assert!(url.contains("://"), "url scheme separator preserved: {url}");
        assert!(url.contains('?') && url.contains('='), "url query preserved: {url}");

        let arn = gen.generate(&Category::AwsArn, "arn:aws:iam::123456789012:user/admin");
        assert_eq!(
            arn.chars().filter(|c| *c == ':').count(),
            "arn:aws:iam::123456789012:user/admin"
                .chars()
                .filter(|c| *c == ':')
                .count(),
            "arn colons preserved: {arn}"
        );
        assert!(arn.contains('/'), "arn slash preserved: {arn}");
    }

    #[test]
    fn randomized_azure_keeps_known_segments() {
        let gen = rand_gen(11);
        let orig = "/subscriptions/550e8400-e29b/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01";
        let out = gen.generate(&Category::AzureResourceId, orig);
        assert!(out.contains("/subscriptions/"));
        assert!(out.contains("/resourceGroups/"));
        assert!(out.contains("/providers/"));
        assert!(out.contains("Microsoft.Compute"));
        assert!(!out.contains("rg-prod"), "variable segment must be replaced: {out}");
    }

    #[test]
    fn randomized_canonical_categories_are_noop() {
        // These categories have a canonical/fixed shape (and JWT is a deliberate
        // exception); Randomized must leave their length unchanged.
        let gen = rand_gen(1);
        let cases: Vec<(Category, &str)> = vec![
            (Category::Uuid, "550e8400-e29b-41d4-a716-446655440000"),
            (Category::MacAddress, "AA:BB:CC:DD:EE:FF"),
            (Category::IpV4, "192.168.1.1"),
            (Category::IpV6, "fd00:abcd:1234:5678::1"),
            (Category::ContainerId, "a1b2c3d4e5f6"),
            (Category::WindowsSid, "S-1-5-21-3623811015-3361044348"),
            (Category::Jwt, "eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeK"),
        ];
        for (cat, orig) in &cases {
            let out = gen.generate(cat, orig);
            assert_eq!(
                out.len(),
                orig.len(),
                "{cat:?} must stay length-preserving under Randomized: {orig} -> {out}"
            );
        }
    }

    #[test]
    fn randomized_token_is_valid_and_in_band() {
        let gen = rand_gen(9);
        for cat in [Category::AuthToken, Category::Custom("api_key".into())] {
            let out = gen.generate(&cat, "sk-abc123-some-secret-value");
            assert!(out.starts_with("__SANITIZED_"), "{cat:?}: {out}");
            assert!(out.ends_with("__"), "{cat:?}: {out}");
            let overhead = "__SANITIZED_".len() + "__".len();
            let hex_len = out.len() - overhead;
            assert!(
                hex_len >= TOKEN_BAND.0 && hex_len <= TOKEN_BAND.1,
                "{cat:?} token hex length {hex_len} out of band"
            );
        }
    }
}
