//! Pluggable replacement strategies.
//!
//! This module provides the [`Strategy`] trait and six built-in
//! implementations that can be composed with the mapping engine via
//! [`StrategyGenerator`], an adapter that implements
//! [`ReplacementGenerator`].
//!
//! # Design Note
//!
//! This is the **extensibility layer** for library consumers who need custom
//! replacement logic. The CLI binary uses [`crate::generator::HmacGenerator`]
//! and [`crate::generator::RandomGenerator`] directly with category-aware
//! formatters for performance and simplicity. Both paths share the same
//! [`ReplacementGenerator`] interface. See `ARCHITECTURE.md` section 2 for
//! details on the dual-path design.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────┐
//! │    MappingStore       │  ← owns Arc<dyn ReplacementGenerator>
//! └──────────┬───────────┘
//!            │ calls generate(category, original)
//!            ▼
//! ┌──────────────────────┐
//! │  StrategyGenerator   │  ← adapter: produces entropy, delegates to Strategy
//! │  (ReplacementGenerator)│
//! └──────────┬───────────┘
//!            │ calls replace(original, &entropy)
//!            ▼
//! ┌──────────────────────┐
//! │   dyn Strategy       │  ← pure function of (original, entropy) → String
//! │                      │
//! │  RandomString        │
//! │  RandomUuid          │
//! │  FakeIp              │
//! │  PreserveLength      │
//! │  HmacHash            │
//! └──────────────────────┘
//! ```
//!
//! # Deterministic Mode
//!
//! Strategies are pure functions of `(original, entropy)`. Determinism is
//! controlled by the **entropy source** inside [`StrategyGenerator`]:
//!
//! - **Deterministic** (`EntropyMode::Deterministic`): entropy is derived
//!   via HMAC-SHA256 keyed with a fixed seed — same seed + same input →
//!   same replacement across runs.
//! - **Random** (`EntropyMode::Random`): entropy comes from OS CSPRNG —
//!   each call produces a fresh value (but the `MappingStore` still caches
//!   the first result per unique input for per-run consistency).
//!
//! The [`HmacHash`] strategy is an exception: it carries its own HMAC key
//! and is deterministic by construction regardless of the entropy mode.
//!
//! # Extensibility
//!
//! To add a new replacement strategy:
//!
//! 1. Create a struct implementing [`Strategy`].
//! 2. Return a unique name from [`Strategy::name`].
//! 3. Implement [`Strategy::replace`] as a pure function of `(category, original, entropy)`.
//! 4. Wrap it in a [`StrategyGenerator`] to use with `MappingStore`.
//!
//! Third-party crates can implement `Strategy` without modifying this crate,
//! since the trait is public and object-safe.

use crate::category::Category;
use crate::generator::ReplacementGenerator;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Strategy trait
// ---------------------------------------------------------------------------

/// A pluggable replacement strategy.
///
/// Strategies transform an original sensitive value into a sanitized
/// replacement using 32 bytes of caller-provided entropy. They MUST be
/// **pure functions** of their inputs: the same `(original, entropy)` pair
/// always produces the same output.
///
/// Strategies are agnostic to how entropy is produced (HMAC-deterministic
/// or CSPRNG-random). That concern is handled by [`StrategyGenerator`].
///
/// # Stability
///
/// This trait is open for third-party implementations. New methods, if any,
/// will always ship with default implementations, so implementing it today
/// remains forward-compatible.
pub trait Strategy: Send + Sync {
    /// Human-readable, unique name for this strategy (e.g. `"random_string"`).
    fn name(&self) -> &'static str;

    /// Produce a sanitized replacement for `original` using `entropy`.
    ///
    /// # Contract
    ///
    /// - Must be deterministic: same `(category, original, entropy)` → same output.
    /// - Must not perform I/O or access external mutable state.
    /// - Returned value should be clearly synthetic / non-sensitive.
    fn replace(&self, category: &Category, original: &str, entropy: &[u8; 32]) -> String;
}

// ---------------------------------------------------------------------------
// Entropy mode (used by StrategyGenerator)
// ---------------------------------------------------------------------------

/// How entropy is produced for strategies.
#[derive(Debug)]
#[non_exhaustive]
pub enum EntropyMode {
    /// Deterministic: `entropy = HMAC-SHA256(key, category || '\0' || original)`.
    #[non_exhaustive]
    Deterministic {
        /// 32-byte HMAC key (seed).
        key: [u8; 32],
    },
    /// Random: entropy is drawn from OS CSPRNG on every call.
    Random,
}

impl EntropyMode {
    /// Deterministic entropy seeded with a 32-byte HMAC key. The variant is
    /// `#[non_exhaustive]`, so this is how it is constructed outside the crate.
    #[must_use]
    pub fn deterministic(key: [u8; 32]) -> Self {
        Self::Deterministic { key }
    }
}

impl Drop for EntropyMode {
    fn drop(&mut self) {
        if let EntropyMode::Deterministic { ref mut key } = self {
            key.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// StrategyGenerator — adapter from Strategy → ReplacementGenerator
// ---------------------------------------------------------------------------

/// Adapter that bridges a [`Strategy`] into the [`ReplacementGenerator`]
/// interface consumed by [`MappingStore`](crate::store::MappingStore).
///
/// It produces entropy according to the configured [`EntropyMode`] and
/// delegates replacement formatting to the wrapped strategy.
pub struct StrategyGenerator {
    strategy: Box<dyn Strategy>,
    mode: EntropyMode,
}

impl StrategyGenerator {
    /// Create a new adapter.
    ///
    /// # Arguments
    ///
    /// - `strategy` — the replacement strategy to use.
    /// - `mode` — how to produce entropy (deterministic seed or random).
    #[must_use]
    pub fn new(strategy: Box<dyn Strategy>, mode: EntropyMode) -> Self {
        Self { strategy, mode }
    }

    /// Produce 32 bytes of entropy for `(category, original)`.
    fn entropy(&self, category: &Category, original: &str) -> [u8; 32] {
        match &self.mode {
            EntropyMode::Deterministic { key } => {
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
                let tag = category.domain_tag_hmac();
                mac.update(tag.as_bytes());
                mac.update(b"\x00");
                mac.update(original.as_bytes());
                let result = mac.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&result.into_bytes());
                out
            }
            EntropyMode::Random => {
                let mut buf = [0u8; 32];
                rand::rng().fill(&mut buf);
                buf
            }
        }
    }

    /// Access the underlying strategy.
    #[must_use]
    pub fn strategy(&self) -> &dyn Strategy {
        self.strategy.as_ref()
    }
}

impl ReplacementGenerator for StrategyGenerator {
    fn generate(&self, category: &Category, original: &str) -> String {
        let entropy = self.entropy(category, original);
        self.strategy.replace(category, original, &entropy)
    }
}

// ===========================================================================
// Built-in strategies
// ===========================================================================

/// Seed a 64-bit xorshift PRNG from a 32-byte entropy buffer.
///
/// Folds the four 8-byte little-endian chunks via wrapping addition so that
/// all 256 bits of entropy influence the initial state. Guards against the
/// degenerate all-zero state that would cause xorshift64 to produce only zeros.
#[inline]
fn xorshift64_seed(entropy: &[u8; 32]) -> u64 {
    let mut state = 0u64;
    for chunk in entropy.chunks_exact(8) {
        let arr: [u8; 8] = chunk
            .try_into()
            .expect("chunks_exact(8) yields 8-byte slices");
        state = state.wrapping_add(u64::from_le_bytes(arr));
    }
    if state == 0 {
        state = 0xDEAD_BEEF_CAFE_BABE;
    }
    state
}

/// Advance a xorshift64 PRNG state by one step.
#[inline]
fn xorshift64_step(state: &mut u64) {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
}

// ---------------------------------------------------------------------------
// 1. RandomString
// ---------------------------------------------------------------------------

/// Generates an alphanumeric string from entropy bytes.
///
/// The output length defaults to 16 characters but can be configured.
/// Characters are drawn from `[a-zA-Z0-9]`.
pub struct RandomString {
    /// Desired output length (capped at 64).
    len: usize,
}

impl RandomString {
    /// Create with default length (16).
    #[must_use]
    pub fn new() -> Self {
        Self { len: 16 }
    }

    /// Create with a specific output length (clamped to 1..=64).
    #[must_use]
    pub fn with_length(len: usize) -> Self {
        Self {
            len: len.clamp(1, 64),
        }
    }
}

impl Default for RandomString {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for RandomString {
    fn name(&self) -> &'static str {
        "random_string"
    }

    fn replace(&self, _category: &Category, _original: &str, entropy: &[u8; 32]) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                                  ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                  0123456789";
        let mut chars = String::with_capacity(self.len);
        let mut state = xorshift64_seed(entropy);

        for _ in 0..self.len {
            xorshift64_step(&mut state);
            #[allow(clippy::cast_possible_truncation)]
            // truncation is intentional for index mapping
            let idx = (state as usize) % CHARSET.len();
            chars.push(CHARSET[idx] as char);
        }
        chars
    }
}

// ---------------------------------------------------------------------------
// 2. RandomUuid
// ---------------------------------------------------------------------------

/// Generates a UUID v4–formatted string from entropy bytes.
///
/// The output looks like `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` where
/// `x` is a hex digit derived from entropy and `y ∈ {8,9,a,b}` per RFC 4122.
/// When backed by deterministic entropy, the UUID is stable.
pub struct RandomUuid;

impl RandomUuid {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RandomUuid {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for RandomUuid {
    fn name(&self) -> &'static str {
        "random_uuid"
    }

    fn replace(&self, _category: &Category, _original: &str, entropy: &[u8; 32]) -> String {
        // Take the first 16 bytes to form a UUID.
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&entropy[..16]);

        // Set version = 4 (bits 4-7 of byte 6).
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        // Set variant = RFC 4122 (bits 6-7 of byte 8).
        bytes[8] = (bytes[8] & 0x3F) | 0x80;

        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        )
    }
}

// ---------------------------------------------------------------------------
// 3. FakeIp
// ---------------------------------------------------------------------------

/// Generates a length-preserving fake IP address.
///
/// Dots (`.`) are preserved in their original positions; every other
/// character is replaced with a deterministic decimal digit derived from
/// `entropy`. The output is always the same byte length as `original`,
/// preserving column widths and log formatting.
pub struct FakeIp;

impl FakeIp {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for FakeIp {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for FakeIp {
    fn name(&self) -> &'static str {
        "fake_ip"
    }

    fn replace(&self, _category: &Category, original: &str, entropy: &[u8; 32]) -> String {
        // Preserve dots; replace every other character with a deterministic
        // digit so the output has the same byte length as the original.
        let mut buf = String::with_capacity(original.len());
        let mut hi = 0usize;
        for ch in original.chars() {
            if ch == '.' {
                buf.push('.');
            } else {
                buf.push((b'0' + entropy[hi % 32] % 10) as char);
                hi += 1;
            }
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// 4. PreserveLength
// ---------------------------------------------------------------------------

/// Generates a replacement with the **same byte length** as the original.
///
/// Useful when column widths, fixed-length fields, or alignment must be
/// maintained. Uses lowercase hex characters derived from entropy.
pub struct PreserveLength;

impl PreserveLength {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for PreserveLength {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for PreserveLength {
    fn name(&self) -> &'static str {
        "preserve_length"
    }

    fn replace(&self, _category: &Category, original: &str, entropy: &[u8; 32]) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

        let target_len = original.len();
        if target_len == 0 {
            return String::new();
        }

        let mut state = xorshift64_seed(entropy);
        let mut result = String::with_capacity(target_len);
        for _ in 0..target_len {
            xorshift64_step(&mut state);
            #[allow(clippy::cast_possible_truncation)]
            // truncation is intentional for index mapping
            let idx = (state as usize) % CHARSET.len();
            result.push(CHARSET[idx] as char);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// 5. HmacHash
// ---------------------------------------------------------------------------

/// HMAC-SHA256 hash strategy — deterministic by construction.
///
/// Unlike the other strategies, `HmacHash` carries its own 32-byte key and
/// computes `HMAC-SHA256(key, original)` directly. The caller-provided
/// entropy is **ignored**. This makes the output deterministic regardless
/// of the [`EntropyMode`] used by [`StrategyGenerator`].
///
/// The output is a lowercase hex string, optionally truncated to
/// `output_len` characters (default: 32).
pub struct HmacHash {
    key: [u8; 32],
    /// Number of hex characters to emit (max 64).
    output_len: usize,
}

impl HmacHash {
    /// Create with both a key and a default output length (32 hex chars).
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            output_len: 32,
        }
    }

    /// Create with a custom output length (clamped to 1..=64).
    #[must_use]
    pub fn with_output_len(key: [u8; 32], output_len: usize) -> Self {
        Self {
            key,
            output_len: output_len.clamp(1, 64),
        }
    }
}

impl Strategy for HmacHash {
    fn name(&self) -> &'static str {
        "hmac_hash"
    }

    fn replace(&self, _category: &Category, original: &str, _entropy: &[u8; 32]) -> String {
        use std::fmt::Write;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(original.as_bytes());
        let result = mac.finalize();
        let hash_bytes: [u8; 32] = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&result.into_bytes());
            buf
        };
        let mut hex = String::with_capacity(64);
        for b in &hash_bytes {
            let _ = write!(hex, "{:02x}", b);
        }
        hex[..self.output_len].to_string()
    }
}

// ---------------------------------------------------------------------------
// 6. CategoryAwareStrategy
// ---------------------------------------------------------------------------

/// Built-in strategy that delegates to the same category-aware formatters
/// used by the CLI.
///
/// Replacements are shaped to match their category: email-shaped for emails,
/// IP-shaped for IPs, JWT-shaped for JWTs, and so on — identical output
/// quality to what [`HmacGenerator`](crate::generator::HmacGenerator)
/// produces. Use this strategy when you want full structured replacement
/// behaviour through the [`Strategy`] / [`StrategyGenerator`] path.
pub struct CategoryAwareStrategy;

impl CategoryAwareStrategy {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for CategoryAwareStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for CategoryAwareStrategy {
    fn name(&self) -> &'static str {
        "category_aware"
    }

    fn replace(&self, category: &Category, original: &str, entropy: &[u8; 32]) -> String {
        crate::generator::format_replacement(
            category,
            entropy,
            original,
            crate::generator::LengthPolicy::Preserve,
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use std::sync::Arc;

    /// Helper: fixed deterministic entropy for testing.
    fn test_entropy() -> [u8; 32] {
        let mut e = [0u8; 32];
        for (i, b) in e.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)] // i is always < 32, fits in u8
            {
                *b = (i as u8).wrapping_mul(37).wrapping_add(7);
            }
        }
        e
    }

    // ---- Strategy trait: purity / determinism ----

    #[test]
    fn strategies_are_deterministic() {
        let entropy = test_entropy();
        let strategies: Vec<Box<dyn Strategy>> = vec![
            Box::new(RandomString::new()),
            Box::new(RandomUuid::new()),
            Box::new(FakeIp::new()),
            Box::new(PreserveLength::new()),
            Box::new(HmacHash::new([42u8; 32])),
            Box::new(CategoryAwareStrategy::new()),
        ];
        for s in &strategies {
            let a = s.replace(&Category::AuthToken, "hello world", &entropy);
            let b = s.replace(&Category::AuthToken, "hello world", &entropy);
            assert_eq!(a, b, "strategy '{}' must be deterministic", s.name());
        }
    }

    #[test]
    fn different_entropy_different_output() {
        let e1 = [1u8; 32];
        let e2 = [2u8; 32];
        let strategies: Vec<Box<dyn Strategy>> = vec![
            Box::new(RandomString::new()),
            Box::new(RandomUuid::new()),
            Box::new(FakeIp::new()),
            Box::new(PreserveLength::new()),
            Box::new(CategoryAwareStrategy::new()),
        ];
        for s in &strategies {
            let a = s.replace(&Category::AuthToken, "test", &e1);
            let b = s.replace(&Category::AuthToken, "test", &e2);
            assert_ne!(
                a,
                b,
                "strategy '{}' should differ with different entropy",
                s.name()
            );
        }
    }

    // ---- RandomString ----

    #[test]
    fn random_string_default_length() {
        let s = RandomString::new();
        let out = s.replace(&Category::AuthToken, "anything", &test_entropy());
        assert_eq!(out.len(), 16);
        assert!(
            out.chars().all(|c| c.is_ascii_alphanumeric()),
            "output must be alphanumeric: {}",
            out,
        );
    }

    #[test]
    fn random_string_custom_length() {
        let s = RandomString::with_length(8);
        let out = s.replace(&Category::AuthToken, "anything", &test_entropy());
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn random_string_clamped_length() {
        let s = RandomString::with_length(999);
        assert_eq!(s.len, 64);
        let s = RandomString::with_length(0);
        assert_eq!(s.len, 1);
    }

    // ---- RandomUuid ----

    #[test]
    fn random_uuid_format() {
        let s = RandomUuid::new();
        let out = s.replace(&Category::AuthToken, "anything", &test_entropy());
        // 8-4-4-4-12 = 36 chars
        assert_eq!(out.len(), 36, "UUID must be 36 chars: {}", out);
        let parts: Vec<&str> = out.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        // Version nibble = 4
        assert_eq!(&parts[2][0..1], "4", "version must be 4");
        // Variant nibble ∈ {8,9,a,b}
        let variant = &parts[3][0..1];
        assert!(
            ["8", "9", "a", "b"].contains(&variant),
            "variant nibble must be 8/9/a/b, got {}",
            variant,
        );
    }

    // ---- FakeIp ----

    #[test]
    fn fake_ip_format() {
        let s = FakeIp::new();
        let input = "192.168.1.1";
        let out = s.replace(&Category::IpV4, input, &test_entropy());
        // Length preserved.
        assert_eq!(
            out.len(),
            input.len(),
            "FakeIp must preserve length: {}",
            out
        );
        // Dot positions preserved.
        let in_dots: Vec<usize> = input
            .char_indices()
            .filter(|&(_, c)| c == '.')
            .map(|(i, _)| i)
            .collect();
        let out_dots: Vec<usize> = out
            .char_indices()
            .filter(|&(_, c)| c == '.')
            .map(|(i, _)| i)
            .collect();
        assert_eq!(out_dots, in_dots, "FakeIp must preserve dot positions");
        // Non-dot characters must be ASCII digits.
        assert!(
            out.chars().all(|c| c == '.' || c.is_ascii_digit()),
            "FakeIp output must contain only digits and dots: {}",
            out
        );
        // Must differ from input.
        assert_ne!(out, input, "FakeIp must change the IP");
    }

    // ---- PreserveLength ----

    #[test]
    fn preserve_length_matches() {
        let s = PreserveLength::new();
        for input in &["a", "hello", "this is a fairly long string indeed", ""] {
            let out = s.replace(&Category::AuthToken, input, &test_entropy());
            assert_eq!(
                out.len(),
                input.len(),
                "length mismatch for input '{}'",
                input,
            );
        }
    }

    #[test]
    fn preserve_length_characters() {
        let s = PreserveLength::new();
        let out = s.replace(&Category::AuthToken, "hello!", &test_entropy());
        assert!(
            out.chars().all(|c| c.is_ascii_alphanumeric()),
            "output must be alphanumeric: {}",
            out,
        );
    }

    // ---- HmacHash ----

    #[test]
    fn hmac_hash_deterministic_with_key() {
        let s = HmacHash::new([42u8; 32]);
        let a = s.replace(&Category::AuthToken, "secret", &[0u8; 32]);
        let b = s.replace(&Category::AuthToken, "secret", &[0xFF; 32]);
        // Entropy is ignored — result depends only on key + original.
        assert_eq!(a, b, "HmacHash must ignore entropy");
    }

    #[test]
    fn hmac_hash_default_length() {
        let s = HmacHash::new([0u8; 32]);
        let out = s.replace(&Category::AuthToken, "test", &[0u8; 32]);
        assert_eq!(out.len(), 32, "default output is 32 hex chars");
        assert!(
            out.chars().all(|c| c.is_ascii_hexdigit()),
            "output must be hex: {}",
            out,
        );
    }

    #[test]
    fn hmac_hash_custom_length() {
        let s = HmacHash::with_output_len([0u8; 32], 12);
        let out = s.replace(&Category::AuthToken, "test", &[0u8; 32]);
        assert_eq!(out.len(), 12);
    }

    #[test]
    fn hmac_hash_different_keys() {
        let s1 = HmacHash::new([1u8; 32]);
        let s2 = HmacHash::new([2u8; 32]);
        let a = s1.replace(&Category::AuthToken, "test", &[0u8; 32]);
        let b = s2.replace(&Category::AuthToken, "test", &[0u8; 32]);
        assert_ne!(a, b, "different keys must produce different output");
    }

    #[test]
    fn hmac_hash_different_inputs() {
        let s = HmacHash::new([42u8; 32]);
        let a = s.replace(&Category::AuthToken, "alice", &[0u8; 32]);
        let b = s.replace(&Category::AuthToken, "bob", &[0u8; 32]);
        assert_ne!(a, b);
    }

    // ---- StrategyGenerator integration ----

    #[test]
    fn strategy_generator_deterministic() {
        let strat = Box::new(RandomString::new());
        let gen = StrategyGenerator::new(strat, EntropyMode::Deterministic { key: [42u8; 32] });
        let a = gen.generate(&Category::Email, "alice@corp.com");
        let b = gen.generate(&Category::Email, "alice@corp.com");
        assert_eq!(a, b, "deterministic mode must be repeatable");
    }

    #[test]
    fn strategy_generator_different_categories() {
        let strat = Box::new(RandomString::new());
        let gen = StrategyGenerator::new(strat, EntropyMode::Deterministic { key: [42u8; 32] });
        let a = gen.generate(&Category::Email, "test");
        let b = gen.generate(&Category::Name, "test");
        assert_ne!(a, b, "different categories must produce different entropy");
    }

    #[test]
    fn strategy_generator_with_store() {
        let strat = Box::new(RandomUuid::new());
        let gen = Arc::new(StrategyGenerator::new(
            strat,
            EntropyMode::Deterministic { key: [99u8; 32] },
        ));
        let store = crate::store::MappingStore::new(gen, None);

        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        let s2 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        assert_eq!(s1, s2, "store must cache strategy output");
        assert_eq!(s1.len(), 36, "output must be UUID-formatted");
    }

    #[test]
    fn strategy_generator_random_cached_in_store() {
        let strat = Box::new(FakeIp::new());
        let gen = Arc::new(StrategyGenerator::new(strat, EntropyMode::Random));
        let store = crate::store::MappingStore::new(gen, None);

        let s1 = store.get_or_insert(&Category::IpV4, "192.168.1.1").unwrap();
        let s2 = store.get_or_insert(&Category::IpV4, "192.168.1.1").unwrap();
        // Random entropy, but store caches first result.
        assert_eq!(s1, s2);
        assert_eq!(
            s1.len(),
            "192.168.1.1".len(),
            "FakeIp must preserve input length"
        );
    }

    #[test]
    fn all_strategies_implement_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RandomString>();
        assert_send_sync::<RandomUuid>();
        assert_send_sync::<FakeIp>();
        assert_send_sync::<PreserveLength>();
        assert_send_sync::<HmacHash>();
        assert_send_sync::<CategoryAwareStrategy>();
        assert_send_sync::<StrategyGenerator>();
    }

    #[test]
    fn strategy_names_unique() {
        let strategies: Vec<Box<dyn Strategy>> = vec![
            Box::new(RandomString::new()),
            Box::new(RandomUuid::new()),
            Box::new(FakeIp::new()),
            Box::new(PreserveLength::new()),
            Box::new(HmacHash::new([0u8; 32])),
            Box::new(CategoryAwareStrategy::new()),
        ];
        let mut names: Vec<&str> = strategies.iter().map(|s| s.name()).collect();
        let len_before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), len_before, "strategy names must be unique");
    }

    // ---- Concurrent use via StrategyGenerator + MappingStore ----

    #[test]
    fn concurrent_strategy_generator() {
        use std::thread;

        let strat = Box::new(PreserveLength::new());
        let gen = Arc::new(StrategyGenerator::new(
            strat,
            EntropyMode::Deterministic { key: [7u8; 32] },
        ));
        let store = Arc::new(crate::store::MappingStore::new(gen, None));

        let mut handles = vec![];
        for t in 0..4 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for i in 0..500 {
                    let val = format!("thread{}-val{}", t, i);
                    let result = store.get_or_insert(&Category::Name, &val).unwrap();
                    assert_eq!(
                        result.len(),
                        val.len(),
                        "PreserveLength must match input length",
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.len(), 2000);
    }

    // ---- CategoryAwareStrategy ----

    #[test]
    fn category_aware_email_shaped() {
        let s = CategoryAwareStrategy::new();
        let input = "alice@corp.com";
        let out = s.replace(&Category::Email, input, &test_entropy());
        assert_eq!(out.len(), input.len(), "length must be preserved");
        assert!(out.contains('@'), "output must be email-shaped");
        assert!(out.ends_with("@corp.com"), "domain must be preserved");
    }

    #[test]
    fn category_aware_length_preserved_across_categories() {
        let s = CategoryAwareStrategy::new();
        let cases = [
            (Category::Email, "alice@corp.com"),
            (Category::IpV4, "192.168.1.1"),
            (Category::AuthToken, "ghp_abc123secrettoken"),
            (Category::Hostname, "db-prod.internal"),
        ];
        for (cat, input) in &cases {
            let out = s.replace(cat, input, &test_entropy());
            assert_eq!(out.len(), input.len(), "length mismatch for {:?}", cat);
            assert_ne!(out, *input, "output must differ from input for {:?}", cat);
        }
    }

    #[test]
    fn category_aware_random_mode_consistent_within_run() {
        // EntropyMode::Random produces fresh entropy each call, but the
        // MappingStore dedup cache must still guarantee per-run consistency.
        let gen = Arc::new(StrategyGenerator::new(
            Box::new(CategoryAwareStrategy::new()),
            EntropyMode::Random,
        ));
        let store = crate::store::MappingStore::new(gen, None);
        let r1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        let r2 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        assert_eq!(
            r1, r2,
            "store cache must return same replacement within run"
        );
        assert!(r1.contains('@'), "replacement must be email-shaped");
        assert_eq!(r1.len(), "alice@corp.com".len(), "length must be preserved");
    }

    #[test]
    fn category_aware_deterministic() {
        let s = CategoryAwareStrategy::new();
        let entropy = test_entropy();
        let a = s.replace(&Category::Email, "alice@corp.com", &entropy);
        let b = s.replace(&Category::Email, "alice@corp.com", &entropy);
        assert_eq!(a, b, "category_aware must be deterministic");
    }

    // ---- Property tests: structural invariants on generated values ----

    mod property {
        use super::*;
        use crate::store::MappingStore;
        use proptest::prelude::*;

        fn hmac_store() -> MappingStore {
            let gen = Arc::new(crate::generator::HmacGenerator::new([77u8; 32]));
            MappingStore::new(gen, None)
        }

        fn category_aware_store() -> MappingStore {
            let gen = Arc::new(StrategyGenerator::new(
                Box::new(CategoryAwareStrategy::new()),
                EntropyMode::Deterministic { key: [77u8; 32] },
            ));
            MappingStore::new(gen, None)
        }

        proptest! {
            #[test]
            fn category_aware_length_preserved(s in "[a-z0-9]{1,64}") {
                let store = category_aware_store();
                let out = store.get_or_insert(&Category::AuthToken, &s).unwrap();
                prop_assert_eq!(out.len(), s.len());
            }

            #[test]
            fn category_aware_email_shaped(
                local in "[a-z]{3,8}",
                domain in "[a-z]{3,8}",
                tld in "[a-z]{2,4}",
            ) {
                let input = format!("{local}@{domain}.{tld}");
                let store = category_aware_store();
                let out = store.get_or_insert(&Category::Email, &input).unwrap();
                prop_assert_eq!(out.len(), input.len());
                prop_assert!(out.contains('@'));
                let after_at = out.split('@').nth(1).unwrap_or("");
                prop_assert!(after_at.contains('.'));
            }

            #[test]
            fn email_output_is_email_shaped(
                local in "[a-z]{3,8}",
                domain in "[a-z]{3,8}",
                tld in "[a-z]{2,4}",
            ) {
                let input = format!("{local}@{domain}.{tld}");
                let store = hmac_store();
                let out = store.get_or_insert(&Category::Email, &input).unwrap();
                prop_assert_eq!(out.chars().filter(|&c| c == '@').count(), 1);
                let after = out.split('@').nth(1).unwrap_or("");
                prop_assert!(after.contains('.'), "no dot in domain part: {out}");
                prop_assert_eq!(out.len(), input.len());
            }

            #[test]
            fn ipv4_output_preserves_dot_structure(
                a in 0u8..=255u8,
                b in 0u8..=255u8,
                c in 0u8..=255u8,
                d in 0u8..=255u8,
            ) {
                let input = format!("{a}.{b}.{c}.{d}");
                let store = hmac_store();
                let out = store.get_or_insert(&Category::IpV4, &input).unwrap();
                // The strategy preserves dot positions and digit counts but does
                // not clamp octet values to 0-255 (e.g. 114 → 987 is valid output).
                // Invariant: 4 dot-separated groups, each containing only digits,
                // each with the same digit count as the original octet.
                let in_parts: Vec<&str> = input.split('.').collect();
                let out_parts: Vec<&str> = out.split('.').collect();
                prop_assert_eq!(out_parts.len(), 4);
                for (inp, outp) in in_parts.iter().zip(out_parts.iter()) {
                    prop_assert_eq!(inp.len(), outp.len());
                    prop_assert!(outp.chars().all(|c| c.is_ascii_digit()));
                }
            }

            #[test]
            fn same_input_always_same_output(s in "[a-z0-9]{4,12}@[a-z]{4,8}\\.com") {
                let store = hmac_store();
                let out1 = store.get_or_insert(&Category::Email, &s).unwrap();
                let out2 = store.get_or_insert(&Category::Email, &s).unwrap();
                prop_assert_eq!(out1, out2);
            }

            #[test]
            fn different_categories_produce_different_outputs(s in "[a-z]{6,10}") {
                let store = hmac_store();
                let as_email = store.get_or_insert(&Category::Email, &format!("{s}@corp.com")).unwrap();
                let as_name  = store.get_or_insert(&Category::Name,  &format!("{s}@corp.com")).unwrap();
                prop_assert_ne!(as_email, as_name);
            }
        }
    }
}
