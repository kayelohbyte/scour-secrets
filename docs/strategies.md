# Pluggable Strategies

The `Strategy` trait provides an extensible replacement mechanism independent of the built-in category formatters. Strategies are **pure functions** of `(original, entropy)` — they receive 32 bytes of caller-provided entropy and produce a replacement string. Determinism is controlled externally by the entropy source, not by the strategy itself.

## Architecture

```text
MappingStore
  └─ owns Arc<dyn ReplacementGenerator>
       └─ StrategyGenerator (adapter)
            └─ calls dyn Strategy::replace(original, &entropy)
```

`StrategyGenerator` bridges the `Strategy` trait to `ReplacementGenerator` (which `MappingStore` expects). It produces entropy based on `EntropyMode`:

- **`EntropyMode::Deterministic { key }`** — entropy is `HMAC-SHA256(key, category_tag || "\x00" || original)`. Same key + same input = same entropy = same replacement.
- **`EntropyMode::Random`** — entropy comes from OS CSPRNG. The `MappingStore` dedup cache still ensures per-run consistency.

## Built-in Strategies

| Strategy | `name()` | Output Format | Length | Notes |
|----------|----------|---------------|--------|-------|
| `RandomString` | `"random_string"` | Alphanumeric `[a-zA-Z0-9]` | Configurable (default 16, range 1–64) | `RandomString::new()` or `RandomString::with_length(n)` |
| `RandomUuid` | `"random_uuid"` | UUID v4 format `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` | Always 36 | Version nibble = 4, variant ∈ {8,9,a,b} |
| `FakeIp` | `"fake_ip"` | Dot positions preserved; other characters replaced with entropy-derived decimal digits | Same as original | Preserves column widths and log formatting |
| `PreserveLength` | `"preserve_length"` | Lowercase alphanumeric `[a-z0-9]` | Same as original | Deterministic PRNG seeded from entropy |
| `HmacHash` | `"hmac_hash"` | Lowercase hex | Configurable (default 32, max 64) | Carries own HMAC key; deterministic by construction regardless of entropy mode |

## Library API Example

```rust
use rust_sanitize::strategy::{PreserveLength, StrategyGenerator, EntropyMode};
use rust_sanitize::store::MappingStore;
use rust_sanitize::category::Category;
use std::sync::Arc;

// Create a strategy-based generator with deterministic entropy.
let strategy = PreserveLength;
let mode = EntropyMode::Deterministic { key: [42u8; 32] };
let generator = Arc::new(StrategyGenerator::new(
    Box::new(strategy),
    mode,
));

// Use it with MappingStore as usual.
let store = MappingStore::new(generator, None);
let replaced = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert_eq!(replaced.len(), "alice@corp.com".len());
```

## Writing a Custom Strategy

Implement the `Strategy` trait and wrap it in `StrategyGenerator`:

```rust
use rust_sanitize::strategy::Strategy;

struct Redact;

impl Strategy for Redact {
    fn name(&self) -> &str { "redact" }

    fn replace(&self, original: &str, _entropy: &[u8; 32]) -> String {
        "X".repeat(original.len())
    }
}
```

The trait is object-safe — third-party crates can implement `Strategy` without modifying this crate.
