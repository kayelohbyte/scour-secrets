# Pluggable Strategies

The `Strategy` trait is the extension point for generating sanitized replacements.
Strategies are **pure functions** of `(category, original, entropy)` — they receive
the [`Category`] of the matched value, the original string, and 32 bytes of
caller-provided entropy, and return a replacement string. Determinism is controlled
externally by the entropy source, not by the strategy itself.

## Architecture

```text
MappingStore
  └─ owns Arc<dyn ReplacementGenerator>
       └─ StrategyGenerator (adapter)
            ├─ produces entropy from EntropyMode (HMAC or CSPRNG)
            └─ calls dyn Strategy::replace(category, original, &entropy)
```

`StrategyGenerator` bridges the `Strategy` trait to `ReplacementGenerator` (which
`MappingStore` expects). It produces entropy based on `EntropyMode`:

- **`EntropyMode::Deterministic { key }`** — entropy is `HMAC-SHA256(key, category_tag || "\x00" || original)`. Same key + same input = same entropy = same replacement.
- **`EntropyMode::Random`** — entropy comes from OS CSPRNG. The `MappingStore` dedup cache still ensures per-run consistency.

## Built-in Strategies

| Strategy | `name()` | Output Format | Length | Notes |
|---|---|---|---|---|
| `CategoryAwareStrategy` | `"category_aware"` | Category-shaped: email → email, IP → IP, JWT → JWT, etc. | Same as original | Delegates to the same formatters as the CLI. Recommended default for library consumers. |
| `RandomString` | `"random_string"` | Alphanumeric `[a-zA-Z0-9]` | Configurable (default 16, range 1–64) | `RandomString::new()` or `RandomString::with_length(n)` |
| `RandomUuid` | `"random_uuid"` | UUID v4 format `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` | Always 36 | Version nibble = 4, variant ∈ {8,9,a,b} |
| `FakeIp` | `"fake_ip"` | Dot positions preserved; other characters replaced with entropy-derived decimal digits | Same as original | Preserves column widths and log formatting |
| `PreserveLength` | `"preserve_length"` | Lowercase alphanumeric `[a-z0-9]` | Same as original | Deterministic PRNG seeded from entropy |
| `HmacHash` | `"hmac_hash"` | Lowercase hex | Configurable (default 32, max 64) | Carries own HMAC key; deterministic by construction regardless of entropy mode |

## Library API Example

Use `CategoryAwareStrategy` when you want the same output quality as the CLI:

```rust
use scour_secrets::strategy::{CategoryAwareStrategy, StrategyGenerator, EntropyMode};
use scour_secrets::store::MappingStore;
use scour_secrets::category::Category;
use std::sync::Arc;

let mode = EntropyMode::Deterministic { key: [42u8; 32] };
let generator = Arc::new(StrategyGenerator::new(
    Box::new(CategoryAwareStrategy::new()),
    mode,
));

let store = MappingStore::new(generator, None);
let replaced = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert_eq!(replaced.len(), "alice@corp.com".len());
assert!(replaced.contains('@'));
```

Use a simpler strategy when structure doesn't matter:

```rust
use scour_secrets::strategy::{PreserveLength, StrategyGenerator, EntropyMode};
use scour_secrets::store::MappingStore;
use scour_secrets::category::Category;
use std::sync::Arc;

let mode = EntropyMode::Deterministic { key: [42u8; 32] };
let generator = Arc::new(StrategyGenerator::new(
    Box::new(PreserveLength::new()),
    mode,
));

let store = MappingStore::new(generator, None);
let replaced = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert_eq!(replaced.len(), "alice@corp.com".len());
```

## Writing a Custom Strategy

Implement the `Strategy` trait and wrap it in `StrategyGenerator`:

```rust
use scour_secrets::category::Category;
use scour_secrets::strategy::Strategy;

struct Redact;

impl Strategy for Redact {
    fn name(&self) -> &'static str { "redact" }

    fn replace(&self, _category: &Category, original: &str, _entropy: &[u8; 32]) -> String {
        "X".repeat(original.len())
    }
}
```

The trait is object-safe — third-party crates can implement `Strategy` without
modifying this crate.

### Contract

- **Deterministic:** same `(category, original, entropy)` must always produce the same output.
- **No I/O or mutable state:** strategies must be pure functions.
- **Clearly synthetic:** returned values should be obviously non-sensitive.
- **Length:** returning a string of the same byte length as `original` preserves
  downstream formatting; this is expected for most use cases (see DESIGN.md §3).
