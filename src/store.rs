//! Thread-safe, concurrent one-way replacement store.
//!
//! # Concurrency Model
//!
//! The store uses [`dashmap::DashMap`] — a concurrent hash map with shard-level
//! locking (default 64 shards). This gives us:
//!
//! - **Lock-free reads** for lookups of already-mapped values.
//! - **Shard-level write locks** that are held only while inserting a new entry.
//!   With 64 shards and 8–16 threads, the probability of two threads contending
//!   on the same shard is very low.
//! - **Atomic get-or-insert** via the `entry()` API, which prevents TOCTOU races
//!   and guarantees first-writer-wins semantics.
//!
//! # Structure
//!
//! The forward map is two-level: `Category → original → sanitized`.
//!
//! ```text
//! DashMap<Category, Arc<DashMap<ZeroizingString, (CompactString, usize)>>>
//!    outer (~20 entries, always hot in cache)
//!               └── inner (one per category, holds the actual values)
//! ```
//!
//! This lets the fast-path read call `inner.get(original: &str)` without
//! constructing a temporary `String`, because `ZeroizingString: Borrow<str>`.
//! For files where the same value appears thousands of times, this eliminates
//! thousands of `malloc`/`free` cycles on the hot path.
//!
//! Replacements are **one-way only** — there is no reverse map, no mapping
//! file, and no restore capability.
//!
//! # Memory Characteristics
//!
//! At 10M unique values with average key length 20 bytes and average value
//! length 30 bytes:
//! - Forward map: 10M × (20 + 30 + ~120 DashMap overhead) ≈ 1.7 GB
//! - **Total: ~1.7 GB** — acceptable for server workloads.
//!
//! An optional `capacity_limit` can be set to prevent unbounded growth.

use crate::allowlist::AllowlistMatcher;
use crate::category::Category;
use crate::error::{Result, SanitizeError};
use crate::generator::ReplacementGenerator;
use compact_str::CompactString;
use dashmap::DashMap;
use std::borrow::Borrow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use zeroize::Zeroize;

/// Whether `value` is a redaction mask rather than a secret: three or more
/// repetitions of a single masking character (`******`, `••••••`, `######`),
/// as produced by upstream tools that scrub their own output (GitLab logs
/// mask passwords as `******`). Such a value carries no information — but
/// replaced with a realistic token it *looks* like a leaked secret, and
/// recorded in the store it becomes a literal that rewrites every future
/// mask. Two-character runs are left alone (`**` is a common glob/emphasis).
fn is_redaction_mask(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !matches!(first, '*' | '•' | '#') {
        return false;
    }
    value.chars().count() >= 3 && chars.all(|c| c == first)
}

/// An opaque cursor into the [`MappingStore`] insertion sequence.
///
/// Obtained from [`MappingStore::snapshot`] and passed to
/// [`MappingStore::iter_since`]. Using a dedicated type prevents accidentally
/// passing an unrelated `usize` (a count, an index, a capacity) to
/// `iter_since`, which would silently yield the wrong subset of entries.
/// To iterate all entries use [`StoreSnapshot::start`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreSnapshot(usize);

impl StoreSnapshot {
    /// A snapshot representing the beginning of the store (before any
    /// insertions). Passing this to [`MappingStore::iter_since`] yields every
    /// entry in the store — equivalent to the former `iter_since(0)`.
    #[must_use]
    pub fn start() -> Self {
        Self(0)
    }
}

impl Default for StoreSnapshot {
    fn default() -> Self {
        Self::start()
    }
}

// ---------------------------------------------------------------------------
// ZeroizingString — map key for the inner (per-category) DashMap
// ---------------------------------------------------------------------------

/// A `String` that zeroizes its heap buffer on drop.
///
/// `Zeroizing<String>` from the `zeroize` crate does not implement `Hash`,
/// so it cannot be used as a `HashMap` key. This newtype adds `Hash` while
/// keeping the zeroize-on-drop guarantee via an explicit `Drop` impl.
///
/// Implementing `Borrow<str>` allows `DashMap<ZeroizingString, _>::get(s: &str)`
/// to work without constructing a temporary `ZeroizingString` — the key insight
/// that makes the fast-path read allocation-free.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZeroizingString(String);

impl std::hash::Hash for ZeroizingString {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Drop for ZeroizingString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Enables `DashMap<ZeroizingString, _>::get(s: &str)` — zero allocation on
/// cache hits. Correct because `ZeroizingString` delegates `Hash` and `Eq`
/// to its inner `String`, which is consistent with `str`'s `Hash` and `Eq`.
impl Borrow<str> for ZeroizingString {
    fn borrow(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Convenience type alias for the inner map
// ---------------------------------------------------------------------------

type InnerMap = DashMap<ZeroizingString, (CompactString, usize)>;

// ---------------------------------------------------------------------------
// MappingStore
// ---------------------------------------------------------------------------

/// Thread-safe concurrent one-way replacement store.
///
/// Caches forward mappings for per-run consistency (same input always
/// produces the same output within a run). There is no reverse map,
/// no journal, and no persistence — replacements are one-way only.
///
/// See the [module-level documentation](self) for concurrency and memory details.
pub struct MappingStore {
    /// `category → original → (sanitized, insertion_index)`
    ///
    /// Two-level map: outer is keyed by `Category` (tiny, always in cache),
    /// inner is keyed by `ZeroizingString` (actual values). The inner map is
    /// behind an `Arc` so it can be obtained without holding the outer shard
    /// lock during inner map operations.
    forward: DashMap<Category, Arc<InnerMap>>,
    /// Replacement generator (HMAC deterministic or CSPRNG random).
    generator: Arc<dyn ReplacementGenerator>,
    /// Current number of mappings (atomic for lock-free reads).
    len: AtomicUsize,
    /// Optional upper bound on the number of mappings.
    capacity_limit: Option<usize>,
    /// Optional allowlist — matched values pass through unchanged and are
    /// not recorded in the forward map.
    allowlist: Option<Arc<AllowlistMatcher>>,
}

impl MappingStore {
    // ---------------- Construction ----------------

    /// Create a new, empty mapping store.
    ///
    /// # Arguments
    ///
    /// - `generator` — replacement strategy (HMAC or random).
    /// - `capacity_limit` — optional max number of unique mappings.
    #[must_use]
    pub fn new(generator: Arc<dyn ReplacementGenerator>, capacity_limit: Option<usize>) -> Self {
        Self {
            forward: DashMap::with_capacity(32),
            generator,
            len: AtomicUsize::new(0),
            capacity_limit,
            allowlist: None,
        }
    }

    /// Create a new store with an allowlist. Values matching the allowlist
    /// are returned unchanged and never recorded in the forward map.
    #[must_use]
    pub fn new_with_allowlist(
        generator: Arc<dyn ReplacementGenerator>,
        capacity_limit: Option<usize>,
        allowlist: Arc<AllowlistMatcher>,
    ) -> Self {
        Self {
            forward: DashMap::with_capacity(32),
            generator,
            len: AtomicUsize::new(0),
            capacity_limit,
            allowlist: Some(allowlist),
        }
    }

    /// Return the allowlist attached to this store, if any.
    pub fn allowlist(&self) -> Option<&AllowlistMatcher> {
        self.allowlist.as_deref()
    }

    // ---------------- Core API ----------------

    /// Get or create the sanitized replacement for `(category, original)`.
    ///
    /// This is the primary API for one-way sanitization.
    ///
    /// **Hot-path allocation:** When the value is already cached, this method
    /// is allocation-free. The inner `DashMap::get` accepts `&str` directly via
    /// `ZeroizingString: Borrow<str>`, so no temporary `String` is constructed.
    ///
    /// **Thread-safety:** Uses `DashMap::entry()` which holds a shard-level
    /// lock only for the duration of the insert closure. The generator is
    /// called inside the lock, but generation is fast (one HMAC or one RNG
    /// call). Capacity enforcement uses `compare_exchange` to prevent
    /// TOCTOU over-insertion.
    ///
    /// **Per-run consistency:** Once a value is mapped, all subsequent
    /// lookups return the same sanitized value (first-writer-wins).
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::CapacityExceeded`] if the store has
    /// reached its configured capacity limit.
    pub fn get_or_insert(&self, category: &Category, original: &str) -> Result<CompactString> {
        // A value that is already a redaction mask (`******`, `••••`) carries
        // no information: replacing it with a realistic-looking token makes
        // upstream masking look like a leaked secret, and recording it would
        // persist the mask as a literal that poisons every future run. Pass
        // it through unrecorded, like an allowlisted value.
        if is_redaction_mask(original) {
            return Ok(CompactString::new(original));
        }

        // Allowlist check: return the original value unchanged without recording it.
        if let Some(al) = &self.allowlist {
            if al.is_allowed(original) {
                return Ok(CompactString::new(original));
            }
        }

        // Fast path: already mapped — zero allocation.
        // `inner.get(original)` accepts `&str` via `ZeroizingString: Borrow<str>`.
        // Clone the Arc while we already hold the outer shard reference so the
        // slow path below never needs to acquire the outer shard a second time.
        let inner: Arc<InnerMap> = match self.forward.get(category) {
            Some(outer) => {
                if let Some(existing) = outer.value().get(original) {
                    return Ok(existing.value().0.clone());
                }
                outer.value().clone()
            }
            None => self
                .forward
                .entry(category.clone())
                .or_insert_with(|| Arc::new(DashMap::new()))
                .value()
                .clone(),
        };

        if let Some(limit) = self.capacity_limit {
            // Atomically reserve a capacity slot *before* generating the value.
            // This eliminates the TOCTOU race where multiple threads pass the
            // capacity check and all insert.
            //
            // insertion_index is set to `current` (the pre-increment value) from
            // the successful CAS — not from a separate load after the loop, which
            // could observe a higher count from a concurrent inserter and assign
            // the wrong monotonic position to this entry.
            let insertion_index;
            loop {
                let current = self.len.load(Ordering::Acquire);
                if current >= limit {
                    // One more chance: key may have been inserted by another thread.
                    if let Some(existing) = inner.get(original) {
                        return Ok(existing.value().0.clone());
                    }
                    return Err(SanitizeError::CapacityExceeded { current, limit });
                }
                if self
                    .len
                    .compare_exchange_weak(
                        current,
                        current + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    insertion_index = current;
                    break;
                }
                // CAS failed → another thread incremented; retry.
            }

            // Slot reserved — generate and insert (first-writer-wins).
            let mut was_inserted = false;
            let result = inner
                .entry(ZeroizingString(original.to_owned()))
                .or_insert_with(|| {
                    was_inserted = true;
                    let val = self.generator.generate(category, original);
                    (CompactString::new(val), insertion_index)
                })
                .value()
                .0
                .clone();

            if !was_inserted {
                // Another thread inserted first — release our reserved slot.
                self.len.fetch_sub(1, Ordering::Release);
            }

            Ok(result)
        } else {
            // No capacity limit — generate inside the entry lock so only the
            // first writer calls the generator (first-writer-wins semantics).
            let result = inner
                .entry(ZeroizingString(original.to_owned()))
                .or_insert_with(|| {
                    let insertion_index = self.len.fetch_add(1, Ordering::AcqRel);
                    let val = self.generator.generate(category, original);
                    (CompactString::new(val), insertion_index)
                })
                .value()
                .0
                .clone();

            Ok(result)
        }
    }

    /// Look up an existing forward mapping without creating one.
    #[must_use]
    pub fn forward_lookup(&self, category: &Category, original: &str) -> Option<CompactString> {
        let inner = self.forward.get(category)?;
        inner.value().get(original).map(|r| r.value().0.clone())
    }

    /// Register `alias` as an additional original that maps to the **same**
    /// `sanitized` replacement under `category`.
    ///
    /// Structured processors use this to record the *source-escaped* form of a
    /// discovered value — e.g. the JSON value `a"b` appears in the raw bytes as
    /// `a\"b`. The format-preserving scanner matches against raw input bytes, so
    /// without the alias the escaped occurrence would not be redacted. Aliasing
    /// (rather than a fresh mapping) keeps the escaped occurrence consistent with
    /// the parsed value's token.
    ///
    /// First-writer-wins: an existing mapping for `alias` is left unchanged.
    /// Allowlisted or empty aliases are ignored. Like [`Self::get_or_insert`],
    /// the new entry participates in [`Self::iter_since`].
    pub fn register_alias(&self, category: &Category, alias: &str, sanitized: &str) {
        if alias.is_empty() {
            return;
        }
        if let Some(al) = &self.allowlist {
            if al.is_allowed(alias) {
                return;
            }
        }
        let inner: Arc<InnerMap> = match self.forward.get(category) {
            Some(outer) => outer.value().clone(),
            None => self
                .forward
                .entry(category.clone())
                .or_insert_with(|| Arc::new(DashMap::new()))
                .value()
                .clone(),
        };
        inner
            .entry(ZeroizingString(alias.to_owned()))
            .or_insert_with(|| {
                let insertion_index = self.len.fetch_add(1, Ordering::AcqRel);
                (CompactString::new(sanitized), insertion_index)
            });
    }

    // ---------------- Metrics ----------------

    /// Number of unique mappings in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all mappings, zeroizing the original plaintexts.
    ///
    /// Takes `&self` so it is usable on a shared `Arc<MappingStore>`. Only
    /// call this after all concurrent readers and writers have finished —
    /// `DashMap::clear` acquires shard locks one at a time, so a concurrent
    /// `get_or_insert` racing with `clear` will observe a partially-cleared
    /// store.
    pub fn clear(&self) {
        // DashMap::clear() acquires each shard lock in turn and drops all
        // entries, triggering ZeroizingString::drop for every key. Cloned
        // Arc<InnerMap> refs held by concurrent threads survive until their
        // last clone drops, but clear() is intended for post-run teardown
        // only, so no concurrent access should be in flight.
        self.forward.clear();
        self.len.store(0, Ordering::Release);
    }

    // ---------------- Snapshot / diff (for format-preserving pass) ----------------

    /// Snapshot the current insertion count.
    ///
    /// Returns a [`StoreSnapshot`] that can be passed to [`Self::iter_since`] to
    /// iterate only the entries added *after* this point — useful for
    /// finding which mappings a structured processor pass discovered without
    /// building a full `HashSet` of all existing keys.
    ///
    /// O(1), no allocation.
    #[must_use]
    pub fn snapshot(&self) -> StoreSnapshot {
        StoreSnapshot(self.len.load(Ordering::Acquire))
    }

    /// Iterate over entries added at or after the given snapshot.
    ///
    /// `since` is the value returned by a previous call to [`Self::snapshot`].
    /// Entries whose insertion index is ≥ `since` are yielded; older entries
    /// are skipped. Still O(n) in total store size, but avoids allocating a
    /// `HashSet` of all prior keys. Use [`StoreSnapshot::start`] to iterate
    /// all entries.
    ///
    /// Implementation note: the inner `.collect::<Vec<_>>()` inside the
    /// `flat_map` is required to release the DashMap shard lock before
    /// yielding items — it allocates one `Vec` per category shard visited.
    pub fn iter_since(
        &self,
        since: StoreSnapshot,
    ) -> impl Iterator<Item = (Category, CompactString, CompactString)> + '_ {
        self.forward.iter().flat_map(move |outer| {
            let cat = outer.key().clone();
            outer
                .value()
                .iter()
                .filter_map(move |inner| {
                    let (sanitized, idx) = inner.value();
                    if *idx >= since.0 {
                        Some((
                            cat.clone(),
                            CompactString::new(inner.key().0.as_str()),
                            sanitized.clone(),
                        ))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
    }

    // ---------------- Iteration (for external use) ----------------

    /// Iterate over all mappings. Yields `(category, original, sanitized)`.
    ///
    /// Note: iteration over `DashMap` is not snapshot-consistent if concurrent
    /// inserts are happening. Call this after all workers have finished.
    ///
    /// Implementation note: allocates one `Vec` per category shard to release
    /// the DashMap shard lock between categories.
    pub fn iter(&self) -> impl Iterator<Item = (Category, CompactString, CompactString)> + '_ {
        self.forward.iter().flat_map(|outer| {
            let cat = outer.key().clone();
            outer
                .value()
                .iter()
                .map(move |inner| {
                    (
                        cat.clone(),
                        CompactString::new(inner.key().0.as_str()),
                        inner.value().0.clone(),
                    )
                })
                .collect::<Vec<_>>()
        })
    }
}

/// Zeroize original keys stored in the forward map on drop.
impl Drop for MappingStore {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Compile-time assertion that a type is `Send + Sync`.
macro_rules! static_assertions_send_sync {
    ($t:ty) => {
        const _: fn() = || {
            fn assert_send<T: Send>() {}
            fn assert_sync<T: Sync>() {}
            assert_send::<$t>();
            assert_sync::<$t>();
        };
    };
}

static_assertions_send_sync!(MappingStore);

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{HmacGenerator, RandomGenerator};
    use std::sync::Arc;

    fn hmac_store(limit: Option<usize>) -> MappingStore {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        MappingStore::new(gen, limit)
    }

    fn random_store() -> MappingStore {
        let gen = Arc::new(RandomGenerator::new());
        MappingStore::new(gen, None)
    }

    // --- Redaction-mask passthrough ---

    #[test]
    fn redaction_masks_pass_through_unrecorded() {
        // Regression (GitLab SOS eval): a log line `password: ******` matched
        // by a kv pattern must keep its mask — replacing it fakes a leak, and
        // recording it poisons future runs via the secrets-file write-back.
        let store = hmac_store(None);
        for mask in ["***", "******", "••••••", "######"] {
            let out = store
                .get_or_insert(&Category::Custom("password".into()), mask)
                .unwrap();
            assert_eq!(out.as_str(), mask, "mask must pass through unchanged");
        }
        assert_eq!(store.len(), 0, "masks must not be recorded");
    }

    #[test]
    fn near_masks_are_still_replaced() {
        // Mixed or short runs are not masks: real values must still map.
        let store = hmac_store(None);
        for value in ["**", "*secret*", "#x#x#x", "a*****"] {
            let out = store
                .get_or_insert(&Category::Custom("password".into()), value)
                .unwrap();
            assert_ne!(out.as_str(), value, "'{value}' must be replaced");
        }
    }

    // --- Basic operations ---

    #[test]
    fn insert_and_lookup() {
        let store = hmac_store(None);
        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        assert!(!s1.is_empty());
        assert!(s1.contains("@corp.com"), "domain must be preserved");
        assert_eq!(s1.len(), "alice@corp.com".len(), "length must be preserved");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn same_input_same_output() {
        let store = hmac_store(None);
        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        let s2 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        assert_eq!(s1, s2, "repeated insert must return cached value");
        assert_eq!(store.len(), 1, "no duplicate entry");
    }

    #[test]
    fn different_inputs_different_outputs() {
        let store = hmac_store(None);
        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        let s2 = store
            .get_or_insert(&Category::Email, "bob@corp.com")
            .unwrap();
        assert_ne!(s1, s2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn different_categories_different_outputs() {
        let store = hmac_store(None);
        let s1 = store.get_or_insert(&Category::Email, "test").unwrap();
        let s2 = store.get_or_insert(&Category::Name, "test").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn forward_lookup_works() {
        let store = hmac_store(None);
        let sanitized = store.get_or_insert(&Category::IpV4, "192.168.1.1").unwrap();
        let found = store.forward_lookup(&Category::IpV4, "192.168.1.1");
        assert_eq!(found, Some(sanitized));
    }

    #[test]
    fn forward_lookup_missing() {
        let store = hmac_store(None);
        assert!(store.forward_lookup(&Category::Email, "nope").is_none());
    }

    // --- Capacity limit ---

    #[test]
    fn capacity_limit_enforced() {
        let store = hmac_store(Some(2));
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        store.get_or_insert(&Category::Email, "b@b.com").unwrap();
        let result = store.get_or_insert(&Category::Email, "c@c.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            SanitizeError::CapacityExceeded {
                current: 2,
                limit: 2,
            } => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn capacity_limit_allows_duplicate() {
        let store = hmac_store(Some(1));
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        // Re-inserting same value should succeed (fast path).
        let s2 = store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        assert!(!s2.is_empty());
    }

    // --- Random generator within store ---

    #[test]
    fn random_store_caches() {
        let store = random_store();
        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        let s2 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        assert_eq!(s1, s2, "random store must still cache the first result");
    }

    // --- Iteration ---

    #[test]
    fn iter_yields_all_mappings() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        store.get_or_insert(&Category::IpV4, "1.2.3.4").unwrap();
        let collected: Vec<_> = store.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    // --- Concurrent inserts (basic smoke test) ---

    #[test]
    fn concurrent_inserts_no_panic() {
        use std::sync::Arc;
        use std::thread;

        let gen = Arc::new(HmacGenerator::new([99u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));

        let mut handles = vec![];
        for t in 0..8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for i in 0..1000 {
                    let val = format!("thread{}-val{}", t, i);
                    store.get_or_insert(&Category::Email, &val).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(store.len(), 8000);
    }

    #[test]
    fn concurrent_inserts_same_key_idempotent() {
        use std::sync::Arc;
        use std::thread;

        let gen = Arc::new(HmacGenerator::new([7u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));

        let mut handles = vec![];
        for _ in 0..8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let mut results = Vec::new();
                for i in 0..100 {
                    let val = format!("shared-{}", i);
                    let r = store.get_or_insert(&Category::Email, &val).unwrap();
                    results.push((val, r));
                }
                results
            }));
        }

        let mut all_results: Vec<Vec<(String, CompactString)>> = vec![];
        for h in handles {
            all_results.push(h.join().unwrap());
        }

        // All threads must agree on every mapping.
        assert_eq!(store.len(), 100);
        for i in 0..100 {
            let val = format!("shared-{}", i);
            let expected = store.forward_lookup(&Category::Email, &val).unwrap();
            for thread_results in &all_results {
                let (_, got) = &thread_results[i];
                assert_eq!(
                    got, &expected,
                    "all threads must see the same mapping for {}",
                    val
                );
            }
        }
    }

    // --- is_empty / clear ---

    #[test]
    fn is_empty_on_new_store() {
        let store = hmac_store(None);
        assert!(store.is_empty());
    }

    #[test]
    fn is_empty_false_after_insert() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        assert!(!store.is_empty());
    }

    #[test]
    fn clear_via_arc_shares_state() {
        // The primary motivation for clear(&self) over clear(&mut self) is
        // usability on Arc<MappingStore>. Verify that calling clear through a
        // second Arc handle empties the store seen by the first handle.
        let store = Arc::new(hmac_store(None));
        let clone = Arc::clone(&store);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        assert_eq!(store.len(), 1);
        clone.clear();
        assert_eq!(store.len(), 0, "clear via Arc must empty the shared store");
        assert!(store.is_empty());
    }

    #[test]
    fn clear_resets_store() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        store.get_or_insert(&Category::IpV4, "1.2.3.4").unwrap();
        assert_eq!(store.len(), 2);
        store.clear();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn clear_then_reinsert_works() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        store.clear();
        let result = store.get_or_insert(&Category::Email, "a@a.com");
        assert!(result.is_ok());
        assert_eq!(store.len(), 1);
    }

    // --- snapshot / iter_since ---

    #[test]
    fn snapshot_and_iter_since_yields_only_new() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "old@a.com").unwrap();
        let snap = store.snapshot();
        store.get_or_insert(&Category::IpV4, "1.2.3.4").unwrap();
        store.get_or_insert(&Category::Name, "Alice").unwrap();

        let new_entries: Vec<_> = store.iter_since(snap).collect();
        assert_eq!(new_entries.len(), 2);
        // None of the new entries should be the pre-snapshot email.
        assert!(!new_entries
            .iter()
            .any(|(cat, orig, _)| { *cat == Category::Email && orig.as_str() == "old@a.com" }));
    }

    #[test]
    fn snapshot_default_and_start_are_equivalent() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        store.get_or_insert(&Category::IpV4, "1.2.3.4").unwrap();
        let via_start: Vec<_> = store.iter_since(StoreSnapshot::start()).collect();
        let via_default: Vec<_> = store.iter_since(StoreSnapshot::default()).collect();
        assert_eq!(
            via_start.len(),
            via_default.len(),
            "default() must yield identical results to start()"
        );
    }

    #[test]
    fn iter_since_zero_yields_all() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        store.get_or_insert(&Category::IpV4, "1.2.3.4").unwrap();
        let all: Vec<_> = store.iter_since(StoreSnapshot::start()).collect();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn iter_since_at_end_yields_nothing() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        let snap = store.snapshot();
        let new: Vec<_> = store.iter_since(snap).collect();
        assert!(new.is_empty());
    }

    // --- new_with_allowlist ---

    #[test]
    fn allowlist_passes_value_through_unchanged() {
        use crate::allowlist::AllowlistMatcher;
        let matcher =
            AllowlistMatcher::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).matcher;
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = MappingStore::new_with_allowlist(gen, None, Arc::new(matcher));

        assert!(store.allowlist().is_some());

        // Allowlisted value must be returned verbatim.
        let result = store
            .get_or_insert(&Category::Hostname, "localhost")
            .unwrap();
        assert_eq!(result.as_str(), "localhost");
    }

    #[test]
    fn allowlist_still_replaces_non_listed() {
        use crate::allowlist::AllowlistMatcher;
        let matcher = AllowlistMatcher::new(vec!["localhost".to_string()]).matcher;
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = MappingStore::new_with_allowlist(gen, None, Arc::new(matcher));

        let result = store
            .get_or_insert(&Category::Hostname, "prod.corp.com")
            .unwrap();
        assert_ne!(result.as_str(), "prod.corp.com");
    }
}
