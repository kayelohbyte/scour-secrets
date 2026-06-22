# Architecture

> **rust-sanitize** v0.14.0 — Deterministic, one-way data sanitization.

This document describes the internal architecture of the sanitization
engine.  It is aimed at contributors and operators who need to
understand data-flow, concurrency, and security boundaries.

---

## 1. High-Level Data Flow

```
┌─────────────┐                 ┌───────────────────────┐
│  CLI args    │  ──────────▶   │    sanitize  (bin)     │
│  [INPUT]     │                │  ┌─────────────────┐   │
│  -o/--output │                │  │ Signal handler   │   │
│  -s/--secrets-│                │  │ Tracing init     │   │
│    file      │                │  │ Thread cap resolve│   │
└─────────────┘                 │  └────────┬────────┘   │
                                │           │            │
                      ┌─────────▼──────────────────────┐ │
                      │  Is it an archive?             │ │
                      │  (.tar / .tar.gz / .zip)       │ │
                      └──┬─────────────────┬───────────┘ │
                    YES  │                 │  NO         │
          ┌──────────────▼──────┐   ┌──────▼──────────┐  │
          │ ArchiveProcessor    │   │ StreamScanner   │  │
          │ (per-entry routing) │   │ (chunk+overlap) │  │
          └──────────┬──────────┘   └──────┬──────────┘  │
                     │                     │             │
         ┌───────────▼─────────────────────▼──────────┐  │
         │          MappingStore (DashMap)             │  │
         │  ┌──────────────┐  ┌─────────────────────┐ │  │
         │  │ ForwardMap   │  │ ReplacementGenerator │ │  │
         │  │ val → repl   │  │ (HMAC / Random)      │ │  │
         │  └──────────────┘  └─────────────────────┘ │  │
         └────────────────────────────────────────────┘  │
                                │                        │
                      ┌─────────▼──────────┐             │
                      │ AtomicFileWriter   │             │
                      │ (tmp → fsync →     │             │
                      │  rename)           │             │
                      └────────────────────┘             │
                                                         │
                      ┌─────────────────────┐            │
                      │ ReportBuilder       │            │
                      │ (JSON summary)      │            │
                      └─────────────────────┘            │
└────────────────────────────────────────────────────────┘
```

### Two-Pass Pipeline (with `--profile`)

When a structured field profile is active, processing uses two serial-then-parallel phases:

**Phase 1 — Serial structured scan:**

1. Load secrets + profiles.
2. For each file matching a profile (in command-line order): parse structured content, walk fields, call `MappingStore::get_or_insert` for matched values. This seeds the store with typed field values (passwords, tokens, hostnames) extracted from config files.
3. Archive discovery pre-pass: each archive is read a second time to collect profile-matched entry values and add them to the store.

**Phase 2 — Parallel augmented scan:**

4. Build augmented scanner: base secrets patterns + all literals discovered in Phase 1.
5. Stdin (if present) is processed now with the augmented scanner so values found in configs are also replaced in piped input.
6. All remaining files and archives are processed in parallel using the augmented scanner.

The two-pass design ensures cross-file consistency: a password extracted from `config.yaml` in Phase 1 is replaced everywhere it appears in Phase 2 logs.

### Plain file path (no profile)

1. Load encrypted secrets → decrypt with password (PBKDF2 + AES-256-GCM).
2. Build `ScanPattern` list from decrypted plain-text entries.
3. Create `StreamScanner` with chunk+overlap configuration.
4. Open input as a `Read`, open output via `AtomicFileWriter`.
5. Call `scan_reader(&mut reader, &mut writer)`.
6. Scanner reads chunks, matches literals via Aho-Corasick and regex patterns via `RegexSet` pre-filter + per-pattern regex scan, calls `MappingStore::get_or_insert` for each match, and writes sanitized chunks to the writer.
7. On success, `AtomicFileWriter::finish()` fsyncs + renames. On error/signal, temp file is cleaned up by `Drop`.

### Archive path

1. Detect format from extension (`.tar`, `.tar.gz`, `.zip`).
2. `ArchiveProcessor` iterates entries; for each regular file:
   - Try structured processor match (JSON / YAML / XML / CSV / KeyValue) via `ProcessorRegistry::find_processor`.
   - If matched and within `MAX_STRUCTURED_ENTRY_SIZE`, parse + walk + replace field values.
   - Otherwise fall back to `StreamScanner::scan_reader` for byte-level replacement.
3. Rebuild the archive with sanitized content and preserved metadata.

### Encrypt / Decrypt subcommands

The `sanitize encrypt` and `sanitize decrypt` subcommands handle
secrets file management. These are simple linear flows that do not
involve the scanning/replacement pipeline:

- **`sanitize encrypt <IN> <OUT>`** — reads a plaintext secrets file,
  optionally validates it, encrypts with AES-256-GCM (PBKDF2 key
  derivation), and writes the ciphertext atomically.
- **`sanitize decrypt <IN> <OUT>`** — reads an encrypted secrets file,
  decrypts, optionally validates the resulting plaintext, and writes
  atomically.

Both subcommands resolve the password through a unified chain:
`--password` flag (triggers interactive masked prompt; requires TTY) →
`--password-file` (with Unix permission enforcement) →
`SANITIZE_PASSWORD` env var → automatic interactive terminal prompt
(masked input via `rpassword`).

### MCP server

The `mcp/` directory contains a TypeScript/Deno wrapper that exposes
the CLI as a Model Context Protocol server:

```
┌─────────────────────────────────────────────────────┐
│  MCP client (Claude Code / Cursor / Claude.ai)      │
└─────────────────────┬───────────────────────────────┘
                      │  stdio (JSON-RPC 2.0)
┌─────────────────────▼───────────────────────────────┐
│  mcp/src/index.ts  (Deno / TypeScript)              │
│  • Validates inputs with Zod schemas                │
│  • Writes sensitive data to mode-0600 temp files    │
│  • Spawns `sanitize` binary as a subprocess         │
│  • Reads sanitized output from temp files           │
│  • Returns results via MCP protocol                 │
└─────────────────────┬───────────────────────────────┘
                      │  subprocess (execve)
┌─────────────────────▼───────────────────────────────┐
│  sanitize  (Rust CLI binary)                        │
│  All sensitive data processing happens here         │
└─────────────────────────────────────────────────────┘
```

**Security boundary:** The TypeScript layer never inspects, logs, or
retains the content it proxies. Sensitive data reaches the Rust binary
via stdin or a temp file (never via argv), and leaves only via a
temp-file path that the TypeScript layer reads once and then deletes.
The Rust binary is the only component with access to secrets files,
decryption keys, and pattern-matched values.

**HTTP daemon mode (`--http`):** The server can run as a persistent
local HTTP service binding to `127.0.0.1` (port 6277 by default,
configurable via `--http <port>`). All requests require a bearer token
set via `SANITIZE_MCP_HTTP_TOKEN`. In this mode AI tools connect to the
already-running daemon rather than spawning it on demand, which decouples
the daemon's user account and file permissions from those of the AI tool.
The daemon enforces a single active MCP session at a time; when the client
disconnects the daemon exits so the service manager can restart it cleanly
for the next connection. Token travel over loopback is acceptable for local
use; for remote deployments a TLS-terminating reverse proxy is required.

**Namespace support:** When `SANITIZE_SECRETS_DIR` is set, the MCP
server resolves a `namespace` parameter to a per-tenant directory
containing `secrets.yaml` and an optional `profile.yaml`. Password
files must be mode `0600` or `0400`. This enables safe multi-tenant
deployments without exposing credentials to clients.

---

## 2. Replacement Strategies

The `Strategy` trait is the single extension point for generating sanitized
replacements. All paths — CLI, library, and custom — flow through the same
interface.

```rust
StrategyGenerator (adapter)
    → implements ReplacementGenerator trait
    → produces entropy (HMAC-deterministic or CSPRNG-random)
    → delegates to dyn Strategy::replace(category, original, entropy)
    → built-in or user-defined strategy
```

`StrategyGenerator` decouples *how entropy is produced* from *what the
replacement looks like*. Strategies are pure functions of
`(category, original, entropy)` — no I/O, no mutable state.

### Built-in Strategies

| Strategy | Output |
|---|---|
| `CategoryAwareStrategy` | Category-shaped: email → email, IP → IP, JWT → JWT. Same formatters as the CLI. |
| `RandomString` | Fixed-length alphanumeric. |
| `RandomUuid` | UUID v4 format. |
| `FakeIp` | Dot positions preserved; digits replaced. |
| `PreserveLength` | Exact byte length match, lowercase alphanumeric. |
| `HmacHash` | Lowercase hex; carries own HMAC key, ignores entropy mode. |

`CategoryAwareStrategy` is the recommended default for library consumers who
want the same replacement quality as the CLI without wiring up `HmacGenerator`
directly.

### CLI Generators

`HmacGenerator` and `RandomGenerator` in `src/generator.rs` implement
`ReplacementGenerator` directly and call `format_replacement` without the
`Strategy` indirection. They remain the primary path for the CLI binary and
streaming scanner, where the category is always known at call time and the
extra vtable call is unnecessary.

`format_replacement` is `pub(crate)` — `CategoryAwareStrategy` delegates to it,
giving library users access to identical output without duplicating the logic.

- **Code:** `src/strategy.rs`, `src/generator.rs`
- **Example:** `examples/custom_strategy.rs`
- **Docs:** `docs/strategies.md`

---

## 3. Module Map

| Module | Responsibility |
|--------|---------------|
| `scanner` | Streaming hybrid scanner with configurable chunk/overlap: Aho-Corasick for literals + regex engine for regex patterns. Memory-bounded reads. |
| `store` | `DashMap`-backed dedup cache. `get_or_insert` is the single entry-point. Capacity-limited. |
| `generator` | `ReplacementGenerator` trait. Two impls: `HmacGenerator` (deterministic), `RandomGenerator` (CSPRNG). Contains category-aware formatters used by the CLI. |
| `strategy` | **Extensibility layer:** `Strategy` trait + `StrategyGenerator` adapter + 5 built-in strategies (`RandomString`, `FakeIp`, etc.). Public API for library users to implement custom replacement logic. |
| `category` | `Category` enum. Drives domain separation in HMAC and replacement format selection. |
| `secrets` | AES-256-GCM encrypted secrets file format. PBKDF2 key derivation. Zeroizes plaintext on drop. |
| `processor::*` | Format-aware processors: JSON, YAML, XML, CSV, KeyValue. Each implements `Processor` trait. |
| `processor::archive` | Tar / tar.gz / zip processing. Per-entry structured-or-scanner routing. |
| `processor::registry` | `ProcessorRegistry` — maps processor names to `Arc<dyn Processor>`. |
| `processor::profile` | `FileTypeProfile` + `FieldRule` — user-supplied rules for structured processing. |
| `report` | Thread-safe `ReportBuilder` producing a JSON summary of the sanitization run. |
| `error` | `SanitizeError` enum + `Result<T>` alias. |
| `atomic` | `AtomicFileWriter` — crash-safe output via temp + fsync + rename. |

---

## 4. Streaming Model

The scanner never holds the entire file in memory. It reads fixed-size
**chunks** (default 1 MiB) with a configurable **overlap** (default
4 KiB). The overlap ensures that a sensitive value straddling a chunk
boundary is still detected.

```
Chunk N:     [===========================|overlap|]
Chunk N+1:                         [overlap|===========================|overlap|]
```

After scanning a chunk, only the overlap window is retained; the rest
is flushed to the writer. Peak memory per file ≈ `chunk_size + overlap`.

For structured processors (JSON, YAML, …) the entry content must fit
in memory (gated by `MAX_STRUCTURED_ENTRY_SIZE`). Oversized entries
fall through to the streaming scanner.

---

## 5. Concurrency Model

- **`MappingStore`** uses `DashMap` (striped read-write locks). Multiple
  threads can call `get_or_insert` concurrently; per-shard locking keeps
  contention low.
- **All public types are `Send + Sync`.**
- The CLI resolves `--threads` to `min(--threads, available_parallelism)`
  and initializes the global rayon thread pool to that size at startup.
- **File-level parallelism:** when multiple `[INPUT]` paths are given, all
  `InputTarget::File` targets are dispatched via `rayon::par_iter`. Stdin
  targets always run serially.
- **Archive-entry parallelism:** for a single-archive input (or when file-level
  parallelism is not active), archive entries are sanitized in parallel via
  rayon when the file-entry count meets `parallel_threshold` (default: 4).
  The rebuilt archive is always written in original entry order — output is
  deterministic regardless of thread count.
- **Thread-budget policy:** file-level and entry-level parallelism are mutually
  exclusive. When multiple files are processed in parallel, archive-entry
  parallelism inside each one is suppressed (`parallel_threshold = usize::MAX`)
  to prevent rayon oversubscription.
- **Progress:** the shared `Arc<Mutex<ProgressReporter>>` serializes all
  `start_task` / `finish_task` calls, so milestone lines are never interleaved.

---

## 6. Replacement Pipeline

```
Input value  ──▶  MappingStore::get_or_insert
                       │
                 ┌─────▼──────────┐
                 │ Already cached? │
                 └──┬──────────┬──┘
                  YES          NO
                   │            │
                   │    ┌───────▼──────────────┐
                   │    │ Strategy::generate()  │
                   │    │ (HMAC or Random seed  │
                   │    │  + category format)   │
                   │    └───────┬──────────────┘
                   │            │
                   │    ┌───────▼──────┐
                   │    │ Insert into  │
                   │    │ forward map  │
                   │    └───────┬──────┘
                   │            │
                   ▼            ▼
              Return cached replacement
```

- **HMAC mode**: `HMAC-SHA256(seed, category_tag || "\x00" || value)` →
  truncated to category-specific format. Same seed + value always
  produces the same replacement.
- **Random mode**: `OsRng` / `thread_rng()` per invocation. The dedup
  cache still ensures per-run consistency.

---

## 7. Atomic Output Safety

All file outputs go through `AtomicFileWriter`:

1. Write to `<destination>.tmp`.
2. `flush()` + `fsync()` the file descriptor.
3. `rename()` atomically over the destination.
4. If the process exits before `finish()`, `Drop` removes the temp file.

This guarantees that readers never see a partial output file after a
crash or signal interrupt.

---

## 8. Signal Handling

The CLI installs a `SIGINT` / `SIGTERM` handler via the `ctrlc` crate.
A global `AtomicBool` (`INTERRUPTED`) is set on signal. The pipeline
checks `is_interrupted()` before committing output:

- If interrupted **before** `AtomicFileWriter::finish()`, the temp file
  is cleaned up and the process exits with code 130.
- If interrupted **after** commit, the already-written output is valid.

---

## 9. Observability

Logging uses the `tracing` / `tracing-subscriber` stack:

- `--log-format human` (default): human-readable terminal output.
- `--log-format json`: structured JSON lines (machine-parseable).
- Level controlled via `SANITIZE_LOG` env var (e.g.
  `SANITIZE_LOG=debug`).
- **No secret values are ever logged.** Only file names, counts, and
  timing data appear in log output.

---

## 10. Feature Flags

| Feature | Effect |
|---------|--------|
| `bench` | Enables additional `tracing::info!` output for internal metrics (unique mapping count, etc.). Not intended for production. |

---

## 11. Build & Test

```bash
# Run all tests
cargo test

# Run with structured logging
SANITIZE_LOG=debug cargo run -- foo.txt -s secrets.enc --password -o foo.sanitized.txt

# Pipe from stdin (no TTY — use env var instead of --password)
echo "sensitive data" | SANITIZE_LOG=debug cargo run -- -s secrets.enc

# Run benchmarks
cargo bench

# Run fuzz targets (requires cargo-fuzz / nightly)
cargo +nightly fuzz run fuzz_regex
cargo +nightly fuzz run fuzz_json
cargo +nightly fuzz run fuzz_yaml
cargo +nightly fuzz run fuzz_archive
```
