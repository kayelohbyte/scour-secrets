# Security Model

> **rust-sanitize** v0.14.0

This document describes the security properties, threat mitigations,
and operational constraints of the sanitization engine.

---

## 1. One-Way Guarantee

Replacements are **irreversible by design**.

- No reverse-mapping table is generated or stored.
- The `MappingStore` forward map (`original → replacement`) lives only
  in process memory and is zeroized on drop (see §5).
- There is no "restore" or "decrypt-output" mode.

---

## 2. Encryption at Rest — Secrets File

Sensitive detection patterns (regex, literals) are stored in an
AES-256-GCM encrypted secrets file.

| Parameter | Value |
|-----------|-------|
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 600 000 |
| Salt | 32 bytes (OS CSPRNG) |
| Key length | 32 bytes (256 bits) |
| Cipher | AES-256-GCM |
| Nonce | 12 bytes (OS CSPRNG) |
| AAD | None (empty) |

The encrypted file format:

```
[32 bytes salt]
[12 bytes nonce]
[N bytes ciphertext + 16-byte GCM tag]
```

After decryption, plaintext secrets are wrapped in `zeroize::Zeroizing`
and each `SecretEntry`'s fields (`pattern`, `kind`, `category`, `label`)
implement `Zeroize` via `Drop`.

Secrets files are managed via the `sanitize encrypt` and
`sanitize decrypt` subcommands.

---

## 3. Password Handling

The password used for secrets encryption/decryption is resolved through
a priority chain designed to balance convenience with security:

| Priority | Source | Security Notes |
|----------|--------|----------------|
| 1 | `--password` flag | Triggers a secure **interactive prompt** — masked terminal input via `rpassword`. No trace in process listings, shell history, or environment. Requires a TTY; fails fast with a clear error in non-interactive contexts. |
| 2 | `--password-file <PATH>` | Reads from a file. The file **must** have Unix permissions `0600` or `0400` (owner read/write or owner read-only). Other permissions are rejected with an error. |
| 3 | `SANITIZE_PASSWORD` env var | Avoids process listings but visible in `/proc/<pid>/environ` on Linux. |
| 4 | Automatic interactive prompt | Falls through to a masked terminal prompt when no password source is explicitly specified and a password is required. |

---

## 4. HMAC Determinism

When using `HmacGenerator`, replacements are derived from:

```
HMAC-SHA256(seed, category_tag || "\x00" || plaintext_value)
```

- The **seed** is a 32-byte key provided at CLI invocation. Same seed +
  same value → same replacement across runs.
- The seed is zeroized on `HmacGenerator` drop.
- Category `domain_tag_hmac()` provides domain separation so e.g. an email
  `"alice"` and a hostname `"alice"` produce different replacements.

### Determinism trade-offs

Deterministic mode buys cross-run/cross-file consistency (the same value
always maps to the same replacement) at the cost of leaking some
structure. Callers should understand what the output still reveals:

- **Equality leakage.** Identical inputs produce identical replacements,
  so an observer can tell *which* values were the same across the
  document or across files — even without learning the values. If two log
  lines share a token, that relationship survives sanitization.
- **Structural / length leakage.** Replacements are
  **length-preserving** and category-shaped, so the output preserves the
  length and rough format of each secret. This can narrow the space of
  candidate plaintexts for low-entropy values.
- **Dictionary confirmation with a weak/shared seed.** Because the
  mapping is `HMAC(seed, value)`, anyone who knows or guesses the seed can
  compute the replacement for any candidate value and confirm it against
  the output. A weak or widely-shared seed therefore enables dictionary
  confirmation of low-entropy values (short IDs, enum-like fields,
  common usernames). Use a high-entropy seed and treat it as a secret.

For maximum unlinkability where cross-run consistency is *not* required,
prefer the non-deterministic (random) generator, which breaks all three
of the above by mapping equal inputs to independent random replacements.

---

## 5. Memory Bounds

The engine enforces hard caps at multiple layers to prevent resource
exhaustion:

| Limit | Value | Purpose |
|-------|-------|---------|
| Regex automaton size | 1 MiB | Prevents catastrophic backtracking / ReDoS |
| Regex DFA size | 1 MiB | Caps DFA memory during matching |
| Max patterns | 10 000 (default) | Bounds total compiled regex memory |
| Mapping store capacity | Configurable | Prevents unbounded map growth |
| YAML input size | 64 MiB | Stops alias-bomb expansion |
| YAML node count | 10 000 000 | Caps post-expansion node count |
| YAML recursion depth | 128 | Prevents stack overflow |
| XML input size | 256 MiB | Bounds memory for DOM parse |
| XML element depth | 256 | Prevents stack overflow |
| CSV input size | 256 MiB | Bounds memory for full parse |
| Structured archive entry | 256 MiB | Oversized entries fall to streaming scanner |
| Scanner chunk size | Configurable (default 1 MiB) | Peak memory ≈ chunk + overlap |

---

## 6. Zeroization

Sensitive data is scrubbed from memory on drop:

| Type | What is zeroized | Mechanism |
|------|-----------------|-----------|
| `HmacGenerator` | 32-byte HMAC key | `Zeroize` trait on `Drop` |
| `SecretEntry` | pattern, kind, category, label strings | `Zeroize` trait on `Drop` |
| `MappingStore` | All original-value keys in forward map | Custom `Drop` iterates + zeroizes |
| Decrypted secrets | Full plaintext JSON blob | `zeroize::Zeroizing<Vec<u8>>` |

> **Note:** Zeroization is best-effort on safe Rust. The compiler may
> copy values before they are scrubbed. Using `zeroize` with its
> `volatile` write semantics minimizes but does not eliminate this risk.

---

## 7. No Unsafe Code

The crate contains **zero** `unsafe` blocks. Thread safety is achieved
through `DashMap` (shard-level locking) and `Arc`. `Send + Sync` bounds
are verified with compile-time assertions.

---

## 8. Out of Scope

The following threats are outside the tool's design boundary:

- **Compromised runtime environment.** If the host OS or runtime is
  compromised, an attacker can read process memory directly.
- **Memory scraping during execution.** Sensitive values exist in
  process memory between decryption and zeroization.
- **Kernel-level or hypervisor adversaries.** The tool operates in user
  space and cannot defend against privileged code.
- **Side-channel attacks.** HMAC computation and regex matching are not
  constant-time with respect to input contents.
- **Deterministic seed brute-force.** In `--deterministic` mode, an
  adversary who knows the seed can compute HMAC for any candidate and
  compare against replacements in the output.

---

## 9. HTTP Daemon Mode

When `sanitize-mcp --http` is used, the server binds to `127.0.0.1` only and
requires a bearer token on every request:

| Property | Value |
|----------|-------|
| Bind address | `127.0.0.1` (loopback only — not reachable from the network) |
| Auth | Bearer token via `SANITIZE_MCP_HTTP_TOKEN` (required; server refuses to start without it) |
| Session model | One active MCP session at a time; daemon exits on clean disconnect so the service manager can restart it |
| Token in transit | Plaintext over loopback — acceptable locally; use a TLS reverse proxy for remote deployments |
| Token storage | Service config file must be mode `0600` (shown in `docs/mcp.md`) |

The daemon never logs request bodies, file paths, file content, or the
`Authorization` header. Only startup messages and unhandled error class
names appear in log output.

**Threat:** Token theft via process listing or config file read.  
**Mitigation:** Config file is mode `0600`; token is not passed via argv.

**Threat:** Unclean disconnect leaves daemon in stuck state.  
**Mitigation:** Service manager (launchd / systemd / NSSM) auto-restarts on
clean disconnect. Unclean exits (SIGKILL) require manual restart — no
health-check probe is built in.

---

## 10. Responsible Disclosure

If you discover a security vulnerability, please report it privately
via GitHub Security Advisories or email the maintainers directly.
Do not open a public issue for security vulnerabilities.

**Response timeline:**
- Acknowledgement within 48 hours.
- Initial assessment within 5 business days.
- Fix or mitigation within 30 days for confirmed issues.

---

## 11. YAML Alias Bomb Mitigation

YAML anchors/aliases can cause exponential expansion:

```yaml
a: &x "boom"
b: [*x, *x, *x, *x, *x, *x, *x, *x]  # 8× expansion
c: [*b, *b, *b, *b, *b, *b, *b, *b]  # 64× expansion
```

The `YamlProcessor` defends against this with three layers:

1. **Input size cap** — reject inputs > 64 MiB before parsing.
2. **Node count cap** — after `serde_yaml` deserialization (which
   expands aliases), count nodes and reject if > 10 000 000.
3. **Recursion depth cap** — reject documents deeper than 128 levels.

---

## 12. Archive Decompression Bomb Mitigation

Malicious archives can contain entries that expand to many times their
compressed size (zip bombs, tar bombs, nested archives). The
`ArchiveProcessor` defends against this:

1. **Entry size cap** — individual entries larger than 256 MiB are
   diverted to the streaming scanner (which processes in bounded chunks)
   rather than being buffered in memory for structured processing.
2. **Nesting depth cap** — recursive archive processing (archives inside
   archives) is limited to a default depth of 5 and a hard maximum of
   10. Exceeding the limit returns `RecursionDepthExceeded`.
3. **Entry-by-entry processing** — archives are never fully decompressed
   into memory. Each entry is processed independently, so peak memory is
   proportional to the largest single entry (structured path) or
   `chunk_size + overlap_size` (streaming scanner path).

---

## 13. Signal Safety

`SIGINT` / `SIGTERM` set a global `AtomicBool`. The pipeline checks
this flag before committing output. If interrupted:

- `AtomicFileWriter` drops the temp file (no partial output).
- Exit code is 130 (standard UNIX convention for SIGINT).

---

## 14. Logging Hygiene

The tracing layer **never** logs:

- Secret patterns or their plaintext values.
- Decryption keys, passwords, or HMAC seeds.
- Contents of sensitive fields.

Only metadata is logged: file paths, byte counts, entry counts, timing,
and error descriptions.

---

## 15. Threat Model Summary

| Threat | Mitigation |
|--------|-----------|
| ReDoS via malicious patterns | Regex size + DFA limits (1 MiB each) |
| YAML alias bomb | Input size + node count + depth caps |
| XML billion-laughs | Input size + element depth limits |
| Unbounded memory from large files | Streaming scanner (chunk + overlap) |
| Partial output after crash | Atomic file writes (tmp → fsync → rename) |
| Secret leakage in logs | No secret values in tracing output |
| Plaintext lingering in memory | Zeroize on Drop for keys, secrets, mappings |
| Reverse-engineering replacements | One-way only; no mapping table persisted |
| Equality/structure leakage in deterministic mode | Documented trade-off (§4); use random generator when unlinkability matters |
| Dictionary confirmation of low-entropy values | High-entropy, secret seed; non-deterministic mode removes the oracle (§4) |
| Thread oversubscription | CLI caps threads to `available_parallelism()` |
