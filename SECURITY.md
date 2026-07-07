# Security Model

> **scour-secrets** v0.14.0

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

Secrets files are managed via the `scour-secrets encrypt` and
`scour-secrets decrypt` subcommands.

---

## 3. Password Handling

The password used for secrets encryption/decryption is resolved through
a priority chain designed to balance convenience with security:

| Priority | Source | Security Notes |
|----------|--------|----------------|
| 1 | `--password` flag | Triggers a secure **interactive prompt** — masked terminal input via `rpassword`. No trace in process listings, shell history, or environment. Requires a TTY; fails fast with a clear error in non-interactive contexts. |
| 2 | `--password-file <PATH>` | Reads from a file. The file **must** have Unix permissions `0600` or `0400` (owner read/write or owner read-only). Other permissions are rejected with an error. |
| 3 | `SCOUR_SECRETS_PASSWORD` env var | Avoids process listings but visible in `/proc/<pid>/environ` on Linux. |
| 4 | Automatic interactive prompt | Falls through to a masked terminal prompt when no password source is explicitly specified and a password is required. |

---

## 4. HMAC Determinism

When using `HmacGenerator`, replacements are derived from:

```
seed         = PBKDF2-HMAC-SHA256(password, salt, 600_000)   // 32 bytes
replacement  = HMAC-SHA256(seed, category_tag || "\x00" || plaintext_value)
```

- The **seed** is a 32-byte key derived from the `--password` (or
  `SCOUR_SECRETS_PASSWORD`) via PBKDF2. Same password + same salt + same value →
  same replacement across runs.
- The seed is zeroized on `HmacGenerator` drop.
- Category `domain_tag_hmac()` provides domain separation so e.g. an email
  `"alice"` and a hostname `"alice"` produce different replacements.

### Seed salt (per-install by default)

The PBKDF2 salt is **unique per install**, not a global constant. On the first
`--deterministic` run a 32-byte CSPRNG salt is generated and persisted at
`<config_dir>/seed-salt` (mode `0600`), then reused on every later run.

This closes the realistic off-box attack: an adversary who has only the
**shared sanitized output** (the artifact this tool is built to produce) cannot
run the dictionary-confirmation attack below without also possessing the salt,
which never leaves the machine. A global constant salt would let one
password→seed table attack every install at once.

Salt resolution order (deterministic mode):

1. `--seed-salt-file <PATH>` — file contents, used verbatim as the PBKDF2 salt.
2. `SCOUR_SECRETS_SEED_SALT` env var — string bytes, used verbatim.
3. Persisted per-install salt at `<config_dir>/seed-salt`.
4. Freshly generated and persisted (the default first-run path).

**Cross-machine reproducibility** now requires sharing the salt: copy the
`seed-salt` file, or set `SCOUR_SECRETS_SEED_SALT` / `--seed-salt-file` to a common
value across machines. **Migration:** output produced before per-install salts
existed is reproducible by setting `SCOUR_SECRETS_SEED_SALT` to the legacy constant
`scour-secrets:deterministic-seed:v1`.

> **One password, two uses.** The same password seeds both secrets-file
> decryption and the deterministic generator (with distinct salts). Guessing it
> offline compromises both, but the per-install secret salt means an off-box
> attacker cannot mount that guess against the seed at all. An in-process
> attacker who could read the live seed already sees the plaintext input (§8),
> so a separate seed secret would add no protection there.

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
- **Preserved-substring leakage.** To stay format-accurate, replacements
  retain non-secret structure verbatim: an email's domain, a hostname's
  suffix, a URL's host, a file extension, ARN/Azure known segments. If those
  substrings are themselves sensitive (e.g. an internal project name in a
  domain), add an explicit secrets-file rule for them or rely on the profile
  pass to discover and map them — the format-preserving formatters will not
  redact them on their own.
- **Dictionary confirmation with a weak/shared seed.** Because the
  mapping is `HMAC(seed, value)`, anyone who knows or guesses the seed can
  compute the replacement for any candidate value and confirm it against
  the output. A weak or widely-shared seed therefore enables dictionary
  confirmation of low-entropy values (short IDs, enum-like fields,
  common usernames). Use a high-entropy seed and treat it as a secret.

### What the non-deterministic (random) generator does and does not change

For workloads that do not need cross-run consistency, the random generator
(`RandomGenerator`, the default when `--deterministic` is not set) draws each
new replacement from the OS CSPRNG instead of `HMAC(seed, value)`. It changes
exactly two of the properties above:

- **Removes the dictionary-confirmation oracle.** There is no seed to guess, so
  an attacker cannot recompute a replacement from a candidate value.
- **Breaks cross-run equality linkage.** The same value sanitized in two
  *separate* invocations maps to unrelated replacements.

It deliberately leaves the other two properties **unchanged**:

- **Within-run / in-document equality still leaks.** The `MappingStore` caches
  the first replacement per value (first-writer-wins) for *both* generators,
  because "every occurrence of one secret maps to one replacement" is a core
  requirement of the tool. So inside a single sanitized document an observer can
  still tell which values were equal.
- **Structure / length still leaks.** Random replacements use the same
  length-preserving, category-shaped formatters, so length and rough format are
  preserved just as in deterministic mode.

In short: random mode buys cross-run unlinkability and removes the dictionary
oracle; it is **not** a way to hide value structure or in-document equality.
Hiding those would require abandoning the format-preserving and
same-secret-same-replacement guarantees, which is outside this tool's design.

### What the length-randomizing mode does and does not change

`--randomize-length` (`LengthPolicy::Randomized`) addresses the first residual
leak above — **structural / length leakage** — for callers who do not need
byte-accurate format preservation. Instead of sizing each replacement to the
original, it draws the length from a per-category band derived from the hash,
uncorrelated to the original. It composes with both the deterministic and the
random generator.

- **Hides the original's length.** A 6-digit number and a 14-digit number both
  map to a digit run whose length is decided by the hash, not the input. The
  output stays type-valid (digits stay digits, an email stays an email, a path
  keeps its extension).

It deliberately leaves these **unchanged**:

- **Preserved substrings still leak.** Non-secret structure that is copied
  verbatim — email domain, hostname suffix, file extension, ARN/Azure known
  segments — is unaffected; if those are themselves sensitive, add an explicit
  rule for them (same caveat as above).
- **In-document equality still leaks.** Within-run consistency is preserved via
  the `MappingStore` cache, so equal values still map to equal replacements
  inside one document.
- **Canonical-shape categories are not length-randomized.** UUID, MAC, IPv4,
  IPv6, container ID, Windows SID, and JWT keep their natural length, because a
  different length would make them structurally invalid (or, for JWT, buys
  little — these values are already high-entropy).

In short: length-randomizing mode hides the original's length while keeping
output type-valid; it does not hide preserved substrings or in-document
equality.

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
| Scanner chunk size | Configurable (default 1 MiB) | Peak memory ≈ 2 × chunk + overlap (a single match is carried up to `chunk_size`; longer matches are redacted, see §16) |

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

When `scour-secrets-mcp --http` is used, the server binds to `127.0.0.1` only and
requires a bearer token on every request:

| Property | Value |
|----------|-------|
| Bind address | `127.0.0.1` (loopback only — not reachable from the network) |
| Auth | Bearer token via `SCOUR_SECRETS_MCP_HTTP_TOKEN` (required; server refuses to start without it) |
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
| Secret leak at a chunk boundary | Edge-touching matches are carried, not committed; over-long matches are redacted (§16) |
| Partial output after crash | Atomic file writes (tmp → fsync → rename) |
| Secret leakage in logs | No secret values in tracing output |
| Plaintext lingering in memory | Zeroize on Drop for keys, secrets, mappings |
| Reverse-engineering replacements | One-way only; no mapping table persisted |
| Equality/structure leakage in deterministic mode | Documented trade-off (§4); random generator removes cross-run linkage + the dictionary oracle, but not in-document equality or length/structure |
| Dictionary confirmation of low-entropy values | High-entropy, secret seed; non-deterministic mode removes the oracle (§4) |
| Thread oversubscription | CLI caps threads to `available_parallelism()` |

---

## 16. Chunk-Boundary Leak Mitigation

The streaming scanner processes input in `chunk_size` windows. A match that
runs to the right edge of a window may be **truncated** by the buffer — more of
it could arrive in the next chunk. Committing such a match would emit a
replacement for a *partial* secret and pass the continuation through verbatim
(the continuation no longer matches the pattern). The scanner prevents this:

1. **Carry, don't commit.** A match that ends at the window edge (and is not at
   EOF) is **not** committed. The commit point is pulled back to the match
   start so the whole match is carried into the next window and re-scanned with
   more context. Matches up to `chunk_size` bytes are therefore always seen in
   full before replacement, and a value split across windows still maps to a
   single replacement.
2. **Fail closed on over-long matches.** A single match longer than
   `chunk_size` can never be buffered. Rather than risk leaking its tail, the
   scanner replaces the entire run with a fixed marker
   (`__SANITIZED_OVERLONG__`) and consumes the rest of the run up to the next
   whitespace boundary. This is not length-preserving, but such a match (an
   unbroken token larger than a chunk) is pathological; redaction is the safe
   default. A per-pattern `max_length` in the secrets file bounds greedy
   patterns before they reach this point.

---

## 17. Residual Leak Surface (Format Preservation)

Format preservation (Core goal 2) intentionally keeps some properties of the
original data in the sanitized output. None of these reveal a secret value
directly, but each can carry information; know them before sharing output from
highly sensitive contexts:

| What survives | Where | Why | How to reduce it |
|---------------|-------|-----|------------------|
| **Value length** | All categories under the default `LengthPolicy::Preserve` | Replacement byte length exactly matches the original (keeps layouts/column alignment intact) | `--randomize-length` draws lengths from per-category bands instead |
| **Email domain** | `email` | `alice@corp.com` → `x7f2…@corp.com`; the domain is treated as context, not secret | Add a `hostname`/`regex` pattern covering the domain itself |
| **Hostname suffix** | `hostname` | `db01.internal.corp` keeps `.internal.corp` | Add a broader hostname pattern or an explicit literal |
| **Structural shape** | `url`, `file_path`, `aws_arn`, `azure_resource_id`, JWT 3-segment form, UUID/MAC/IP formats | Separators and known segments are copied so the value stays type-valid | Inherent to format preservation; use `custom:` categories for full opacity |
| **Match count & positions** | All output | Every replacement marks *where* a secret occurred and how many there were | Inherent — the output is a redaction of the input |
| **File names & structure** | Reports, archive output, `--llm` manifests | Paths and entry names are treated as non-secret metadata | Rename inputs before running, or post-filter reports |

Two related persistence notes:

- **Structured handoff** (`--profile`): discovered original values are
  appended to your secrets file as detection patterns — written `0600`,
  re-encrypted when the file is encrypted, originals only (never the
  replacements, so no mapping exists). Disable with `--no-structured-handoff`.
- **Deterministic mode**: anyone holding the password **and** the per-install
  seed salt can confirm guesses against sanitized output (see §4 and §8).
  Treat the salt file like a key file.
