# Design Principles

This document captures the non-negotiable constraints and deliberate tradeoffs
that shape scour-secrets. Read it before opening a PR that touches core
behavior — it explains why things are the way they are and what proposals are
likely to be declined.

---

## 1. One-way, no restore

Sanitization is **permanent and intentional**. There is no mapping file, no
reverse mode, and no way to recover original values from the output. The tool
is for sharing sanitized data safely, not for encrypting data you want back.

PRs that add a reverse-lookup file, a restore subcommand, or any mechanism
that could reconstruct original values from output will not be merged. If you
need round-trip fidelity, this is the wrong tool.

## 2. Determinism is a first-class guarantee

In HMAC mode, the same input value + the same seed always produces the same
replacement — across runs, machines, and time. This lets teams share sanitized
outputs and compare them without coordinating who ran which tool when.

Any change to the HMAC mode output (new formatting, different truncation,
category reclassification) is a **breaking change** and must go through a
version bump and CHANGELOG entry. Do not alter category-specific formatters
in `generator.rs` without understanding the downstream impact on reproducibility.

Random mode is explicitly non-deterministic per run; within a single run the
dedup cache still guarantees consistency (the same input value always maps to
the same replacement within that run).

## 3. Length preservation

Replacements match the byte length of the original value. This keeps
downstream tooling (parsers, log analyzers, column-aligned formats) from
breaking on sanitized output.

The property tests in `tests/property_tests.rs` enforce this. Any new
category or formatter must include a length-preservation property test before
the PR is ready for review.

## 4. Secrets never leave the Rust process

No secret value — matched pattern, replacement, or intermediate — may appear
in logs, error messages, panic output, or structured reports. The JSON summary
reports file names, match counts, and timing; never matched content.

The MCP layer enforces the same boundary: the TypeScript wrapper never reads
or logs the content it proxies. Sensitive data flows only through the Rust
binary.

Violations of this principle are treated as security bugs, not quality issues.
Report them via `SECURITY.md`, not as public issues.

## 5. Memory-bounded for any input size

The streaming scanner processes arbitrarily large files in constant memory
(`chunk_size + overlap`). No feature may require buffering an entire file
unless it is gated behind an explicit size limit and falls back to the
streaming path when exceeded.

The existing structured processors (JSON, YAML, XML, CSV) buffer their input
but cap it at 256 MiB and fall through to the streaming scanner for larger
inputs. Any new structured processor must follow the same pattern.

## 6. Crash safety: atomic writes only

All output goes through `AtomicFileWriter`: write to a temp file, fsync,
rename. Readers never see a partial output file. Drop cleans up the temp file
if the process exits before `finish()`.

Do not write output directly to the destination path. Do not skip fsync for
performance.

## 7. Defensive limits are not optional

The tool accepts untrusted input by design — users routinely sanitize files
from third parties. Every parser has explicit size, depth, and node-count
limits. These are not conservative guesses; they are calculated to bound
worst-case memory while accommodating every legitimate real-world input we
are aware of.

Do not raise limits without a concrete motivating case and a documented
worst-case memory analysis. Do not remove limits. See
`docs/defensive-limits.md` for the full table and rationale.

## 8. The strategy trait is the extension point

Library users extend the tool through the `Strategy` trait in `src/strategy.rs`.
`Strategy::replace` receives the `Category`, the original value, and 32 bytes of
entropy, and must return a deterministic replacement. The `StrategyGenerator`
adapter handles entropy production (HMAC-deterministic or CSPRNG-random) so
strategies remain pure functions of their inputs.

The built-in `CategoryAwareStrategy` delegates to the same category-aware
formatters as the CLI — email-shaped for emails, IP-shaped for IPs, and so on.
Use it when you want CLI-quality replacements through the `Strategy` path, or
as a reference for what category-aware output looks like.

Before adding a new built-in category or formatter, consider whether a
user-defined strategy covers the need. The bar for a new built-in is:
_this pattern appears in real production data frequently enough that most
users would want it by default_.

## 9. MSRV changes require justification

The minimum supported Rust version is **1.86**, pinned by the
dependency tree (current `clap`/transitive crates require it) and
enforced by the MSRV jobs in CI. Raising the MSRV forces every
downstream user to update their toolchain. It is acceptable when a
dependency genuinely requires it or a language feature materially
improves safety or correctness — not for convenience.

## 10. Test coverage for behavioral changes

All behavioral changes require tests. The bar is:

- New category or formatter → property test for length preservation + at
  least one round-trip integration test.
- New structured processor → correctness tests + a size-limit fallback test.
- New CLI flag → a test in the CLI smoke-test block in `src/bin/sanitize.rs`.
- Security-relevant change → regression test in `tests/audit_fix_tests.rs`.

The test suite runs in CI on every PR. A PR that adds behavior without tests
will be asked to add them before merge.

---

## What this project is not

- A general-purpose anonymization library (we focus on structured secret
  patterns, not free-text NLP redaction).
- A reversible pseudonymization tool.
- A tool for operating on data in transit (it reads files or stdin; it does
  not run as a network proxy or man-in-the-middle interceptor). The optional
  HTTP daemon mode (`scour-secrets-mcp --http`) is a local-only control interface
  for AI tooling and does not process data in transit.
- An encryption tool (secrets files use AES-256-GCM for the pattern store,
  but the sanitized output itself is not encrypted).
