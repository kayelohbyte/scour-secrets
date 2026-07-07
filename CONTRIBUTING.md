# Contributing to scour-secrets

Thank you for your interest in contributing! This document explains how to
get started.

Before writing code, read [DESIGN.md](DESIGN.md). It explains the
non-negotiable constraints (determinism, length preservation, no secret
logging, memory bounds, atomic writes) and will save you from opening a PR
that can't be merged.

## Getting Started

```bash
git clone https://github.com/kayelohbyte/scour-secrets.git
cd scour-secrets
cargo build
```

## Running Tests

```bash
# Run the full test suite (300+ tests)
cargo test

# Run a specific test file
cargo test --test scanner_tests

# Run benchmarks
cargo bench
```

## Linting

All code must pass clippy with no warnings:

```bash
cargo clippy --all-targets -- -D warnings
```

## Formatting

Code must be formatted with `rustfmt`:

```bash
# Check formatting
cargo fmt -- --check

# Auto-format
cargo fmt
```

## Fuzz Testing

Four fuzz targets are provided under `fuzz/fuzz_targets/`. Fuzz testing
requires the nightly toolchain:

| Target | Purpose |
|--------|---------|
| `fuzz_regex` | Exercises regex compilation and scanning with arbitrary patterns and input data. |
| `fuzz_json` | Feeds arbitrary bytes through the JSON structured processor. |
| `fuzz_yaml` | Feeds arbitrary bytes through the YAML processor to exercise alias bomb mitigations. |
| `fuzz_archive` | Feeds arbitrary bytes through the tar archive processor. |

```bash
cargo +nightly fuzz run fuzz_regex
cargo +nightly fuzz run fuzz_json
cargo +nightly fuzz run fuzz_yaml
cargo +nightly fuzz run fuzz_archive
```

## Test Suite

The test suite includes 300+ tests spanning unit tests, integration tests, and
property-based tests (via `proptest`). Property tests verify length-preservation
(`replacement.len() == original.len()`) for all categories with random inputs.

| File | Coverage Area |
|------|---------------|
| Unit tests in `src/*.rs` | Scanner, store, generator, strategy, secrets, atomic writer, report, processors |
| `tests/scanner_tests.rs` | End-to-end scanner behaviour |
| `tests/processor_tests.rs` | Structured processor correctness |
| `tests/archive_tests.rs` | Archive processing (tar, tar.gz, zip) |
| `tests/secrets_tests.rs` | Encryption, decryption, parsing |
| `tests/plaintext_secrets_tests.rs` | Plaintext secrets: parsing, auto-detect, CLI flag, replacement correctness, determinism, fail-on-match, zeroization |
| `tests/report_tests.rs` | Report generation |
| `tests/property_tests.rs` | Property-based tests (proptest) |
| `tests/audit_fix_tests.rs` | Regression tests for audit findings |
| `src/bin/sanitize.rs` (inline) | CLI argument parsing smoke tests |

## Minimum Supported Rust Version (MSRV)

The MSRV is **Rust 1.86**, driven by the dependency tree (current
`clap`/transitive crates) and enforced by the MSRV jobs in CI. Do not use
language features or library APIs that require a newer version without
updating `rust-version` in `Cargo.toml`.

## Commit Guidelines

- Write clear, concise commit messages.
- Use the imperative mood in the subject line (e.g., "Add CSV depth limit"
  not "Added CSV depth limit").
- Keep commits focused — one logical change per commit.
- Reference issue numbers where applicable (e.g., `Fixes #42`).

## Pull Requests

1. Fork the repository and create a feature branch.
2. Ensure `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
   `cargo fmt -- --check` all pass.
3. Add tests for new functionality.
4. Update documentation if public API changes.
5. Open a pull request with a clear description of the change.

## Security

If you discover a security vulnerability, **do not open a public issue**.
See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0.
