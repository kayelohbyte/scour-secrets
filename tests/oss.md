Prepare this Rust project (scour-secrets) for its first public open source release.

This is a security-focused CLI + library for deterministic, one-way data sanitization with:
- Streaming scanner
- Structured processors (JSON, YAML, XML, CSV, key-value)
- Archive support (tar, tar.gz, zip)
- Deterministic and random modes
- Optional encrypted secrets file (AES-256-GCM)
- Length-preserving replacement option
- Zero unsafe code
- 290+ passing tests, 0 clippy warnings

Make the following improvements:

1. Repository Hygiene
- Add LICENSE (MIT OR Apache-2.0 dual license).
- Add CONTRIBUTING.md with:
  - How to run tests
  - How to run clippy
  - How to run fuzz targets
  - MSRV policy
  - Commit guidelines
- Add CODE_OF_CONDUCT.md (Contributor Covenant standard template).
- Ensure SECURITY.md includes responsible disclosure process and response timeline.

2. README Improvements
- Add a concise project description suitable for GitHub landing page.
- Add a “Security Model” section explaining:
  - One-way design
  - Deterministic mode limitations
  - Zeroization is best-effort
  - Threat model boundaries
- Add “Design Principles” section.
- Add installation instructions (cargo install).
- Add example workflows:
  - Encrypted secrets
  - Plaintext secrets
  - Deterministic mode
  - Length-preserving mode
- Add CLI reference table.
- Add performance notes (streaming, bounded memory).

3. CI Setup
- Create GitHub Actions workflow:
  - cargo check
  - cargo test
  - cargo clippy --all-targets -- -D warnings
  - cargo fmt -- --check
- Ensure MSRV is documented and enforced.
- Optional: build fuzz targets (no need to run them in CI).

4. Crate-Level Documentation
- Add crate-level docs in lib.rs with:
  - Example usage as a library
  - Example deterministic configuration
  - Example scanning workflow
- Ensure public API items have rustdoc comments.

5. Versioning & Release
- Prepare for v0.1.0 release.
- Add CHANGELOG.md with initial release notes.
- Ensure `--version` CLI prints version from Cargo.toml.
- Ensure Cargo.toml metadata includes:
  - description
  - repository
  - license
  - categories (command-line-utilities, security)
  - keywords (sanitization, redaction, privacy, pii)

6. Stability & Expectations
- Document which APIs are stable vs experimental.
- Clarify that CLI flags may evolve pre-1.0.
- Add note about semantic versioning policy.

Keep everything idiomatic Rust and consistent with existing project structure.
Do not introduce unsafe code.
Maintain current test coverage and lint cleanliness.