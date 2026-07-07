## What does this PR do

<!-- One paragraph. What problem does it solve and how? -->

## Design principle check

<!-- scour-secrets has non-negotiable constraints documented in DESIGN.md.
     Answer each question that applies to your change. -->

- [ ] This PR does not add a reverse/restore mode or mapping file output
- [ ] If it touches HMAC output format: I've noted this is a breaking change and updated CHANGELOG.md
- [ ] If it adds a new category or formatter: property tests for length preservation are included
- [ ] No secret values, matched patterns, or replacements appear in logs, errors, or reports
- [ ] Any new buffering is gated behind a size limit with a streaming fallback
- [ ] Output still goes through `AtomicFileWriter` (no direct writes to destination paths)
- [ ] Defensive limits are unchanged or a new limit was added (none removed)

## Tests

<!-- What tests cover this change? If you added new tests, name them.
     If you didn't add tests for a behavioral change, explain why. -->

## MSRV impact

<!-- Does this change require a newer Rust version? If yes, why is it justified? -->

## Checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo fmt -- --check` passes
- [ ] Documentation updated if public API changed
- [ ] CHANGELOG.md updated (for user-visible changes)
