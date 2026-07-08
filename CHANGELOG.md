# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] — 0.16.0

### Security

- **Parse errors never echo secrets-file content.** A malformed TOML secrets
  file previously rendered the offending source line (with literal secret
  values) into the error on stderr; serde JSON/YAML data errors embedded
  mistyped values the same way. All three parsers now report format +
  line/column only.
- **TOML *data-file* parse errors never echo input content.** The structured
  TOML processor had the same bug as the secrets-file parser above: a
  malformed TOML input file rendered the offending source line — including
  any secret on it — into the `warn!`/error output during a `--profile` run.
  Both the re-serializing and the span-edit TOML paths now report line/column
  only.
- **The streaming scanner fails closed on invalid capture bounds.** If a
  match ever carried capture-group bounds outside the match bounds (not
  reachable with the `regex` crate; defensive path), the scanner previously
  emitted the full match *unreplaced*. It now falls back to replacing the
  full match.
- **XML parse errors never echo input content.** The structured XML processor
  rendered `quick-xml`'s error `Display` — which embeds element names
  (mismatched-tag errors) and, in some entity/attribute decode errors, the
  offending substring — into the `warn!`/error output. All XML parse, decode,
  and attribute error paths now report a byte position only.
- **MCP `test_pattern` / `test_allowlist` no longer pass candidate values on
  the command line.** Test values — which are frequently real secrets — were
  visible to every local user via `ps` while the subprocess ran. They are now
  piped over stdin (one per line); as a side effect, values starting with `-`
  are now testable, while empty values and values containing newlines are
  rejected with a clear error (the line protocol cannot carry them).
- **Encrypted secrets files now receive the structured-handoff write-back**:
  decrypt → merge discovered literals → re-encrypt (fresh salt + nonce) with
  the same password. The file on disk is never downgraded to plaintext, and
  the write-back fails closed (file untouched) on a wrong or missing password.
- **Key derivation switched from PBKDF2 to Argon2id** (memory-hard: 19 MiB,
  2 passes, 1 lane) for both the encrypted secrets-file key and the
  deterministic-generator seed, giving one modern KDF everywhere and dropping
  the `pbkdf2` dependency. Argon2id resists GPU/ASIC-accelerated offline
  brute-force far better than an iterated PBKDF2.
- **Warns when `--llm-endpoint` uses plain `http://` to a non-loopback host** —
  the API key and the (sanitized) prompt would travel in cleartext. A local
  model over `http://localhost` does not warn; `https://` never warns.
- **Encrypted secrets files carry a versioned header** (`SCOUR` magic +
  1-byte version, then salt/nonce/ciphertext). Encrypted-vs-plaintext detection
  is now exact instead of a content heuristic, so a plaintext file whose first
  token is a bare key can no longer be misread as ciphertext. A future KDF or
  parameter change bumps the version byte without changing the magic.

### Changed — BREAKING

- **Project renamed to `scour-secrets`** (crate, lib, and binary; previously
  `rust-sanitize` / `sanitize`). Env vars are now `SCOUR_SECRETS_*` (previously
  `SANITIZE_*`), the config directory is `~/.config/scour-secrets/`, the project
  config file is `.scour-secrets.yaml`, and the MCP binary is `scour-secrets-mcp`
  (server name `scour-secrets`). MCP *tool* names (`sanitize`, `scan`, …) and
  `-sanitized` output suffixes are unchanged.
- **API freeze ahead of 1.0.** Public structs and the `LengthPolicy`,
  `SecretsFormat`, `ArchiveFormat`, and `EntropyMode` enums are now
  `#[non_exhaustive]`: struct literals and exhaustive matches outside the
  crate no longer compile. Use the new constructors — `SecretEntry::new` +
  `with_*`, `ReportMetadata::new` + `with_*`, `FileReport::new`,
  `Replacement::new`, `EntropyMode::deterministic` — or serde. Result structs
  (`SecretsLoadResult`, `AllowlistResult`, `AutoLoadedSecrets`) must be read
  by field access instead of destructured exhaustively.
- **`load_secrets_auto` returns `AutoLoadedSecrets`** (named struct) instead
  of the nested tuple `((PatternCompileResult, Vec<String>), bool)`.
- The structured-handoff write-back now preserves the secrets file's own
  plaintext format — a `.json` secrets file previously came back rewritten as
  YAML, and `.toml` write-back failed outright.
- **Crypto format break (no migration).** The Argon2id switch and the new
  versioned encrypted-file header mean secrets files encrypted by 0.15.x no
  longer decrypt, and `--deterministic` output differs from earlier releases
  even with the same seed salt. Re-encrypt secrets files with `scour-secrets
  encrypt` and regenerate any shared deterministic datasets on 0.16.0+.

### Added

- **`command_output` processor** for `> command` + output-block support dumps
  (Dataiku `diag.txt`, Elastic diagnostics, `mdiag`, sosreport-style files).
  Field rules glob-match the *command string* (`hostname*` matches
  `hostname --fqdn`); a rule with `sub_processor` delegates the block content
  (e.g. a `printenv` block to the `env` processor), a rule without one
  replaces the trimmed block as a single value. Prompt lines, separators, and
  unmatched blocks are preserved byte-for-byte. The `prompt_prefix` option
  (default `"> "`) adapts it to other dump styles. The sub-processor dispatch
  used by `key_value` heredocs is now shared in `processor::mod`.
- **The dataiku app captures the machine hostname and environment** from
  `diag.txt` (`hostname --fqdn` output; `printenv` delegated to the env
  processor for proxy/password/secret/token/key variables), catches the live
  `accessToken`/`identityToken` in `run/user-sessions.json`, and redacts
  whole-line base64 blobs (`run/shared-secret.txt`). Discovered values are
  seeded so bare occurrences in `uname` output, `sysctl.txt`, and logs are
  scrubbed too.
- **Entropy detection now runs on archive inner entries.** `kind: entropy`
  secrets entries and `--entropy-threshold` previously did nothing for files
  inside zip/tar archives (the pass lived in the CLI dispatch layer). The
  detection core moved into the library (`entropy` module, re-exported at the
  root) and `ArchiveProcessor` gained `with_entropy_configs`.
- `tracing` warning when an unknown bare category string (e.g. a typo like
  `emial`) silently maps to a custom category; use the `custom:` prefix to
  silence it. Category parsing is now consolidated in one place
  (`parse_category`) for both secrets files and profiles.
- Stability contract on `Processor` / `Strategy` / `ReplacementGenerator`:
  new trait methods will always ship with default implementations.
- Root re-exports for `ReportSummary`, `MatchLocationsResult`, `Replacement`,
  and the `secrets::` free functions.
- **`tracing-subscriber` is now gated behind the `cli` feature.** It is only
  used by the binary's logging setup; library-only consumers
  (`default-features = false`) no longer pull it (and its `json` / `env-filter`
  machinery). No effect on the default build or the CLI.
- **`ROADMAP.md`** documenting the stability posture, the path to 1.0, and the
  features deliberately deferred past 1.0.
- **Release: `cargo publish` to crates.io** is now automated in the release
  workflow (gated on the build matrix, with a tag-vs-`Cargo.toml`-version
  guard), so tagged releases reach crates.io instead of only shipping binaries.
- **CI: `cargo-semver-checks` job** that diffs the public library API against
  the latest crates.io release and fails a PR whose version bump is not
  semver-appropriate. It self-skips until the crate is first published (there
  is no baseline yet), then activates automatically.
- **Documented MSRV policy:** raising the MSRV is a minor-version bump (noted
  in the changelog), not a breaking change, and only happens when a dependency
  or a required language feature makes it necessary (README + CONTRIBUTING).

### Fixed

- **Seeded name-category literals now require word boundaries.** A discovered
  login like `admin` was replaced as a raw substring, rewriting
  `administrators` (silently defeating its own allowlist entry), JSON keys
  like `adminProperties`, and path segments like `dssadmin`. Tokens and
  passwords stay substring-matched.
- **IPv4 replacements are always valid addresses** (each octet keeps its digit
  count but is drawn from 0–255; no more `794.55.0.9`), and **URL replacements
  keep the scheme** (`https://` no longer becomes hex).
- **The structured-handoff write-back deduplicates within a batch** — the same
  value discovered under two categories was written to the secrets file twice.
- **`--app` bundle copies land in the documented config directory**
  (`~/.config/scour-secrets/apps`, honoring `XDG_CONFIG_HOME`; previously
  `~/.config/scour/apps`), and `show-config` now lists the directory, the
  provisioned apps, and the write-back behavior. The auto-created default
  secrets template is written owner-only (0600).
- **The "no secrets file or --app provided" warning no longer fires when one
  was given.** A provided config that yields no patterns, profiles, or entropy
  rules gets its own accurate message instead.
- **The structured-handoff write-back no longer persists trivially short
  discovered values.** A structured field that held a 1–3 character value
  (e.g. `v`, `id`) was written to the secrets file as a global `kind: literal`
  entry, which then matched that fragment everywhere in every subsequent run —
  corrupting unrelated text (`sensitive` → `sensiti9e`). Discovered literals
  now share the format-preserving scanner's minimum-length threshold
  (`MIN_DISCOVERED_LITERAL_LEN`, currently 4) for both in-run use and
  write-back, so a value the scanner would reject is never persisted. Existing
  secrets files that already accumulated such short literals should have them
  removed by hand.

## [0.15.0] - 2026-06-26

### Security

- **Fixed a chunk-boundary secret leak in the streaming scanner.** A single
  match longer than the scan window (`chunk_size + overlap`) was matched
  greedily to the window edge, committed as a *complete* replacement, and its
  continuation in the next chunk was emitted **verbatim** (the continuation no
  longer matched the pattern). This affected unbounded patterns (`url`,
  `credential_url`, `secret_kv`, long token/base64 runs). The scanner now
  carries an edge-touching match into the next window instead of committing a
  truncated one, so matches up to `chunk_size` are always seen in full. A
  single match longer than `chunk_size` (pathological) is now redacted with a
  fixed `__SANITIZED_OVERLONG__` marker rather than leaking its tail. See
  SECURITY.md §16.

### Added

- **`--randomize-length` ("format doesn't matter") replacement mode.** Opt-in
  flag that draws each replacement's length from a per-category band derived
  from the hash, independent of the original, so the output no longer leaks the
  secret's length. Output stays type-valid (a number stays digits, an email
  stays an email, a path keeps its extension) and preserved substrings (email
  domain, file extension, ARN/Azure known segments) are unchanged. Composes with
  `--deterministic`. Canonical-shape categories (UUID, MAC, IPv4/6, container ID,
  Windows SID, JWT) keep their natural length. Exposed in the library as
  `LengthPolicy` / `Generator::with_length_policy`. See SECURITY.md §4.
- **Per-install deterministic seed salt.** The PBKDF2 salt for `--deterministic`
  mode is now a unique, secret, per-install value (generated and persisted at
  `<config_dir>/seed-salt`, mode `0600`) instead of a global constant. This
  prevents a single password→seed table from attacking every install, and
  closes the off-box dictionary-confirmation attack against shared output.
  Override with `--seed-salt-file <PATH>` or `SCOUR_SECRETS_SEED_SALT` to share a
  salt across machines for reproducible team output. See SECURITY.md §4.
- **`min_length` / `max_length` secrets-file fields are now enforced.** These
  documented per-entry bounds were previously dropped during pattern
  compilation; matches outside `[min_length, max_length]` are now discarded.
  `max_length` also bounds greedy patterns before the over-long redaction path.
- **Scripted demo recordings** under `docs/demos/` — four flows (zero-config
  scan, dry-run/CI gate, app bundles, pipe/structured fields) captured as both
  VHS GIFs and asciinema casts, regenerable via `docs/demos/render.sh`. The
  quickstart GIF is embedded in the README.

### Changed

- **BREAKING (deterministic output):** because the seed salt is now per-install,
  deterministic output changes versus prior versions. To reproduce pre-upgrade
  output, set `SCOUR_SECRETS_SEED_SALT=scour-secrets:deterministic-seed:v1` (the
  legacy constant). Cross-machine reproducibility now requires copying the
  `seed-salt` file or setting the env/flag to a shared value.

### Fixed

- **First-run creation of the default secrets file and the per-install seed
  salt is now atomic and safe under concurrent first runs.** Each is written to
  a temp file and then claimed (rename / `hard_link`), so a parallel first run
  can no longer observe a half-written file. Previously two concurrent first
  runs could persist different seed salts (inconsistent deterministic output),
  or a run could load a half-written secrets file and fall through to zero
  patterns (an unsanitized passthrough). First-run write errors now fail closed
  instead of silently running with no patterns.

## [0.14.1] - 2026-06-24

### Added

- **`--no-baseline` flag.** Opts out of the built-in baseline detectors for
  app-only precision (use an app bundle's curated rules and nothing else). The
  baseline is composed by default; this is the escape hatch when over-redaction
  matters more than recall.

### Changed

- **Connection-string and `key=value` secrets are redacted in place, preserving
  surrounding context.** The baseline `credential_url`, `password_kv`, and
  `secret_kv` detectors now capture just the secret, so the scheme, host, port,
  database, query params, and the `key=` name survive:
  `postgres://app:secret@db:5432/orders?sslmode=require` →
  `postgres://‹token›@db:5432/orders?sslmode=require`, and
  `password=secret,ssl=True` → `password=‹token›,ssl=True`. The `password_kv`
  value class also stops at the structured separators `, ; &` so trailing
  parameters aren't swallowed. Previously the whole URI / whole `key=value…` run
  was replaced, destroying troubleshooting context. `credential_url` also now
  matches the password-only form `redis://:secret@host` (empty username), which
  was previously only caught incidentally (by the email detector) and leaked on
  `localhost`/IP hosts. (These improvements made the whole-URI connection-string
  rules in the `mongodb`, `mysql`, and `redis` bundles redundant — removed; see
  Fixed — and the `DATABASE_URL` / `REDIS_URL` / `CELERY_BROKER_URL` /
  `JDBC_DATABASE_URL` / `CLOUDINARY_URL` / `BONSAI_URL` whole-value field rules
  in the `django`, `mysql`, `heroku`, `rails`, and `redis` bundles were removed
  in favor of the precise baseline, plus `ELASTICSEARCH_HOSTS` in the
  `elasticsearch` bundle and `*.datasource.url` / `spring.datasource.url` in the
  `spring-boot` bundle, whose URL holds no secret — the credentials are separate
  username/password properties.) `credential_url` is now ordered before the generic
  `url` detector so a credential-bearing `https://user:pass@host` URL is redacted
  precisely rather than whole (the generic detector still redacts plain URLs).
- **The built-in baseline detectors are now composed under `--app`, not just on
  a plain run.** App bundles are now a layer *on top of* the generic baseline
  (email, IP, UUID, URL, home path, common token shapes) rather than a
  replacement for it, so `scour-secrets --app <name>` scrubs generic PII in
  unstructured dumps that the bundle's curated rules don't target. Previously the
  baseline only loaded when no app/secrets file was given, so e.g. a Dataiku
  diagnosis sanitized with `--app dataiku` still shipped every email, IP, UUID,
  and `/home/<user>` path in its `*.txt`/log files. Pass `--no-baseline` for the
  old app-only behavior. This raises recall (the right default for a one-way
  egress scrubber) at the cost of more aggressive redaction; bundle allow-lists
  tune the false positives.
- **`user_home_path` redacts only the username, preserving the path.**
  `/home/alice/.ssh/id_rsa` now becomes `/home/‹token›/.ssh/id_rsa` instead of
  replacing the whole `/home/alice` span, so sanitized paths stay readable. The
  segment charset no longer includes `.`, so the match can't swallow file
  extensions (`/home/foo.html` → `/home/‹token›.html`), which also makes the
  `/home/`-namespaced web-route false positives cosmetically harmless. No real
  usernames are missed (POSIX usernames contain neither dots nor slashes).
- **Baseline `aws_access_key_id` now covers all AWS unique-ID prefixes**
  (`ABIA ACCA AGPA AIDA AIPA AKIA ANPA ANVA APKA AROA ASCA ASIA`), not just the
  four access-key/STS prefixes — so role (`AROA`), user (`AIDA`), and other
  unique IDs are caught everywhere. The redundant per-bundle JWT and AWS-key
  rules that re-implemented baseline detectors were removed from `aws-cli`,
  `bruno`, `har`, `insomnia`, `postman`, and the `postgres://…@…` rule from
  `postgresql` (all now covered by the composed baseline `jwt` / `credential_url`
  detectors). No detection coverage is lost.
- **Dataiku bundle: allow the DSS service-account paths and vendor URLs.**
  `/home/dataiku` (via the already-allowed `dataiku` username), `/home/projects`
  (via `projects`), and `https://*.dataiku.com*` (public docs/help/update — not
  customer endpoints) are passed through, now that the baseline composes under
  `--app dataiku`.
- **GitLab bundle: added 6 missing token types, fixed the log profiles, and
  expanded `gitlab.rb` coverage.** New token-prefix detectors for OAuth
  application secrets (`gloas-`), pipeline trigger (`glptt-`), incoming mail
  (`glimt-`), workspace (`glwt-`), feature-flags client (`glffct-`) tokens, and
  the `glrtr-` runner-registration variant — previously only 7 of GitLab's token
  types were caught. The `gitlab.rb` profile now also redacts the
  OAuth/Azure/object-store identifiers from gitlab-scrubber's `sensitiveKeyPatterns`
  (`client_id`, `app_id`, `application_id`, `tenant_id`, `accountname`,
  `_account_name`, `bucket`), and the production-log profile adds
  `meta.namespace` / `meta.root_namespace`.

- **Structured redaction is now span-based — fully format-preserving and
  leak-free.** JSON, JSONL, YAML, TOML, XML, and CSV are sanitized by replacing
  each matched value at its **exact source byte span** rather than
  re-serializing the parsed tree (which lost comments/formatting) or matching the
  parsed value against the raw bytes (which leaked values escaped in the source).
  Comments, key order, quoting style, whitespace, and the escaping of unrelated
  content are preserved byte-for-byte, and each value is redacted **as it appears
  in the source** — so values written `\/` or `\uXXXX` (JSON), as XML entities,
  with CSV `""` doubling, or as quoted/escaped YAML/TOML scalars are hit directly
  and never leak. Applies across standalone files, stdin, and archive entries; a
  processor that can't parse an input falls back to the previous behavior.
  New byte-span parser dependencies: `toml_edit` (TOML), `jiter` (JSON/JSONL),
  `saphyr-parser` (YAML), and `csv-core` (CSV); XML reuses `quick-xml`.
  Non-escaping processors (INI, env, key-value, log-line) are unchanged.

### Fixed

- **Extensionless config files matched by a profile now redact.** A profile's
  extension gate is a hard prerequisite, so a profile listing `extensions:
  [".yaml"]` (etc.) skipped extensionless files even when its `include` named
  them — the standard kubeconfig `~/.kube/config` leaked `client-key-data` /
  `client-certificate-data`, and extensionless nginx vhosts under
  `sites-available/` / `sites-enabled/` leaked `server_name` and proxy targets.
  Both bundles now also list `""` in `extensions` (matching the aws-cli pattern),
  so the include list governs the match.
- **fstab: server addresses after the first mount line no longer leak.** The
  CIFS (`//host/share`) and NFS (`host:/export`) server-address patterns were
  anchored with `^` but lacked the multiline flag, so `^` matched only the start
  of the whole file — every mount line after the first kept its server address
  unredacted. The patterns now use `(?m)`. (The redundant first-column device-IP
  rule was dropped; the baseline `ipv4` detector already matches every line.)
- **Profiles with a path-anchored `include` now match plain files.** The
  structured-vs-scanner decision and profile lookup for a plain file used only
  its basename, so an `include` with a path component — `group_vars/*.yml`,
  `.aws/credentials`, `.circleci/config.yml` — matched during the phase
  partition (which uses the full path) but failed during actual processing,
  silently dropping the file to the plain scanner with its profile inert. The
  field rules in the `ansible`, `aws-cli`, and `circleci` bundles (and any
  path-anchored profile) were effectively dead for on-disk files. File dispatch
  now matches on the full path, consistent with the partition. (Archive entries
  were unaffected — they already matched on the entry path.)
- **Three app bundles had silently-dropped (non-compiling) regex patterns.**
  The Rust regex engine rejected them at load — `mongodb` and `mysql` connection-
  URI rules used an unsupported trailing look-ahead `(?=…)`, and `redis`'s Azure
  connection-string rule blew past the compiled-size limit via a unicode
  `[\w\d.-]{1,100}` host class — so those detectors never ran. No leaks resulted
  (the composed baseline covered these cases), and with the baseline now redacting
  connection-string secrets precisely (below), all four URI rules in those bundles
  were removed as redundant — the baseline handles them with less collateral. The
  `kubernetes` service-account-token rule, a plain JWT already covered by the
  baseline `jwt` detector, was likewise removed.
- **The run summary now counts in-place structured field redactions.** Profile
  field edits on a plain structured file are applied as exact span replacements
  and never re-matched by the scanner, so they were invisible to `total_matches`
  — the summary printed `Redacted: nothing` (or undercounted) while the file was
  correctly scrubbed. The structured edit pass now reports its edit count, folded
  into the summary under a `profile-field` bucket (per-category attribution isn't
  available at the span-edit layer). Archive and stdin paths, which already count
  these via the augmented scanner / store growth, are unchanged.
- **A profile that declares a non-structured extension now actually runs.**
  The structured-vs-scanner decision was made purely from the file extension
  (`is_structured_filename`), so a profile declaring e.g. `extensions: [".log"]`
  was silently dropped to the plain scanner and its field rules never fired —
  even though profile *selection* already matched the file. The gate is now
  profile-aware (a file is structured-eligible if its extension is structured
  **or** a loaded profile matches it), applied to both the discovery pre-pass and
  the output pass. This revived the GitLab bundle's five `.log` log profiles
  (production/sidekiq/workhorse/gitaly/shell), which were dead code; they are also
  switched from the single-document `json` processor to `jsonl` so every line of
  these line-delimited logs is scrubbed, not just the first. Regression test in
  `tests/app_bundle_tests.rs`.
- **VCS and hidden directories are now actually pruned during a directory walk.**
  Skipping the directory *entry* still let walkdir descend into it, so `.git/`
  contents and hidden-directory contents (e.g. `.secretdir/inner.txt`) were
  processed and written to the output despite "VCS dirs always skipped" and the
  `--hidden` documentation. The walk now prunes the whole subtree (the
  explicitly-provided root is never pruned).
- **stdin is now discovered before structured files are written.** A value seen
  only as a matched field in stdin reappearing in another file (e.g. a comment)
  used to leak from that file, because stdin was processed *after* the structured
  output pass. stdin discovery now runs alongside files/archives, before the
  augmented scanner and the structured-file output, so its values are redacted
  everywhere. (A value that is structurally undiscoverable — not in the secrets
  file and not a matched field anywhere — still cannot be redacted, by design.)
- **No-leak hardening across input sources (found via an input-source matrix).**
  A new `tests/input_source_matrix_tests.rs` asserts the core rule — a secret
  never appears in output, stdout, or stderr/logs — across every combination of
  stdin / file / archive (incl. archives nested in archives, a file per
  processor type, canaries spanning sources, special/escaped/Unicode values),
  reading the actual bytes of every artifact. It found two leaks, both fixed:
  - **Literal secrets leaked into the `Redacted:` summary / findings / logs.** A
    `literal` secrets-file entry with no explicit label defaulted its label to
    its own pattern — the raw secret value — which is printed in the summary and
    reports. Literals now default to `literal:<category>`; regex patterns (not
    themselves secrets) still default to their text.
  - **`--format` forced *file* inputs to the stdin format, leaking escaped
    values.** Piping structured stdin needs `--format`, but it also clobbered
    accompanying files (e.g. `--format json` made a `.yaml` file parse as JSON →
    no structured edits → its escaped values leaked). A file whose extension
    already maps to a structured format now keeps it; `--format` only fills in
    for stdin and untypeable inputs.
- **No-leak hardening across formats (found via a systematic leak matrix).**
  Six issues in the span-based path are fixed, each with regression coverage in
  `tests/leak_matrix_tests.rs` (format × value-class incl. Unicode/TSV × location
  × scope × EOF/BOM):
  - **CSV:** the last field of a file with **no trailing newline** was dropped
    (and, if it matched a rule, leaked) because the `csv-core` loop broke on
    `InputEmpty` before the EOF flush call.
  - **Cross-location escaped values:** a value discovered in a matched field
    leaked when it reappeared in an **unmatched** field of another file that
    escaped it differently (JSON/YAML `\"`, CSV `""`, XML `&quot;`). The
    span-edit discovery path no longer skips registering the format-escaped
    store aliases the phase-2 scanner relies on.
  - **XML unmatched attributes:** the escaped alias over-escaped `'`/`>`, missing
    the realistic double-quoted-attribute form; context-specific XML alias forms
    are now registered.
  - **YAML quoted scalars:** a `"…"`/`'…'` value followed by an inline
    `# comment` lost the comment (saphyr's span runs to end-of-line); the span is
    now clamped to the closing quote.
  - **BOM-prefixed JSON/JSONL:** a leading UTF-8 BOM made jiter error, so a
    matched value was never redacted; the BOM is now skipped for parsing and
    preserved in the output.
  - **YAML multi-byte UTF-8:** a matched scalar following multi-byte content
    (e.g. an accented header comment) was sliced at the wrong byte position and
    the output corrupted, because saphyr's `Marker::index()` is a character
    count, not a byte offset; char indices are now translated to byte offsets.
- **`process()`-path alias parity.** The non-span path (INI, env, key-value, and
  the oversized-file fallback) now registers the same cross-format escaped
  aliases as the span-edit path, so a value discovered on either path is redacted
  wherever it reappears escaped in another file.
- **Structured entries inside archives now preserve comments and formatting.**
  A profile-matched entry in a `.zip`/`.tar`/`.tar.gz` was re-serialized from its
  parsed tree, which silently dropped YAML/TOML comments and reflowed JSON
  whitespace and key spacing — unlike standalone files, which are byte-preserving.
  Archive entries now redact field values (and non-structural patterns) over the
  original bytes, matching the plain-file path: comments, key order, and
  whitespace are preserved, and a secret that also appears in a comment is still
  redacted.

### Upgrade notes

- **A previously-seeded local app copy shadows these built-in bundle changes.**
  The first time you run `--app <name>`, sanitize writes a user-local copy of the
  bundle to `$SCOUR_SECRETS_APPS_DIR/<name>/` (the two-pass write-back target), and on
  later runs `load_app_bundle` loads that copy in preference to the embedded
  built-in. So if you ran a bundle under 0.14.0, the connection-string rule
  removals, new GitLab token types, expanded AWS prefixes, and Dataiku allow-list
  above will **not** take effect until you refresh the copy. Re-sync with
  `scour-secrets apps remove <name> --yes` (then re-run `--app <name>`), or delete the
  stale directory under `$SCOUR_SECRETS_APPS_DIR`. Custom edits you made to that copy
  are intentionally preserved — this only matters for bundles you hadn't
  customized.

## [0.14.0] - 2026-06-21

### Added

- **Cargo feature flags** for slimmer library builds. The crate now exposes
  `cli` (clap/ureq/walkdir/ctrlc/rpassword), `archive` (zip/tar/flate2), and
  `structured` (csv/quick-xml) features, all on by default. Library-only
  consumers can opt out via `default-features = false` and re-enable only what
  they need; JSON/YAML/TOML/INI/env/key-value/log-line and the streaming
  scanner remain always-on. Default builds (`cargo install`, release artifacts)
  are unchanged.

### Changed

- **Documented MSRV corrected to 1.86** across README, DESIGN.md, and
  CONTRIBUTING.md to match `Cargo.toml` and CI (docs previously lagged at 1.74).

### Fixed

- **Duplicate values across structured files leaked in all but the first.**
  When several profile-matched files were sanitized in one run, a value that
  appeared in more than one of them (e.g. the same email in `users.json` and
  `license.json`) was redacted only in the first file processed and shipped in
  plaintext in the rest. Each structured file built its format-preserving
  scanner from its own discovery delta, so values already in the store from an
  earlier file were skipped. The `--profile` pipeline now runs a discovery
  pre-pass over all structured files before writing any output, then builds each
  file's scanner from the full store. Results are now independent of
  command-line order, and cross-file values are also caught in comments and
  unstructured regions of structured files.

## [0.13.1] - 2026-06-19

### Fixed

- **INI processor panic on invalid UTF-8** — a `=` followed by a non-UTF-8 byte
  could cause the delimiter-reconstruction logic to slice a multi-byte
  replacement character (`U+FFFD`, produced by lossy UTF-8 decoding) at a
  non-char-boundary, panicking. The slice is now boundary-checked and falls back
  to the default delimiter. Found by the `fuzz_ini` target.

### Security

- **MCP file path guards** now resolve symlinks and match the operator denylist
  against the canonical path. This closes an absolute-path bypass where a path
  like `/x/secrets/y` slipped past a `secrets/**` `SCOUR_SECRETS_MCP_FILES_DENYLIST`
  pattern (start-anchored glob), and prevents a symlink in an allowed directory
  from reaching `SCOUR_SECRETS_SECRETS_DIR` or a `.password` file.
- **MCP HTTP daemon** compares the bearer token in constant time (over SHA-256
  digests), removing a token timing/length oracle.

## [0.13.0] - 2026-06-12

### Added

- **`--quick PATTERN[,PATTERN…]` flag** — add one-off literal or regex patterns
  for the current run without creating or modifying a secrets file. Bare values
  are matched literally; prefix with `regex:` to enable regex matching, consistent
  with the `--allow` convention. Patterns are merged with any `--secrets-file` /
  `--app` patterns for the same run.

- **`balanced` and `aggressive` template presets** — two new presets for
  `scour-secrets template`. `balanced` produces a ready-to-edit YAML that mirrors the
  built-in runtime detection set (the same patterns activated by omitting
  `--secrets-file`). `aggressive` extends `balanced` with high-entropy block
  detection, bearer / authorization header patterns, and short container IDs.

- **Namespace `settings.yaml` in MCP** — per-namespace behavior defaults loaded
  from `$SCOUR_SECRETS_SECRETS_DIR/<namespace>/settings.yaml` alongside the existing
  secrets file and profile. Supports all scan-behavior flags (e.g. `fail_on_match`,
  `force_text`, `entropy_threshold`, `allow`, `exclude_path`). Per-call tool
  parameters always override namespace defaults.

- **`IniProcessor`** — new structured processor for INI / CFG files (`*.ini`,
  `*.cfg`). Handles `[section]` / `key = value` and `key: value` syntax,
  preserves comments and blank lines, and strips inline comments to prevent
  sensitive context leaking into output. Field rules use dot-path notation
  (`database.password`, `*`, `global_key`). Register with processor name
  `"ini"` in a profile.

- **Fuzz targets for `IniProcessor` and `XmlProcessor`** — `fuzz_ini` and
  `fuzz_xml` feed arbitrary bytes through the respective structured processors,
  covering malformed input, deeply nested elements, crafted entity references,
  binary content, and oversized values.

- **`CategoryAwareStrategy`** — new built-in [`Strategy`] implementation that
  delegates to the same category-aware formatters used by the CLI. Produces
  email-shaped, IP-shaped, JWT-shaped, etc. replacements identical in quality
  to `HmacGenerator`. Use it when you want full structured replacement behaviour
  through the `Strategy` / `StrategyGenerator` path.

- **`AllowlistResult` struct** — `AllowlistMatcher::new` and
  `AllowlistMatcher::new_case_sensitive` now return `AllowlistResult { matcher,
  warnings }` instead of a raw tuple. The struct is `#[must_use]`, so the
  compiler warns when the return value (and therefore `warnings`) is silently
  discarded. `warnings` includes failed `regex:` compilations (the pattern is
  **skipped**) and metacharacter hints.

- **`SecretsLoadResult` struct** — `StreamScanner::from_encrypted_secrets` and
  `StreamScanner::from_plaintext_secrets` now return
  `Result<SecretsLoadResult>` where `SecretsLoadResult` has named fields
  `scanner`, `warnings`, and `allow_patterns`. Previously the return type was
  an anonymous three-tuple. The struct is `#[must_use]` and its fields are
  documented. Re-exported from the crate root.

- **`StoreSnapshot` type** — `MappingStore::snapshot` now returns a
  `StoreSnapshot` newtype instead of a bare `usize`. `MappingStore::iter_since`
  accepts `StoreSnapshot`. This prevents accidentally passing an unrelated
  integer (a count, an index, a capacity) to `iter_since`. Use
  `StoreSnapshot::start()` (or `StoreSnapshot::default()`) to iterate all
  entries, replacing the former `iter_since(0)`.

### Removed

- **`scour-secrets guided` interactive subcommand** — removed. The pattern generation
  it provided is now covered by `scour-secrets template balanced` (exact runtime
  defaults, editable) and `scour-secrets template aggressive`. Removing it eliminates
  the `GuidedOptions` / `GuidedPreset` coupling between the wizard and the scanner
  defaults; `balanced_secret_entries()` in `scanner_builder` is now the single
  source of truth for the built-in detection set.

### Changed

- **`scour-secrets template` preset is now a positional argument** *(breaking)* —
  `scour-secrets template --preset k8s` becomes `scour-secrets template k8s`. Default
  preset changes from `generic` → `balanced`.

- **Project config format: `.scour-secrets.toml` → `.scour-secrets.yaml`** *(breaking)* —
  the per-project config file is now `.scour-secrets.yaml` instead of `.scour-secrets.toml`.
  Rename any existing `.scour-secrets.toml` files. The schema is unchanged; field names
  are identical in both formats.

- **Unified config schema across all three layers** — `~/.config/scour-secrets/settings.yaml`,
  `.scour-secrets.yaml`, and (MCP) `<namespace>/settings.yaml` now share a single
  `SanitizeConfig` struct covering all 30+ behavior flags. Previously, the global
  settings file and project config file had different, partial schemas. Lists
  (`app`, `allow`, `exclude_path`, `include_path`, `context_keywords`) are merged
  additively across layers; scalar flags follow lowest-wins precedence (global →
  project → namespace → per-call CLI flag).

- **LLM client hardened** — `send_prompt` now enforces: SSRF scheme check
  (http/https only, validated before the request is sent); 10 MiB SSE stream cap
  (returns an error if exceeded); ESC byte stripping from decoded content (prevents
  terminal control-sequence injection); bounded error-body read; separate connect
  timeout distinct from the read timeout.

- **`Strategy::replace` takes `category: &Category` as first argument** *(breaking)*
  — strategies can now produce category-aware output. The five built-in strategies
  that do not need category information ignore it via `_category`. Update any
  custom `Strategy` implementations by adding `_category: &Category` as the first
  parameter after `&self`.

- **`MappingStore::clear` now takes `&self`** *(breaking)* — previously
  `clear(&mut self)` was unusable on a shared `Arc<MappingStore>` (the typical
  pattern). The method now uses `DashMap::clear()` internally, which holds
  shard locks one at a time and triggers `ZeroizingString::drop` for every key.
  Callers that bound `let mut store` solely for `clear()` can drop the `mut`.

- **`MappingStore::snapshot` return type is `StoreSnapshot`** *(breaking)* —
  see the new `StoreSnapshot` type above.

- **`MappingStore::iter_since` parameter type is `StoreSnapshot`** *(breaking)*
  — see the new `StoreSnapshot` type above.

- **`AllowlistMatcher::new` / `new_case_sensitive` return `AllowlistResult`**
  *(breaking)* — callers that destructured the old tuple
  `let (matcher, warnings) = …` should change to
  `let AllowlistResult { matcher, warnings, .. } = …` or access fields
  directly (`.matcher`, `.warnings`).

- **`StreamScanner::from_encrypted_secrets` /
  `from_plaintext_secrets` return `Result<SecretsLoadResult>`** *(breaking)* —
  callers that destructured the old tuple `let (scanner, warnings, allow) = …?`
  should change to
  `let SecretsLoadResult { scanner, warnings, allow_patterns } = …?`.

### Internal

- Extracted `xorshift64_step` helper in `strategy.rs` — the three-line
  xorshift64 advance was previously inlined in both `RandomString::replace` and
  `PreserveLength::replace`.

- Extracted `normalize_keywords` and `line_first_hit` helpers in
  `log_context.rs` — the keyword pre-normalisation block and line hit-detection
  logic were previously duplicated between `extract_context` and
  `extract_context_reader`. The `extract_context_reader` loop also computed the
  same hit twice (once for the truncation check, once for the match path);
  these are now a single call.

- `MappingStore::Drop::drop` now delegates to `clear()` instead of duplicating
  the map teardown logic.

- Extracted `strip_terminal_escapes` and `process_sse_stream` from `send_prompt`
  in `llm_client.rs`. 7 new unit tests cover ESC stripping, multi-token SSE
  concatenation, `[DONE]` termination, non-data line skipping, and the stream
  byte-cap error path.

- 4 new `llm_endpoint_tests` integration tests exercise the full
  `--llm-endpoint` path via a self-contained mock HTTP server: correct SSE
  streaming, wrong-token 401 rejection, 500 error propagation, and ESC stripping
  end-to-end.

- 27 entropy unit tests (branch coverage 42 % → 97.7 %), 7 `looks_binary` /
  `merge_entropy_counts` tests, 10 `--quick` integration tests, 10 config /
  hooks env-var tests added in `tests/`.

- 3 new MCP namespace `settings.yaml` integration tests (94 total).

### Changed

- **Zero `unsafe` code across the entire codebase** — replaced the
  platform-specific `stdin_is_pipe` implementations (Unix `fstat`/`S_IFIFO` and
  a hand-rolled `GetFileType` FFI call on Windows) with `std::io::IsTerminal`,
  which is safe and cross-platform. `#![forbid(unsafe_code)]` is now enforced on
  both the library crate and the binary crate.

### Fixed

- **MCP `init` / `build_secrets` preset flag** — `toolInit` and
  `toolBuildSecrets` were invoking `scour-secrets template --preset <name>` (old flag
  syntax removed in v0.13.0); corrected to the positional form
  `scour-secrets template <name>`. The `balanced` and `aggressive` presets are also
  now included in the Zod schema and handler types for both tools.

## [0.12.0] - 2026-06-03

### Added

- **`scour-secrets-mcp` HTTP daemon mode** — `scour-secrets-mcp --http` binds to
  `127.0.0.1:6277` (default) and serves the MCP protocol over HTTP. Pass
  `--http <n>` to use a different port. Requires `SCOUR_SECRETS_MCP_HTTP_TOKEN` to be
  set; the server refuses to start without it.

- **Daemon auto-restart on session close** — the HTTP daemon now exits with code
  `0` when the MCP client sends a `DELETE /mcp` (clean disconnect). Service
  managers configured with `Restart=always` (systemd), `KeepAlive: true`
  (launchd), or `AppExit Default Restart` (NSSM) will automatically restart the
  daemon for the next connection. Systemd unit updated from `Restart=on-failure`
  to `Restart=always` + `RestartSec=1`.

- **Default HTTP port constant** — `DEFAULT_HTTP_PORT = 6277`. Port is validated
  at startup (1–65535, numeric); non-numeric or out-of-range values exit with a
  clear error message.

- **`build_secrets` overwrite guard** — calling `build_secrets` when the output
  file already exists now returns an `"already exists"` error instead of silently
  passing `--overwrite` to the CLI. Pass `"overwrite": true` explicitly to
  replace an existing file. This matches CLI behaviour.

- **NUL byte sanitization in `build_secrets`** — NUL bytes in entry labels and
  patterns are stripped before writing to the YAML output file.

- **87 tests in `mcp/test-direct.ts`** — new tests for default port, invalid
  port values, daemon exit on session close (exit code 0), and reconnect after
  restart.

### Changed

- **`test_pattern` exit-code-1 handling** — replaced a brittle stderr string
  match with a JSON parse attempt; the tool now correctly reports partial matches
  (some values match, some do not) without returning an error.

### Documentation

- Added VS Code (Copilot) coverage: `.copilotignore` soft guardrail, `mcp-remote`
  shim setup for service-user isolation, IDE setup section with on-demand stdio
  and daemon configs.
- Added VS Code row to the tool comparison table with accurate deny-mechanism
  status.
- Corrected service manager restart instructions: systemd `Restart=always` +
  `RestartSec=1`; added explanation of clean vs unclean disconnect behaviour.
- Added Codex daemon client config example.
- Security notes expanded: what the daemon logs, token handling, loopback-only
  binding.

## [0.11.0] - 2026-05-30

### Added

- **38 new unit tests across binary modules** — `sanitize.rs` (10 tests for
  `apply_settings_layer` and `apply_project_config_layer`), `crypto.rs` (7 tests
  for `read_password_file_contents` edge cases including LF/CRLF stripping,
  empty file, oversized file), `dispatch.rs` (5 tests for
  `save_discovered_secrets`), `hooks.rs` (11 tests for `sh_quote` and
  `build_hook_flags`), `config.rs` (5 tests for `find_project_config_from` and
  `load_project_config`).

### Changed

- **Binary split into modules** — `main.rs` has been refactored into dedicated
  modules: `cli_args.rs`, `commands.rs`, `crypto.rs`, `dispatch.rs`, `input.rs`,
  `run_header.rs`, `sanitize.rs`, `scanner_builder.rs`. `run_sanitize` is split
  into `load_run_resources` and `write_run_output` phases via `RunResources` and
  `OutputPhase` structs.

- **Removed hidden `--use-default` flag** — the flag was never documented and
  existed only for internal use by the MCP server. The CLI's existing
  "nothing specified → activate built-in defaults" behaviour is unchanged; no
  caller needs to change anything. The `use_default` parameter has also been
  removed from the MCP `scour-secrets` and `scan` tools for the same reason — omit
  all pattern sources and defaults activate automatically.

- **MCP agent instructions overhauled** — all 10 tool descriptions updated:
  `scour-secrets` leads with "MODIFIES content — run scan first to preview"; `scan`
  leads with "Read-only audit"; `test_pattern` WARNING moved to the first
  sentence; `strip_config_values` clarifies when to use it vs `scour-secrets`; `init`
  and `build_secrets` cross-reference each other; `list_apps`, `list_processors`,
  and `list_templates` each explain when to call them; `namespace` and `seed`
  descriptions include security guidance.

### Fixed

- **`atomic_write_private` for sensitive output files** — decrypted secrets
  written by `scour-secrets decrypt` and discovered secrets written by
  `save_discovered_secrets` now use a mode-0600 temp file (via
  `atomic_write_private`) so plaintext secrets are never world-readable, even
  briefly during the atomic rename window.

- **In-memory secrets wrapped in `Zeroizing<Vec<u8>>`** — secrets file bytes
  read into memory are now zeroed on drop, preventing plaintext secrets from
  lingering in heap memory after use.

- **`save_discovered_secrets` silent data loss fixed** — a stale YAML secrets
  file that failed to parse previously caused the operation to silently succeed
  with an empty pattern list (via `.unwrap_or_default()`). It now propagates the
  parse error instead.

- **MCP `buildSecretsJson` default kind was `"regex"` instead of `"literal"`**
  — when `kind` was omitted from an inline `patterns` entry, the JSON secrets
  file written to the temp dir used `kind: "regex"` while the Zod schema
  advertised `"literal"` as the default. Now consistent: omitting `kind` gives
  literal matching on both sides.

### Added

- **Datadog app bundle** (`datadog`) — covers `datadog.yaml` (API key, app key,
  proxy credentials, SNMP community strings, cluster agent token, Cloud Foundry
  credentials, per-subsystem intake URLs), legacy `datadog.conf` (INI-style,
  colon-delimited), and `conf.d/conf.yaml` integration check configs (host,
  username, password, token, TLS paths, AWS access/secret keys). Streaming
  patterns cover 32-char hex API keys, 40-char hex app keys, `DD_API_KEY=` env
  vars, proxy URLs with embedded credentials, and SNMP community strings.
  `field-name` signals at entropy thresholds 3.0 and 3.5 catch arbitrary
  credential fields in integration configs.

- **docker-compose list-form env var coverage** — a streaming regex in
  `apps/docker-compose/secrets.yaml` now covers the list form of `environment:`
  blocks (`- KEY=value` lines where the key contains `PASSWORD`, `SECRET`,
  `TOKEN`, `API_KEY`, `PRIVATE_KEY`, `ACCESS_KEY`, or `AUTH`). The structured
  profile already handled map-form env vars; this closes the remaining gap.

### Added

- **MCP `include_path` parameter on `scour-secrets` and `scan`** — mirrors the CLI's `--include-path` flag. Pass an array of glob patterns to restrict directory walks to only matching files (e.g. `["**/*.log", "**/*.conf"]`). Has no effect on explicitly named file arguments or archive entries. When both `include_path` and `exclude_path` match a file, exclusion wins.

- **`regex:<pattern>` allowlist syntax documented in MCP schemas** — the `allow` parameter on `scour-secrets` and `scan`, and the `patterns` parameter on `test_allowlist`, now document the `regex:<pattern>` prefix form for full regex matching alongside the existing exact-string and `*`-glob forms. The underlying CLI already supported this; the MCP schema descriptions and docs now surface it.

### Changed

- **Default archive nesting depth raised from 3 to 5** — `DEFAULT_ARCHIVE_DEPTH` in the Rust library and `--max-archive-depth` CLI default now allow five levels of nested archives before returning an error. The MCP server default (`SCOUR_SECRETS_MCP_MAX_ARCHIVE_DEPTH`) is updated to match. Use `--max-archive-depth` / `max_archive_depth` to override per-call; the hard cap remains 10.

### Fixed

- **MCP security hardening** — several issues in the TypeScript MCP server were addressed: `test_allowlist`, `list_apps`, and `init` now respect the `MAX_CONCURRENT = 4` concurrency limit (previously they bypassed it); `build_secrets` and `init` now call `validateFilesPath` on the output path to prevent writing to `.password` files or paths inside `SCOUR_SECRETS_SECRETS_DIR`; `label` and `category` fields in the YAML written by `build_secrets` are now double-quoted to prevent YAML injection; `allow`, `exclude_path`, `app`, `delimiter`, `comment_prefix`, and positional test values now reject inputs that start with `-` to prevent flag injection into the subprocess; `resolveNamespace` now uses the resolved (absolute) secrets dir path for consistent path comparison; the `llm_template` schema description was updated to include `review-security` as a valid built-in template; and the `context_keywords` description was corrected to reference `context_keywords_replace` (was `context_keywords_only`).

- **MCP archive output filename prediction for `.tar.gz` and `.tgz`** — `predictOutputName` in the MCP TypeScript layer now correctly mirrors the CLI's `default_archive_output` logic: archives use `{stem}.sanitized.{full-ext}` (e.g. `archive.sanitized.tar.gz`), not `{stem}-sanitized.{last-ext}` (the plain-file convention). `.tgz` inputs are also normalised to `.tar.gz` in the output name, matching the CLI. The collision-suffix function (`uniquifyName`) was fixed to treat `.tar.gz` as a compound extension so suffixes land before `.tar.gz` rather than before `.gz` alone.

- **`-o -` with file inputs now writes to stdout** — passing `-o -` (the
  conventional stdout sentinel) when the input was a file path caused the
  sanitized output to be written to a literal file named `-` in the working
  directory instead of standard output. Both the buffered structured path
  (`write_output`) and the streaming `AtomicFileWriter` path in
  `process_plain_file` now treat `-` as a stdout sentinel, matching the
  behaviour already supported for stdin.

- **GitHub Actions template expressions over-redacted** — `${{ secrets.X }}`
  expressions (using the `${{…}}` syntax) were being flagged by streaming
  patterns. Added `"${{*}}"` to the `apps/github-actions/secrets.yaml`
  allowlist so template references pass through unredacted.

- **CircleCI pipeline expressions over-redacted** — `<< parameters.X >>`
  expressions were being flagged by streaming patterns. Added `"<<*>>"` to the
  `apps/circleci/secrets.yaml` allowlist.

- **secrets.yaml for every built-in app** — all 21 apps now ship a secrets
  file. Apps with TruffleHog detectors get regex patterns sourced from those
  detectors (AWS AKIA key IDs, GitHub ghp_/gho_/ghs_ tokens, GitLab glpat-
  v2/v3, CircleCI CCIPAT_, Grafana glc_eyJ/glsa_, Heroku HRKU-AA, MongoDB and
  Redis connection URIs, Terraform Cloud .atlasv1. tokens, Splunk observability
  tokens, Docker auth config). Every secrets file includes app-specific
  `kind: allow` entries so the app name, official hostnames, and common local
  dev URIs are never flagged as sensitive.

- **13 new built-in app bundles** — ansible, aws-cli, circleci, elasticsearch,
  github-actions, grafana, heroku, laravel, mongodb, mysql, redis, splunk,
  terraform. Each profile targets only
  app-specific config filenames (e.g. `redis.conf`, `elasticsearch.yml`,
  `*.tfvars`) rather than broad globs. The nginx profile's `*.conf` include was
  tightened to `nginx.conf`, `conf.d/*.conf`, `sites-available/*`, and
  `sites-enabled/*`.

- **`scour-secrets apps edit <name>`** — copies a built-in app bundle's YAML files
  into `~/.config/scour-secrets/apps/<name>/` so they can be customised. The local
  copy automatically takes precedence over the compiled built-in (no extra
  flags needed). Re-running `edit` on an app that already has a user copy
  just prints the file paths. Reverting to the built-in: `scour-secrets apps
  remove <name> --yes`.

- **Built-in override indicator in `scour-secrets apps`** — when a built-in app has
  a user copy, the list now shows `(overridden by user copy)` next to its name.

- **`scour-secrets apps remove` works on built-in overrides** — previously the
  command refused to remove any app whose name matched a built-in; it now
  allows removal of user copies of built-ins and prints "Built-in 'X' is now
  active again." after removal.

- **JWT secret patterns** — `jwt_secret` and `jwt_key` (and camelCase variants
  `jwtSecret`, `jwtKey`) added to plaintext log scanning (`secret_kv` regex in
  `build_guided_entries`) and to the `apps/rails/profile.yaml` and
  `apps/kubernetes/profile.yaml` structured-config profiles.

### Fixed

- **`FakeIp` strategy now preserves input length** — previously `FakeIp::replace`
  always emitted a `10.x.x.x` address (variable length), so a 15-character input
  like `192.168.100.200` could produce a 12-character output. The implementation
  now preserves dots at their original positions and replaces every other character
  with a deterministic decimal digit, guaranteeing `output.len() == original.len()`
  for any input. The `10.0.0.0/8` range guarantee is removed; replacements are
  clearly synthetic (hash-derived digits) rather than routable-range constrained.

- **`--format jsonl` / `--format ndjson` rejected by CLI** — `jsonl` and `ndjson`
  were missing from `VALID_FORMATS` and from `format_to_ext`, so passing
  `--format jsonl` produced an "invalid format" error even though the JSONL
  processor was fully functional. Both are now accepted; MCP `format: "jsonl"`
  works correctly end-to-end.

- **Structured YAML/JSON/TOML output corrupted by key=value patterns** — the
  format-preserving double-pass scanner used by `--profile` included the
  built-in balanced `password_kv` / `secret_kv` patterns which match
  `key: value` as a unit. These patterns caused the YAML key (e.g. `password:`)
  to be lost from the output, producing lines like `  __SANITIZED_xxx__` instead
  of `  password: __SANITIZED_xxx__`. Fixed by adding
  `StreamScanner::for_structured_pass()` which filters out `_kv`-labelled patterns
  from the base scanner so only value-only patterns and profile-discovered literals
  are used in the structured pass.

## [0.8.0] — 2026-05-10

This is the **community preview release**. The public library API and CLI
interface are considered stable and breaking changes will be avoided, but may
occur in minor releases based on community feedback before 1.0.0. See the
[Stability section in README.md](README.md#stability) for the full stability
contract and MSRV policy.

### Added

- **`SecretEntry.values`** — new optional field in secrets files for compact
  multi-value `kind: allow` entries. A single entry with `values: [...]`
  replaces N separate single-pattern entries. Fully backward-compatible via
  `#[serde(default)]`; existing files require no changes.

- **Common allow patterns in built-in presets** — the `balanced`, `aggressive`,
  and guided-entry code paths now automatically allow common non-sensitive
  values: loopback IPs (`127.0.0.1`, `::1`), subnet masks, `localhost`,
  `example.{com,org,net}`, nil UUID, and localhost URLs. Reduces false
  positives out of the box.

- **`processor/limits.rs`** — single source of truth for all processor safety
  limits. Constants (`DEFAULT_ARCHIVE_DEPTH`, `YAML_INPUT_SIZE`, etc.) are now
  imported from one module instead of redefined per-processor.

- **`TreeNode` trait + `walk_tree` generic function** — shared tree-walker used
  by the JSON, YAML, and TOML processors. Eliminates ~150 lines of duplicated
  recursive walk code.

### Changed

- **`--update-secrets` replaced by `--no-structured-handoff`** — saving discovered
  field values to the secrets file is now the default when a profile is active
  (`--profile` or `--app` with a profile). Pass `--no-structured-handoff` to
  suppress the write. The old `--update-secrets` flag is removed.

- **Common allow patterns apply to `--profile` runs** — `--profile` now loads
  the same common non-sensitive allow patterns as `--default` and `--app`,
  so loopback IPs, `localhost`, `example.com`, etc. are not replaced.

- **`AllowlistMatcher` internals** — exact patterns are now stored in a
  `HashSet` for O(1) lookup; only glob patterns walk a `Vec`. No API change.

- **`DEFAULT_MAX_ARCHIVE_DEPTH` renamed to `DEFAULT_ARCHIVE_DEPTH`** —
  re-exported from `processor::limits`. The old name is removed; update any
  direct imports.

- **`format_char_class_lp` extraction in `generator.rs`** — `format_digits_lp`
  and `format_hex_digits_lp` are now thin wrappers around a shared helper.
  Outputs are identical to previous versions.

- **`scan_reader_with_progress` split into helpers** — the main scan loop now
  delegates per-window work to `process_committed_window` and pattern count
  folding to `fold_chunk_counts`. Behavior is unchanged.

### Fixed

- **`zeroize` on drop for `SecretEntry.values`** — the new `values` field is
  included in the `Drop` impl that zeros sensitive memory.

## [0.5.0] — 2026-05-05

### Added

- **`--default` flag** — scan without a secrets file using built-in balanced patterns. Covers API keys (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, HuggingFace, GitLab, SendGrid, npm), JWTs, emails, IPv4/IPv6, UUIDs, MAC addresses, PEM headers, password/secret key=value pairs, and credential URLs. Cannot be combined with `--secrets-file`.

- **`--app <APPS>` flag** — load built-in app bundles (comma-separated). Each bundle provides app-specific secrets patterns and a structured field profile. Additive with `--default`, `--secrets-file`, and `--profile`. Eight built-in bundles: `docker-compose`, `django`, `gitlab`, `kubernetes`, `nginx`, `postgresql`, `rails`, `spring-boot`.

- **`--allow <PATTERN>` flag** — suppress specific values from replacement (repeatable). Matched values pass through unchanged and are not recorded in the mapping store, so they will not propagate to other files in the same run. Supports exact strings and `*` glob wildcards (`*.internal`, `192.168.1.*`).

- **`kind: allow` in secrets files** — allowlist entries can be placed in the secrets file alongside `kind: regex` and `kind: literal` entries. Patterns support the same `*` glob syntax as `--allow`. Entries from the secrets file and `--allow` flags are merged at runtime.

- **`scour-secrets apps` subcommands** — `scour-secrets apps` now dispatches to four sub-subcommands:
  - `scour-secrets apps` (no subcommand) — list built-in and user-defined bundles.
  - `scour-secrets apps add <NAME> [--profile FILE] [--secrets FILE] [--overwrite]` — install a custom app bundle from local YAML files. Both files are validated before anything is written to disk.
  - `scour-secrets apps remove <NAME> [--yes]` — remove a custom app bundle. Built-in bundles are protected. Requires `--yes` to confirm.
  - `scour-secrets apps dir` — print the user apps directory (`$SCOUR_SECRETS_APPS_DIR` or `~/.config/scour-secrets/apps`).

- **`scour-secrets allow-test` subcommand** — test allowlist patterns against values before a full run. Accepts `--allow` patterns, positional values or stdin (one per line), and `--json` for machine-readable output. Shows which pattern matched each value and a summary count.

- **`scour-secrets template` subcommand** — generate a starter secrets template YAML for a preset use case (`generic`, `web`, `k8s`, `database`, `aws`). Output defaults to `secrets.template.<preset>.yaml`.

- **`AllowlistMatcher`** — new public type in `scour_secrets::allowlist`. Compiles `*`-glob and exact patterns; `is_allowed()` and `match_pattern()` methods; atomic seen-counter; regex-character warning on construction.

- **`AllowlistMatcher::match_pattern`** — returns the first matching pattern string (not just a bool), used by `allow-test` to show which pattern matched.

- **`MappingStore::new_with_allowlist`** — constructs a store with an injected `AllowlistMatcher`. Allowlist check happens inside `get_or_insert` before any replacement is recorded, so allowed values never enter the forward map or Phase 2 augmentation.

- **MCP: `use_default`, `app`, `allow` parameters** — `scour-secrets` and `scan` tools now expose all three new flags. `use_default` is validated in TypeScript before spawning the subprocess (conflicts with `secrets_file`, `namespace`, and `patterns` are caught early with a clear error message).

- **MCP: `test_allowlist` tool** — accepts `patterns: string[]` and `values: string[]`, delegates to `scour-secrets allow-test --json`, and returns structured match results.

- **`--strip-delimiter <DELIM>` flag** — sets the delimiter used to split key/value lines when `--strip-values` is active. Default: `=`. Use `--strip-delimiter :` for YAML-style or nginx-style configs. Requires `--strip-values`.

- **`--strip-comment-prefix <PREFIX>` flag** — sets the line prefix that marks a comment when `--strip-values` is active. Default: `#`. Requires `--strip-values`.

- **`--max-context-matches <N>` flag** — caps keyword matches captured per file when `--extract-context` is active. Default: `50`.

- **`--context-case-sensitive` flag** — makes keyword matching case-sensitive when `--extract-context` is active.

- **MCP server (`mcp/`)** — Deno-based MCP server wrapping the `scour-secrets` binary as a subprocess. Ships as a standalone binary for Linux x64, macOS x64, macOS arm64, and Windows. Tools: `scour-secrets`, `scan`, `strip_config_values`, `test_allowlist`, `list_processors`, `list_templates`.

- **MCP: `namespace` parameter** — per-namespace secrets resolution from `$SCOUR_SECRETS_SECRETS_DIR/<namespace>/`.

- **Test suites** — `tests/allow_test_cli_tests.rs` (11 tests), `tests/apps_cli_tests.rs` (19 tests), `tests/strip_values_cli_tests.rs` (6 tests); new unit tests for `AllowlistMatcher::match_pattern`, glob edge cases, `sanitize_zip_entry_name`, `parse_secrets` size cap, and `truncate_label` boundary.

### Fixed

- **Zip entry name traversal** — zip entry names are now sanitised on read: leading `/`, `./`, and `../` segments are stripped. A crafted archive with entry names like `../../etc/passwd` would previously propagate those names into the output zip; they are now normalised to safe relative paths.

- **Secrets file size cap** — `parse_secrets` now rejects inputs larger than 10 MiB before attempting deserialization, preventing OOM from accidentally passing a large binary or log file as a secrets file.

### Changed

- **`scour-secrets apps` is now a subcommand group** — previously `scour-secrets apps` was a bare list command. It now accepts `add`, `remove`, and `dir` sub-subcommands. The bare `scour-secrets apps` (no subcommand) still lists bundles.

- **`validate_app_name` error messages** — now name the specific invalid character rather than giving a generic character-class description.

- **`truncate_label` magic number replaced** — `31`/`32` replaced with `MAX_LABEL_CHARS = 32` constant.

## [0.4.0] — 2026-05-01

### Added

- **`--llm [TEMPLATE]` flag** — formats sanitized output as an LLM-ready prompt and writes it to stdout instead of a file. Built-in templates: `troubleshoot` (default) and `review-config`. A custom template file path can be provided instead. Sanitized content appears in `<content name="...">` blocks followed by a Sanitization Summary and (optionally) a `<notable_events>` section when used with `--extract-context`.

- **Validation: `--llm` conflicts** — `--llm` cannot be combined with `--output` (the prompt is the output) or `--dry-run` (no sanitized content to include). A nonexistent or non-file custom template path is also rejected with a clear error.

- **Unit tests for `--llm` helpers** — `resolve_llm_template`, `format_llm_prompt` (content blocks, sanitization summary, notable events, multiple entries), and `validate_args` for all `--llm` rejection cases.

- **Integration test suite: `tests/llm_tests.rs`** — end-to-end CLI coverage for `--llm`: validation rejections, template selection, prompt structure, secret sanitization in prompt, `--extract-context` integration, and no-write guarantee.

- **Integration test suite: `tests/extract_context_tests.rs`** — CLI coverage for `--extract-context` (report JSON output, `--context-lines` 0 and non-zero), `--context-keywords`, `--context-keywords-only`, and `--strip-values` (file and stdin paths).

- **Unit tests for `--strip-values` helpers** — `strip_values_from_text` preserves keys, comments, blank lines, section headers, and pass-through lines without a delimiter.

- **Unit tests for `validate_args`** — covers `--format`, `--log-format`, `--threads 0`, `--password` without `--encrypted-secrets`, known LLM templates, and all `--llm` rejection paths.

## [0.3.0] — 2026-04-29

### Added

- **`--profile <FILE>` flag** — enables structured field-level sanitization. A profile YAML or JSON file maps file extensions to processors and field rules (e.g. replace `*.password` with `custom:password` category). Profiles are evaluated before the streaming scanner.

- **Two-phase pipeline** — when `--profile` is supplied, profile-matched files are processed first (serially) to populate the replacement store with discovered field values. The streaming scanner used for all other files is then augmented with those values as literal patterns, so the same secret found in `config.yaml` is automatically replaced in `app.log` with the same replacement.

- **Format-preserving structured pass** — the structured processor populates the store with field-value mappings, then the original file bytes are scanned with a per-file scanner containing those literals. Comments, indentation, key ordering, blank lines, and quoting style are all preserved exactly.

- **`include` / `exclude` globs on `FileTypeProfile`** — profiles can now restrict which files they apply to beyond extension matching. `include` narrows to filenames matching at least one glob; `exclude` skips matching filenames. Patterns without a path separator are matched against both the filename and the full path.

- **Discovered-value persistence** (`--deterministic` + `--profile`) — when `--deterministic` is set alongside `--profile`, values discovered by the structured pass are appended to `--secrets-file` after the run (creating the file if absent, deduplicating if it exists). Subsequent runs against unstructured files load those patterns and produce consistent replacements.

- **`--deterministic` without `--encrypted-secrets`** — `--deterministic` can now be used with a plaintext secrets file. The password (via `SCOUR_SECRETS_PASSWORD`, `--password-file`, or `-p`) is used as the HMAC seed only; `--encrypted-secrets` is no longer required when using deterministic mode without an encrypted secrets file.

- **Archive structured discovery pre-pass** — archives in Phase 2 are opened once before the augmented scanner is built. Profile-matched entries inside the archive populate the store, so their values are included in the augmented scanner used for all Phase 2 processing.

- **`ScanPattern::Clone`** — `ScanPattern` now implements `Clone` (via the internally ref-counted `regex::bytes::Regex`).

- **`StreamScanner::with_extra_literals`** — builds an extended copy of a scanner with additional literal patterns appended. Used internally for per-file scanners in the structured pass.

- **`MappingStore::snapshot_keys`** — returns a `HashSet` of all current `(Category, original)` keys. Used to diff the store before and after structured processing to find newly discovered literals.

### Changed

- **Default secrets mode is now plaintext** — `scour-secrets` loads secrets files as
  plaintext JSON / YAML / TOML by default. Encrypted (AES-256-GCM) files now
  require the explicit `--encrypted-secrets` flag.
- **`--unencrypted-secrets` removed** — replaced by the inverse `--encrypted-secrets`
  flag. Scripts using `--unencrypted-secrets` must remove the flag (the default
  behaviour is now plaintext).
- **Password inputs require `--encrypted-secrets`** — supplying `--password`,
  `--password-file`, or the `SCOUR_SECRETS_PASSWORD` environment variable without
  `--encrypted-secrets` is now a hard error with a clear message.
- **`--password` / `-p` is now interactive** — The flag no longer accepts an
  inline value. When provided, it triggers a secure interactive password prompt
  (masked input via `rpassword`, no shell history or process listing exposure).
  Passing `--password VALUE` is rejected by the parser. In non-interactive
  contexts (no TTY) the flag returns a clear error and directs users to
  `--password-file` or `SCOUR_SECRETS_PASSWORD`.

## [0.2.0] — 2026-03-20

### Fixed

- **CLI panic on startup** — `required_unless_present = "command"` referenced
  a clap subcommand field that is not exposed as a named argument in clap 4.5,
  causing a debug assertion panic on every invocation. Replaced with manual
  validation after parsing.
- **`--unencrypted-secrets` still prompted for password** — password resolution
  via `rpassword` was called unconditionally, even when `--unencrypted-secrets`
  was set. Now skips password resolution entirely when the flag is present.
- **`--dry-run --report` showed zero matches for archives** — `ScanStats` from
  per-entry scanning were discarded (`_scan_stats`). Added
  `file_scan_stats: HashMap<String, ScanStats>` to `ArchiveStats` and
  aggregated per-entry scan results so reports reflect actual match counts.

### Changed

- **Consolidated `encrypt-secrets` into `scour-secrets` subcommands.** The separate
  `encrypt-secrets` binary has been removed. Use `scour-secrets encrypt <IN> <OUT>`
  and `scour-secrets decrypt <IN> <OUT>` instead. The default sanitize mode
  (`scour-secrets [INPUT]`) is unchanged and requires no subcommand.
- **Unified password handling** across all modes with a single resolution
  chain: `--password` flag → `--password-file` → `SCOUR_SECRETS_PASSWORD` env var
  → interactive prompt (masked via `rpassword`).
- **Removed `--secrets-key`** — use `--password` instead.
- **`OUTPUT` is now `--output` / `-o`** — Output path changed from a positional
  argument to a named flag. Usage: `scour-secrets data.log -s s.enc -o output.log`.
  Plain files still default to stdout; archives default to
  `<input>.sanitized.<ext>`.
- **Cross-platform support** — `nix` dependency is now Unix-only; password-file
  permission checks degrade gracefully on non-Unix platforms.

### Added

- **CLI smoke tests** — 15 unit tests in `src/bin/sanitize.rs` covering argument
  parsing, subcommand dispatch, short flags, stdin detection, and flag
  combinations. Prevents future clap derive regressions.
- **Stdin support** — When `INPUT` is omitted or set to `-`, `scour-secrets` reads
  from stdin. Enables Unix pipeline usage:
  `export SCOUR_SECRETS_PASSWORD="secret"; grep "error" log.txt | scour-secrets -s secrets.enc`.
  TTY detection prevents hanging when run interactively without input.
- **Short flags** — Common options now have short aliases: `-s` (secrets-file),
  `-p` (password), `-P` (password-file), `-o` (output), `-n` (dry-run),
  `-d` (deterministic), `-r` (report), `-f` (format).
- **`--format` / `-f` flag** — Force input format (`text`, `json`, `yaml`,
  `xml`, `csv`, `key-value`), overriding file-extension detection. Required
  for structured processing when reading from stdin.
- **`scour-secrets encrypt`** subcommand — encrypts a plaintext secrets file with
  AES-256-GCM (replaces the standalone `encrypt-secrets` binary).
- **`scour-secrets decrypt`** subcommand — decrypts an encrypted secrets file back
  to plaintext for editing, with optional format validation.
- **`--password <PW>`** flag — provides the password for the default
  scour-secrets mode. Also available in `encrypt` and `decrypt` subcommands.
- **`--password-file <PATH>`** flag — read the password from a file with
  strict Unix permissions enforcement (`0600` or `0400`). Avoids shell
  history and `/proc/<pid>/environ` exposure.
- **Interactive password prompt** — when no password is provided via flag,
  file, or env var, the user is prompted on the terminal with masked input
  (via the `rpassword` crate).

### Removed

- **`encrypt-secrets` binary** — functionality absorbed into
  `scour-secrets encrypt` and `scour-secrets decrypt`.

## [0.1.0] — 2026-03-19

### Added

- **Streaming scanner** with configurable chunk + overlap for bounded-memory
  processing of arbitrarily large files.
- **18 built-in categories**: email, name, phone, credit card, SSN, IPv4, IPv6,
  MAC address, hostname, container ID, UUID, JWT, auth token, file path,
  Windows SID, URL, AWS ARN, Azure resource ID, plus `custom:<tag>`.
- **Structured processors** for JSON, YAML, XML, CSV, and key-value formats
  that replace matched values while preserving document structure.
- **Archive support** for tar, tar.gz, and zip with entry-by-entry processing
  and metadata preservation (timestamps, permissions, uid/gid).
- **Deterministic mode** using HMAC-SHA256 seeded replacements — same seed and
  same input produce identical output across runs.
- **Random mode** (default) using CSPRNG with per-run dedup cache for
  consistency within a single run.
- **Length-preserving replacements** for all 18 built-in categories.
- **Encrypted secrets file** (AES-256-GCM with PBKDF2, 600 000 iterations) for
  storing detection patterns at rest.
- **Plaintext secrets** support with auto-detection (JSON, YAML, TOML).
- **`encrypt-secrets` CLI** (since removed — see 0.2.0) for converting
  plaintext secrets to encrypted form.
- **`scour-secrets` CLI** with `--dry-run`, `--fail-on-match`, `--report`,
  `--deterministic`, `--strict`, and streaming/structured processing options.
- **Regex hardening**: per-pattern automaton size limits (1 MiB), DFA size
  limits, and pattern count cap (10 000).
- **YAML alias bomb mitigation**: input size cap (64 MiB), node count cap
  (10 000 000), and recursion depth limit (128).
- **Memory bounds** for all structured processors (JSON/XML/CSV: 256 MiB;
  YAML: 64 MiB) with automatic fallback to streaming.
- **Atomic file writes** using temp-file + rename for crash safety.
- **Zeroization** of sensitive data (HMAC keys, secret entries, mapping store)
  on drop via the `zeroize` crate.
- **Graceful shutdown** on SIGINT with atomic flag.
- **JSON report output** (`--report`) with per-file and aggregate statistics.
- **Zero `unsafe` code** — entire crate uses safe Rust only.
- **290+ tests** including unit, integration, property-based (proptest), and
  4 fuzz targets.

[Unreleased]: https://github.com/kayelohbyte/scour-secrets/compare/v0.14.1...HEAD
[0.14.1]: https://github.com/kayelohbyte/scour-secrets/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/kayelohbyte/scour-secrets/compare/v0.13.1...v0.14.0
[0.13.1]: https://github.com/kayelohbyte/scour-secrets/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/kayelohbyte/scour-secrets/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/kayelohbyte/scour-secrets/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/kayelohbyte/scour-secrets/compare/v0.10.0...v0.11.0
[0.8.0]: https://github.com/kayelohbyte/scour-secrets/compare/v0.5.0...v0.8.0
[0.5.0]: https://github.com/kayelohbyte/scour-secrets/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kayelohbyte/scour-secrets/releases/tag/v0.4.0
[0.3.0]: https://github.com/kayelohbyte/scour-secrets/releases/tag/v0.3.0
[0.2.0]: https://github.com/kayelohbyte/scour-secrets/releases/tag/v0.2.0
[0.1.0]: https://github.com/kayelohbyte/scour-secrets/releases/tag/v0.1.0
