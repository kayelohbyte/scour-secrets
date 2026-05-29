# Defensive Limits & Streaming Scalability

## Streaming Architecture

### Chunking Model

The streaming scanner never holds the entire file in memory. It reads fixed-size **chunks** (default 1 MiB) with an automatically derived **overlap** window (default 4 KiB). The overlap ensures that a sensitive value straddling a chunk boundary is still detected.

The CLI derives overlap from the `--chunk-size` value: `overlap = chunk_size / 4`, clamped to the range `[1, 4096]` bytes. The library API allows direct configuration via `ScanConfig::new(chunk_size, overlap_size)`.

```
Chunk N:     [===========================|overlap|]
Chunk N+1:                         [overlap|===========================|overlap|]
```

After scanning a chunk, only the overlap window is retained; the rest is flushed to the writer. Peak memory per file ≈ `chunk_size + overlap_size`.

### Archive Streaming

Archives (tar, tar.gz, zip) are processed entry-by-entry:

1. Each entry is matched against file-type profiles for structured processing.
2. If a structured processor matches and the entry is within `STRUCTURED_ENTRY_SIZE` (256 MiB), the entry is parsed and field values are replaced.
3. Otherwise the entry is piped through the streaming scanner in chunks — no full-entry buffering.
4. The archive is rebuilt with sanitized content and preserved metadata (timestamps, permissions, uid/gid).

**Parallel processing.** Entries are sanitized concurrently via rayon when the archive's total uncompressed file data fits within the parallel cap (256 MiB) and the entry count meets the minimum threshold (default: 4). The rebuilt archive is always written in the original entry order — output is fully deterministic regardless of thread count.

For archives exceeding the parallel cap, entries are processed sequentially. Tar archives use a speculative-buffer strategy: entries are buffered until the cap is reached, at which point already-buffered entries are processed from memory and the remainder stream directly without additional buffering. This bounds peak RAM to approximately `cap + one entry` regardless of total archive size.

Per-entry parallelism is suppressed when multiple archive files are already being processed in parallel at the file level, to avoid oversubscribing the rayon thread pool.

### Structured File Size Caps

Files exceeding the structured processor's size limit are automatically demoted to the streaming scanner. This ensures bounded memory regardless of individual file size.

The 256 MiB cap is intentionally generous relative to real-world config files. No production configuration file (GitLab `gitlab.rb`, Kubernetes manifests, Terraform state, `docker-compose.yml`, `.env` files) approaches this size. Files that do exceed the limit in practice are typically large JSON log dumps, database exports, or ML datasets — none of which have the named secret fields that structured processing is designed for. The streaming scanner is the correct tool for those inputs: it catches API keys, JWTs, emails, and other typed secrets by pattern regardless of document structure.

### Pattern Count Limits

The `StreamScanner` rejects pattern sets exceeding 10 000 patterns at construction time. This bounds matcher automaton memory: regex patterns contribute to `RegexSet` memory, and literal patterns contribute to the Aho-Corasick automaton.

### Memory Characteristics for Large Inputs

For 20–100 GB plain-text files, the streaming scanner maintains constant memory usage: `chunk_size + overlap_size + mapping store`. With the default 1 MiB chunk and 4 KiB overlap, base memory per active scan is ~1 MiB. The mapping store grows proportionally to the number of **unique** matched values (not file size).

---

## Defensive Limits

| Limit | Default Value | Configurable | Notes |
|-------|---------------|--------------|-------|
| Max structured file size | 256 MiB | `--max-structured-size` | Applies to standalone JSON, YAML, XML, CSV files and archive entries routed to structured processors. Oversized inputs fall back to the streaming scanner. Real config files never approach this limit; the fallback is only relevant for large data dumps and log files. |
| Max pattern count | 10 000 | Compile-time (`DEFAULT_MAX_PATTERNS`) | Bounds matcher automaton memory (`RegexSet` + Aho-Corasick). |
| Max mapping store entries | 10 000 000 | `--max-mappings` | Prevents unbounded heap growth. |
| Regex automaton size | 1 MiB | Compile-time (`REGEX_SIZE_LIMIT`) | Per-pattern limit. |
| Regex DFA cache size | 1 MiB | Compile-time (`REGEX_DFA_SIZE_LIMIT`) | Per-pattern limit. |
| YAML input size | 64 MiB | Compile-time (`MAX_YAML_INPUT_SIZE`) | Pre-parse rejection. |
| YAML node count | 10 000 000 | Compile-time (`MAX_YAML_NODE_COUNT`) | Post-expansion alias bomb defence. |
| YAML recursion depth | 128 | Compile-time (`MAX_YAML_DEPTH`) | Stack overflow prevention. |
| JSON input size | 256 MiB | Compile-time (`MAX_JSON_INPUT_SIZE`) | Pre-parse rejection. |
| JSON recursion depth | 128 | Compile-time (`MAX_JSON_DEPTH`) | Stack overflow prevention. |
| XML input size | 256 MiB | Compile-time (`MAX_XML_INPUT_SIZE`) | Pre-parse rejection. |
| XML element depth | 256 | Compile-time (`MAX_XML_DEPTH`) | Stack overflow prevention. |
| CSV input size | 256 MiB | Compile-time (`MAX_CSV_INPUT_SIZE`) | Pre-parse rejection. |
| Key-value input size | 256 MiB | Compile-time (`MAX_KV_INPUT_SIZE`) | Pre-parse rejection. |
| Max archive nesting depth | 5 | `--max-archive-depth` (max 10) | Prevents archive bombs and unbounded recursion. Each nesting level may buffer up to 256 MiB. |
