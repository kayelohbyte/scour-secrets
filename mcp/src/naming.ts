/**
 * Output filename prediction and uniquification, mirroring the Rust CLI's
 * default_archive_output / default_plain_output / uniquify_output_path logic.
 */

/**
 * Replicates the CLI's output naming logic:
 *   - Archives (.zip, .tar, .tar.gz, .tgz, standalone .gz): default_archive_output →
 *     "{stem}.sanitized.{full-ext}" where stem has any trailing ".tar" stripped.
 *     .tgz is normalised to .tar.gz in the output, matching the CLI.
 *   - Plain files: default_plain_output →
 *     "{stem}-sanitized.{ext}" splitting at the last dot only.
 */
export function predictOutputName(inputPath: string): string {
  const base = inputPath.replace(/\\/g, "/").split("/").pop() ?? "output";
  const lower = base.toLowerCase();
  if (lower.endsWith(".tar.gz")) {
    return `${base.slice(0, base.length - ".tar.gz".length)}.sanitized.tar.gz`;
  }
  if (lower.endsWith(".tgz")) {
    return `${base.slice(0, base.length - ".tgz".length)}.sanitized.tar.gz`;
  }
  if (lower.endsWith(".tar")) {
    return `${base.slice(0, base.length - ".tar".length)}.sanitized.tar`;
  }
  if (lower.endsWith(".zip")) {
    return `${base.slice(0, base.length - ".zip".length)}.sanitized.zip`;
  }
  if (lower.endsWith(".gz") && base.length > ".gz".length) {
    // Standalone single-file gzip: "config.json.gz" → "config.json.sanitized.gz".
    return `${base.slice(0, base.length - ".gz".length)}.sanitized.gz`;
  }
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return `${base}-sanitized`;
  return `${base.slice(0, dot)}-sanitized.${base.slice(dot + 1)}`;
}

/**
 * Appends _2, _3 … suffixes until the name is not in `used`, mirroring the
 * CLI's uniquify_output_path. Handles .tar.gz as a compound extension so the
 * suffix lands before ".tar.gz" rather than before ".gz" alone.
 */
export function uniquifyName(name: string, used: Set<string>): string {
  if (!used.has(name)) { used.add(name); return name; }
  const lower = name.toLowerCase();
  let stem: string;
  let ext: string;
  if (lower.endsWith(".tar.gz")) {
    stem = name.slice(0, name.length - ".tar.gz".length);
    ext = ".tar.gz";
  } else {
    const dot = name.lastIndexOf(".");
    stem = dot > 0 ? name.slice(0, dot) : name;
    ext = dot > 0 ? name.slice(dot) : "";
  }
  for (let i = 2; ; i++) {
    const candidate = `${stem}_${i}${ext}`;
    if (!used.has(candidate)) { used.add(candidate); return candidate; }
  }
}
