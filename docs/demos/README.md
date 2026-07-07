# Demo recordings

Scripted, reproducible terminal demos of `scour-secrets`. Each flow is captured
in two formats:

- **VHS GIFs** (`out/*.gif`) — embed inline in Markdown / GitHub READMEs.
- **asciinema casts** (`out/*.cast`) — selectable, copy-paste-able commands;
  embeddable via the asciinema player or shareable as a link.

Both are generated from the same scripts, so nothing is hand-typed and every
re-render is identical. All sample inputs contain **only clearly-fake secrets**
(AWS's published example access key, the Stripe documentation key,
`example.com` / RFC-1918 / RFC-5737 addresses) — no real credentials.

| Flow | What it shows |
|------|---------------|
| `01-quickstart`    | Zero-config scan of a log: before / after, all secret types redacted |
| `02-dryrun-ci`     | `--dry-run`, NDJSON `--findings` piped to `jq`, and the `--fail-on-match` CI gate |
| `03-app-bundles`   | `scour-secrets apps` + `--app nginx` zero-config field sanitization with layout preserved |
| `04-pipe-structured` | stdin piping and `--profile` structured field rules |

## Regenerate

```bash
cargo build --release          # produce target/release/sanitize
docs/demos/render.sh           # rewrites every out/*.gif and out/*.cast
```

Override the binary under test with `SCOUR_SECRETS_BIN=/path/to/sanitize docs/demos/render.sh`.

Requires `vhs`, `asciinema`, `ffmpeg`, `ttyd`, and `jq` on `PATH`
(`brew install vhs asciinema ffmpeg ttyd jq`).

## Layout

```
docs/demos/
├── lib.sh              # shared: hermetic work dir + sample inputs
├── render.sh           # regenerate everything
├── tapes/*.tape        # VHS scripts → GIFs
├── drivers/*.sh        # asciinema drivers (print-then-run) → casts
└── out/                # generated GIFs and casts
```

`lib.sh` redirects `HOME` into a throwaway work dir, so recordings never show
the operator's real home path or depend on a personal
`~/.config/sanitize/secrets.yaml`.

## Embedding

**GIF (renders inline on GitHub):**

```markdown
![Zero-config scan](docs/demos/out/01-quickstart.gif)
```

**asciinema cast** — upload with `asciinema upload out/01-quickstart.cast` and
link the resulting page, or self-host with
[asciinema-player](https://docs.asciinema.org/manual/player/):

```html
<script src="asciinema-player.min.js"></script>
<div id="player"></div>
<script>
  AsciinemaPlayer.create('01-quickstart.cast', document.getElementById('player'));
</script>
```
