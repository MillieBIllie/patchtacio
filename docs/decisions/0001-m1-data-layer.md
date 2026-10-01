# 0001: Data layer, exit codes, and paths (pre-M1)

- **Status:** accepted
- **Date:** 2026-10-01
- **Scope:** M1 (data layer), with contracts that later milestones inherit

The rules below are also written into the skills (`cross-platform`, `new-feed-adapter`,
`output-formats`) and `docs/ROADMAP.md`. This record keeps the reasons, so nobody "simplifies"
a decision without knowing why it was made.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Finished; nothing at or above the threshold; all data fresh |
| 1 | Findings at or above the `--fail-on` threshold |
| 2 | Tool error, or a feed has no usable data at all |
| 3 | Finished, but at least one feed was served stale from cache |

- Findings plus stale data exits 1, because the findings are actionable; the stale warning is
  still printed. No findings plus stale data exits 3, never 0, because "nothing found" in old data
  is not an all clear (CLAUDE.md rule 3).
- `feeds update` exits 0 when every feed is fresh, 3 when any feed was stale, and 2 when one has
  no data.
- The GitHub Action (M9) treats 3 as a warning annotation and passes by default, with opt-in
  `fail-on-stale: true`. Otherwise CISA blocking runner IPs would fail unrelated PRs.

## Storage

- **Raw feed responses on disk are the source of truth.** SQLite holds only metadata: ETag,
  Last-Modified, fetched_at, last contact, sha256, record count, and which source served it.
  Raw files can be inspected, diffed, and re-parsed when a parser changes, with no migration.
- **M1 ships the migration mechanism and the feed-metadata table only.** Migrations are embedded
  `.sql` files tracked by `PRAGMA user_version`, with no library. Findings and acknowledgements
  arrive as a later migration in M3, once finding identity and dedupe are designed. A schema
  guessed now would need migrating anyway.
- If metadata says a cache file exists but the file is missing or its sha256 differs, treat that
  feed as having no cache.

## Directories

| Purpose | Linux | Windows | macOS |
|---|---|---|---|
| Config (YAML) | `~/.config/patchtacio` | `%AppData%\patchtacio` | `~/Library/Application Support/patchtacio` |
| Cache (raw feeds, safe to delete) | `~/.cache/patchtacio/cache` | `%LocalAppData%\patchtacio\cache` | `~/Library/Caches/patchtacio/cache` |
| Data (SQLite) | `$XDG_DATA_HOME/patchtacio` (`~/.local/share/patchtacio`) | `%LocalAppData%\patchtacio\data` | `~/Library/Application Support/patchtacio` |

- State must not live in the cache dir: users and OS cleanup tools delete caches, and acks would
  be lost.
- SQLite must not live in Windows **Roaming** `%AppData%` (where `os.UserConfigDir` points).
  Roaming profiles, common in schools and councils, sync files at logoff and corrupt a live
  database and its WAL.
- Go has no `UserDataDir`, so `internal/paths` provides one, with per-OS files.
- Overrides: `PATCHTACIO_CONFIG_DIR`, `PATCHTACIO_CACHE_DIR`, `PATCHTACIO_DATA_DIR` (Docker, tests,
  portable installs). There are no per-directory flags. `--config <file>` and the YAML loader
  arrive in M2 with `init`; M1 has nothing to configure.

## Concurrency

A scheduled check and a manual run can overlap.

- SQLite runs in WAL mode with `busy_timeout`.
- Cache files are written to a temp file in the same directory and then renamed into place, with
  a short retry on Windows, where a rename over an open file fails.
- An update lock is held as a SQLite row taken with `BEGIN IMMEDIATE`, with a heartbeat. A lock
  older than about 5 minutes is treated as abandoned. This needs no new dependency and no per-OS
  code. A second updater waits briefly, then uses the result.

## Freshness and validation

- Staleness is measured from the **last successful contact**, where a 304 counts. KEV becomes
  stale after 48h, endoflife.date after 7 days (hard-coded per source in M1). The feed's own
  publish date is shown alongside, e.g. "checked 2h ago, catalog published 3 days ago".
- `--offline` skips the network and reports staleness honestly. Falling back to the cache when
  the network fails is the default anyway.
- **Validate before replacing the cache** (as built in M1: each adapter's `Parse` does the
  structural checks, and a shared `feeds.Validate(prev, next)` does the rest):
  - On first fetch, only structural checks: the body parses, required top-level fields are
    present, at least one record, and for KEV, `count` equals the number of records. No
    hard-coded minimum counts, which would quietly go out of date.
  - After that, the same checks plus: the record count must not drop by more than 10%.
    A user who has confirmed a real reduction can override this one check, once, with
    `feeds update --accept-shrink <source>`; the warning suggests it only for this case.
    It approves only the reduction the user was shown (a download within 10% of the rejected
    record count), never "anything smaller". It is never persisted, never read from env or
    config, and scheduled runs (M4) must never pass it.
  - On failure, keep the old cache, mark the feed stale, warn, and exit 3. A truncated body or
    an HTML error page must never become an empty "all clear".

## Feeds

### CISA KEV

Checked 2026-10-01:
- CISA honors `If-Modified-Since` (304) but **ignores `If-None-Match`** (always 200). Send both,
  and rely on Last-Modified.
- The file is about 1.7 MB, gzip about 200 KB.
- The data is CC0.
- **Fallback:** `cisagov/kev-data` on GitHub (official, CC0, synced within minutes), tried only
  after the primary has used up its retries.
  - The mirror copy passes the same validation.
  - Never accept an older `catalogVersion` than the cached one.
  - Record `via: mirror` and show it in `feeds status`.
  - Choosing the mirror as primary is not supported for now; it could be added as a config key
    if someone needs it.

### endoflife.date

- Use **API v1** (`/api/v1/...`, schema_version 1.2.1). It has explicit `isEol`/`eolFrom`,
  `isEoas`, `isEoes`, `isMaintained`, and `identifiers` (purl/cpe) for Phase 2. The legacy API's
  `eol: bool | date` is exactly the ambiguity rule 6 warns about.
- Fetch **`/api/v1/products/full`** in one request, revalidated by ETag. Most runs get a 304, so
  this is lighter on their servers than about 30 per-product requests, and M1 doesn't wait for
  the M2 catalog.
  - The OpenAPI spec prefers `/products` where possible, so we ask the maintainers whether a
    daily bulk fetch is OK, and switch to per-product fetching if they object.
  - Send the ETag back exactly as received (Netlify appends `-ssl`).
  - Follow 301s, because products get renamed.
  - A 404 is an HTML page, not JSON.
- The data is MIT licensed. Fixtures derived from it carry the MIT notice.

### Shared `httpcache.Client` defaults

- 30s per attempt, 2 minutes overall per source.
- 3 retries with exponential backoff and jitter on network errors, 5xx and 429, honoring
  `Retry-After` capped at 60s. Other 4xx are never retried.
- HTTPS-only redirects, at most 5. A 32 MB body cap per source (`io.LimitReader`).
- Gzip is handled by Go's transport. Send both conditional headers when known; a 304 counts as
  success.
- User-Agent from `version.UserAgent()`. Every behavior is covered by `httptest` tests.

### Drift detection

A weekly scheduled workflow, plus manual trigger, on ubuntu only, runs
`go test -tags integration ./internal/feeds/...`. It doesn't block PRs; a failure opens or updates
an issue. Fixtures are trimmed and tests never go live, so this is how a format change is noticed.

### Attribution

- `testdata/feeds/eol/LICENSE` holds endoflife.date's MIT text; `testdata/feeds/kev/README` notes
  CC0 and the source.
- The README gets a "Data sources" section. Credits also appear in `version --json` and, later,
  the UI.

## Logging and output

- **stdout** carries command output only (tables, JSON), so it can be piped.
- **stderr** carries `log/slog` diagnostics (text handler). Levels: warn by default, `-v` info,
  `-vv` debug, `--quiet` errors only.
- `-v` currently belongs to cobra's automatic `--version` shorthand. Defining the verbose flag in
  M1 takes it over; `--version` stays long-form.
- Redaction:
  - A `secret` type implementing `slog.LogValuer` always renders `[REDACTED]`.
  - A `ReplaceAttr` strips URL userinfo and query strings (webhook URLs carry tokens).
- Stale-data warnings always print, even with `--quiet`, because they change what the output means.
- The M4 log file uses the same redacted records, so redaction is written once. Its format (text
  or JSON) is decided in M4.

## Repository process

- Rebase-merge only, so each step commit is kept for GoReleaser's changelog.
- `main` is protected:
  - A PR and these checks are required: the three `test (…)` jobs and `goreleaser snapshot`.
  - No force-push or deletion. No required reviews while there is a single maintainer.
- Branches are deleted on merge.
- Personal skills-manager files (`.agents/`, `skills-lock.json`, third-party skills under
  `.claude/skills/`) stay out of the repo through `.git/info/exclude`.
