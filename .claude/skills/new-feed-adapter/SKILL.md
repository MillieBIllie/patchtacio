---
name: new-feed-adapter
description: Pattern and checklist for adding or changing a Patchtacio data source under internal/feeds/ (CISA KEV, endoflife.date, NVD, EPSS, OSV, ENISA EUVD, vendor CSAF/RSS/PSIRT feeds). Use this whenever code fetches, parses, caches, or normalizes external vulnerability or end-of-life data, or when a feed's format changed and a parser broke.
---

# Adding a feed adapter

## Interface

Every source lives in its own package under `internal/feeds/<name>` and implements:

```go
// internal/feeds
type Source interface {
    Name() string             // "kev", "eol", "nvd", ...: lowercase, also the cache file name
    Title() string            // shown to users: "CISA KEV catalog"
    StaleAfter() time.Duration
    Fetch(ctx context.Context, c *httpcache.Client, prev httpcache.Validators) (*Fetched, error)
    Parse(raw []byte) (Summary, error) // count, version, publish time; reject anything malformed
}
```

Adapters **fetch and parse only**: no caching, no freshness decisions, no matching, no alert text.
`feeds.Updater` owns the rest: it passes the cached copy's validators to `Fetch`, calls `Parse`,
applies the shared `feeds.Validate(prev, next)`, writes the cache atomically, stores metadata, and
computes Fresh/Stale/Missing. Each adapter also exports a typed parser for consumers
(`kev.ParseCatalog`, `eol.ParseCatalog`), and reads the cached bytes via `Updater.ReadCache`.
Mirrors are the adapter's job: try them inside `Fetch` and return `Via: feeds.ViaMirror`.

## Checklist

1. **Read the source's current docs first** (web fetch / Context7). Note: format, rate limits,
   auth, pagination, license/terms. Put a short summary in the package doc comment.
2. **Record a fixture:** `go run ./tools/record <name>` saves a trimmed real response to
   `testdata/feeds/<name>/`. Keep fixtures small (tens of records) but include edge cases:
   missing fields, odd dates, unicode, very long text.
3. **Write the parser test first** against the fixture, with a golden JSON of the normalized output
   (`-update` flag regenerates goldens).
4. **Implement Fetch** using the shared cache client (ETag / If-Modified-Since, timeout, retry
   with backoff, our User-Agent). Honor documented rate limits; NVD needs `NVD_API_KEY` and
   pacing between requests.
5. **Failure behavior** (handled by the Updater; your job is to return errors, never fake data):
   a network or parse failure keeps the cached copy and the CLI warns (exit `3`). Never return an
   empty "all clear". No cache at all → exit `2`.
   **Validation before replacing the cache:** `Parse` rejects structural problems (not JSON,
   missing required fields, declared count ≠ actual, bad dates, duplicates). A malformed record
   rejects the whole document; silently dropping one could hide an affected product. The shared
   `feeds.Validate` then requires ≥1 record and, after the first fetch, rejects a count drop of
   more than 10% or an older publish time. No hard-coded minimum counts.
   **Staleness** is measured from the last successful contact (304 counts). Each source sets its
   threshold: KEV 48h, endoflife.date 7 days. Also report the feed's own publish date.
6. **Be strict about dates** (store UTC, parse the source's exact format) and **lenient about
   unknown fields** (ignore extras, so upstream additions don't break us).
7. **Register** the source in `defaultApp().sources` in `cmd/patchtacio/app.go` (adapters import
   `internal/feeds`, so the list can't live there), add its unit to `unitFor` in
   `cmd/patchtacio/feeds.go`, its credit to `dataSources` in `version.go`, and a README "Data sources"
   entry. Put the source's license next to its fixture.
8. **Integration test** behind `//go:build integration` that hits the live endpoint once.
9. Run the `security-reviewer` agent: check URL handling, response size limits
   (`io.LimitReader`), and that no secrets reach logs.

## Known quirks

- KEV `vendorProject`/`product` are free text, so matching uses the catalog, never string equality in adapters.
- KEV (CISA) honors `If-Modified-Since` but ignores `If-None-Match` (always 200). Send both,
  and rely on Last-Modified. Check that `count` equals `len(vulnerabilities)`. Fallback after the
  retries run out: the `cisagov/kev-data` GitHub mirror (CC0), validated the same way, never older
  than the cached `catalogVersion`, recorded as `via: mirror`.
- KEV `notes` is one string of URLs separated by " ; " and may contain empty segments.
  `forensicTriage` ("Yes"/"No") is a newer optional field.
- endoflife.date: use **API v1** (`/api/v1/products/full`, one request, ETag revalidation). Send
  the ETag back verbatim (Netlify appends `-ssl`), follow 301s (renamed products), and treat a 404
  as an HTML page. v1 has explicit `isEol`/`eolFrom`, and date fields can be null. The legacy
  `/api/<product>.json` has `eol` as a date **or** a boolean; don't use it.
- License notices travel with fixtures: endoflife.date is MIT, KEV is CC0.
- Vendor feeds change without notice, so keep each vendor adapter isolated and easy to disable.
