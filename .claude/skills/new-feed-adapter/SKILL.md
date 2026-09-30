---
name: new-feed-adapter
description: Pattern and checklist for adding or changing a Patchtacio data source under internal/feeds/ (CISA KEV, endoflife.date, NVD, EPSS, OSV, ENISA EUVD, vendor CSAF/RSS/PSIRT feeds). Use this whenever code fetches, parses, caches, or normalizes external vulnerability or end-of-life data, or when a feed's format changed and a parser broke.
---

# Adding a feed adapter

## Interface

Every source lives in its own package under `internal/feeds/<name>` and implements:

```go
type Source interface {
    Name() string                                   // "kev", "eol", "nvd", ...
    Fetch(ctx context.Context, c *httpcache.Client) (*Snapshot, error)
}
```

`Snapshot` holds normalized records plus metadata: `FetchedAt`, `SourceURL`, `ETag`, `Stale bool`.
Adapters **parse and normalize only**. No matching logic, no alert text.

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
5. **Failure behavior:** network or parse failure → return the last cached snapshot with
   `Stale: true` and a wrapped error the CLI shows as a warning. Never return an empty "all clear".
6. **Be strict about dates** (store UTC, parse the source's exact format) and **lenient about
   unknown fields** (ignore extras, so upstream additions don't break us).
7. **Register** the source in `internal/feeds/registry.go` and add it to `feeds status`.
8. **Integration test** behind `//go:build integration` that hits the live endpoint once.
9. Run the `security-reviewer` agent: check URL handling, response size limits
   (`io.LimitReader`), and that no secrets reach logs.

## Known quirks

- KEV `vendorProject`/`product` are free text, so matching uses the catalog, never string equality in adapters.
- endoflife.date `eol` fields can be a date string **or** a boolean. Model both.
- Vendor feeds change without notice, so keep each vendor adapter isolated and easy to disable.
