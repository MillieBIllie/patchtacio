# Patchtacio

Patchtacio is a **local-only, fully open source (Apache-2.0)** tool that tells small IT teams
(schools, local government, small businesses) when a product they run:

1. appears in the **CISA Known Exploited Vulnerabilities (KEV)** catalog or a vendor advisory, or
2. is approaching or past **end-of-life** (via endoflife.date).

Alerts are plain-language: what's affected, how urgent, and "patch to X or disable Y by <date>".

- **Phase 1 (current focus):** "tick your stack" alerts: CLI + small local web UI + scheduled checks.
- **Phase 2:** developer mode: SBOM/lockfile/image → PURLs → EOL + KEV/OSV findings, output
  SARIF/CycloneDX, shipped as a GitHub Action.
- **Phase 3:** precision and early warning: NVD version ranges, EPSS, vendor CSAF/PSIRT feeds, ENISA EUVD.

Current milestone and task list: **docs/ROADMAP.md**. Read it at the start of each session.
Machine setup, MCP servers, and secrets: **docs/SETUP.md**.

MCP servers available (see `.mcp.json`): `github` (issues/PRs/Actions/code scanning), `context7`
(current library docs; use it before writing code against Syft, cyclonedx-go, go-sarif, GoReleaser),
`gopls` (Go symbol search and diagnostics).

## Tech stack

- Go (latest stable). Module: `github.com/milliebillie/patchtacio`. Binary: `patchtacio`.
- **Pure Go only: `CGO_ENABLED=0` always.** SQLite via `modernc.org/sqlite`.
- CLI: `spf13/cobra`. Config: YAML. Interactive picker: `charmbracelet/huh`.
- Local web UI: `net/http` + `html/template` + `embed`. No JS framework (a vendored htmx file is OK).
- Releases: GoReleaser, cosign signatures, Homebrew tap, Scoop bucket, Docker image.

## Layout

```
cmd/patchtacio/        main + cobra commands (thin: parse flags, call internal packages)
internal/feeds/        one sub-package per data source (kev, eol, nvd, epss, osv, vendor/*)
internal/catalog/      loads + validates catalog/products/*.yaml
internal/inventory/    user's ticked products, CSV import, local host scan, SBOM import
internal/match/        inventory × feed data → findings
internal/store/        SQLite: cache metadata, seen findings, acknowledgements
internal/advice/       findings → plain-language alert text (templates)
internal/notify/       smtp, webhook (slack/teams/discord), ntfy, desktop
internal/output/       table, json, sarif, cyclonedx
internal/schedule/     systemd/cron, Task Scheduler, launchd install/uninstall
internal/ui/           local web UI
catalog/products/      product identity catalog (YAML, licensed CC0)
testdata/              recorded feed fixtures + golden files
```

## Commands

```
go build ./...
go test ./...
go vet ./...
golangci-lint run
go run ./cmd/patchtacio check --config ./testdata/config/example.yaml
go run ./cmd/patchtacio catalog lint
```

## Rules (non-negotiable)

1. **Tests never call live APIs.** Use recorded fixtures in `testdata/`. Live calls only behind
   `//go:build integration`.
2. **Every fetch is polite:** timeouts, retries with backoff, ETag/If-Modified-Since caching,
   User-Agent `patchtacio/<version> (+https://github.com/milliebillie/patchtacio)`, respect NVD rate limits.
3. **If a feed is down, use the cached copy and warn.** Never crash or report "all clear".
4. **Cross-platform:** use `os.UserConfigDir()`, `os.UserCacheDir()`, `filepath.Join`. OS-specific
   code goes in `_linux.go` / `_windows.go` / `_darwin.go` files. Run subprocesses with arg slices,
   never through a shell string. See the `cross-platform` skill.
5. **No secrets in the repo or logs.** Read from env vars (`PATCHTACIO_SMTP_PASSWORD`,
   `NVD_API_KEY`, `PATCHTACIO_WEBHOOK_URL`) or the OS keychain. Redact them in debug output.
6. **Never invent security facts.** No made-up CPEs, fixed versions, or dates. If source data
   doesn't say, the alert says "check the vendor advisory" and links it.
7. **Alert text follows the `alert-writing` skill.** Never tell a user something is safe to ignore.
8. Local web UI binds to `127.0.0.1` only, uses a CSRF token, and never exposes secrets to the page.
9. Wrap errors with `%w`; no `panic` outside `main`. Prefer stdlib; justify every new dependency.
10. Conventional Commits (`feat:`, `fix:`, `docs:` …). Keep PRs small and tied to a ROADMAP task.

## Slash commands

- `/verify-setup`: read-only readiness check (tools, secrets, MCP, skills).
- `/bootstrap [github-username]`: install missing tools and initialize the repo (asks first).
- `/milestone <Mx>`: implement one roadmap milestone, verify it, and stop for review.

## Skills in this repo

- `add-catalog-product`: adding or fixing a product mapping (KEV aliases, CPE, EOL slug).
- `new-feed-adapter`: adding a data source.
- `cross-platform`: OS differences for paths, scheduling, inventory, notifications.
- `alert-writing`: tone and safety rules for any user-facing alert text.
- `output-formats`: SARIF 2.1.0 and CycloneDX output (Phase 2).

Agent: `security-reviewer`. Run it before finishing any change to feeds, notify, ui, or schedule.
