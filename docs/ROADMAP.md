# Patchtacio Roadmap

Work top to bottom. Each milestone has a "done when" check. Tick boxes as tasks land.

## Phase 1: "Tick your stack" alerts

### M0: Scaffold
- [x] `go mod init github.com/milliebillie/patchtacio`, cobra skeleton, `patchtacio version`
- [x] LICENSE (Apache-2.0), `catalog/LICENSE` (CC0), README stub, CONTRIBUTING, SECURITY.md
- [x] GitHub Actions CI: matrix ubuntu/windows/macos → build, vet, test, golangci-lint
- [x] `.goreleaser.yaml` with `goreleaser release --snapshot` working locally

**Done when:** CI is green on all three OSes and a snapshot build produces 6 binaries (amd64/arm64 × 3).

### M1: Data layer
Design decisions: [docs/decisions/0001-m1-data-layer.md](decisions/0001-m1-data-layer.md).
- [x] `internal/paths`: config / cache / data dirs per OS, `PATCHTACIO_*_DIR` overrides
- [x] Logging: slog to stderr, `-v`/`-vv`/`--quiet`, secret + URL redaction
- [x] `httpcache` client: timeouts, retries + `Retry-After`, conditional requests, size cap, atomic cache writes
- [x] KEV feed adapter (JSON) with fixture + tests; GitHub mirror fallback
- [x] endoflife.date adapter (API v1, `/products/full`) with fixtures + tests
- [x] SQLite store: feed cache metadata + update lock; embedded migrations (`user_version`)
- [x] `patchtacio feeds update [--offline]` / `patchtacio feeds status` (exit 0 / 2 / 3)
- [x] Weekly scheduled integration-test workflow (feed format drift); data-source attribution in README + fixtures

**Done when:** `feeds update` works offline from cache and reports staleness honestly.

### M2: Catalog + matching
- [x] Catalog YAML schema + `patchtacio catalog lint`
- [x] Seed ~30 products, edge devices first: Fortinet FortiOS/FortiProxy, Ivanti Connect Secure,
      Palo Alto PAN-OS, SonicWall SonicOS/SMA, Citrix NetScaler, Cisco ASA/FTD, Microsoft Exchange,
      Windows Server, VMware ESXi/vCenter, Atlassian Confluence, MOVEit, etc.
- [x] Coverage report: % of KEV entries from the last 2 years that map to a catalog product
      (`catalog coverage`; seed catalog vs KEV 2026.10.01: 169 of 547, 30.9%; 43 products vs KEV 2026.10.02: 194 of 549, 35.3%)
- [x] Matcher: KEV → catalog product (version optional in v1)
- [x] `patchtacio init` (interactive picker) and `patchtacio check` (table + JSON output)

**Done when:** a fresh user can tick products and see relevant KEV findings in under 2 minutes.

### M3: Alerts
Design decisions: [docs/decisions/0002-m3-alerts.md](decisions/0002-m3-alerts.md). Setup: [docs/ALERTS.md](ALERTS.md).
- [x] Store migration: findings + acknowledgements tables (finding identity designed here)
- [x] Findings dedupe: alert once, remind as `dueDate` approaches
- [x] Advice templates (see `alert-writing` skill) with golden-file tests
- [x] Notifiers: SMTP, webhook (Slack/Teams/Discord), ntfy, desktop notification
- [x] `patchtacio ack <id>`; daily/weekly digest option
- [x] `patchtacio test-alert` to verify notification setup
- [x] End-of-life alerts: map the user's version to an endoflife.date release cycle, alert before
      and after EOL ([decision 0003](decisions/0003-eol-alerts.md))

**Done when:** a new KEV entry for a ticked product produces exactly one clear alert.

### M4: Scheduling
Design decisions: [docs/decisions/0004-m4-scheduling.md](decisions/0004-m4-scheduling.md). Setup: [docs/SCHEDULING.md](SCHEDULING.md).
- [x] `patchtacio watch --install / --uninstall / --status` (and `--run-now`)
- [x] Linux: systemd user timer (fallback: cron). Windows: Task Scheduler (windowless `patchtaciow.exe`). macOS: launchd agent.
- [x] Log file in cache dir with rotation

**Done when:** install → reboot → scheduled check runs on each OS (manual test checklist in docs/).
Checklist and results: [docs/manual-testing.md](manual-testing.md). Verified on Windows 11 (restart, shutdown and sleep,
with missed-run catch-up), on Linux with systemd and cron (WSL, including restart and catch-up), and on macOS in CI
(launchd installs and runs the check on schedule). Still to do on a real Mac: restart and missed runs.

### M5: Local web UI
- [ ] `patchtacio ui` opens the browser on 127.0.0.1:<random port>
- [ ] Product picker with search, notification setup + test button, findings list with ack

**Done when:** a non-technical tester can set everything up without touching the CLI.

### M6: Release + portfolio polish
- [ ] GoReleaser: checksums, cosign signing, build provenance, SBOM for our own release
- [ ] Homebrew tap, Scoop bucket, Docker image, `.deb`/`.rpm`
      (already built, not published: the Scoop manifest with a Start-menu shortcut that opens `patchtacio ui`,
      and `.deb`/`.rpm` with a menu entry for it. Still to do: publish them; a macOS way to open the UI without
      a terminal, since GoReleaser's app bundles need Pro: a Homebrew cask with a small `.app`, or document
      `patchtacio ui`)
- [ ] README with demo GIF (recorded with `vhs`), install instructions per OS, architecture diagram
- [ ] Docs: "How matching works", "Adding a product to the catalog"

**Done when:** v0.1.0 is tagged and installable on all three OSes in one command.

## Phase 2: Developer mode
- [ ] M7: SBOM import (CycloneDX/SPDX), then lockfiles/images via Syft as a library
- [ ] M8: PURL → endoflife.date identifier matching; OSV + KEV cross-check
- [ ] M9: `--format sarif|cyclonedx`, `--fail-on` threshold, GitHub Action (+ Marketplace listing)

## Phase 3: Precision and early warning
- [ ] NVD API 2.0 version ranges (uses NVD_API_KEY) → filter by user's version
- [ ] EPSS scores for prioritization
- [ ] Vendor advisory adapters (CSAF 2.0 first, then RSS/APIs): Fortinet, Palo Alto, Cisco, Microsoft
- [ ] ENISA EUVD adapter; CRA-friendly report export
