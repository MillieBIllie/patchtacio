# Patchtacio Roadmap

Work top to bottom. Each milestone has a "done when" check. Tick boxes as tasks land.

## Phase 1: "Tick your stack" alerts

### M0: Scaffold
- [ ] `go mod init github.com/milliebillie/patchtacio`, cobra skeleton, `patchtacio version`
- [ ] LICENSE (Apache-2.0), `catalog/LICENSE` (CC0), README stub, CONTRIBUTING, SECURITY.md
- [ ] GitHub Actions CI: matrix ubuntu/windows/macos → build, vet, test, golangci-lint
- [ ] `.goreleaser.yaml` with `goreleaser release --snapshot` working locally

**Done when:** CI is green on all three OSes and a snapshot build produces 6 binaries (amd64/arm64 × 3).

### M1: Data layer
- [ ] KEV feed adapter (JSON) with fixture + tests
- [ ] endoflife.date adapter (product list + per-product cycles) with fixtures + tests
- [ ] SQLite store: feed cache metadata, findings, acknowledgements; migrations
- [ ] `patchtacio feeds update` / `patchtacio feeds status`

**Done when:** `feeds update` works offline from cache and reports staleness honestly.

### M2: Catalog + matching
- [ ] Catalog YAML schema + `patchtacio catalog lint`
- [ ] Seed ~30 products, edge devices first: Fortinet FortiOS/FortiProxy, Ivanti Connect Secure,
      Palo Alto PAN-OS, SonicWall SonicOS/SMA, Citrix NetScaler, Cisco ASA/FTD, Microsoft Exchange,
      Windows Server, VMware ESXi/vCenter, Atlassian Confluence, MOVEit, etc.
- [ ] Coverage report: % of KEV entries from the last 2 years that map to a catalog product
- [ ] Matcher: KEV → catalog product (version optional in v1)
- [ ] `patchtacio init` (interactive picker) and `patchtacio check` (table + JSON output)

**Done when:** a fresh user can tick products and see relevant KEV findings in under 2 minutes.

### M3: Alerts
- [ ] Findings dedupe: alert once, remind as `dueDate` approaches
- [ ] Advice templates (see `alert-writing` skill) with golden-file tests
- [ ] Notifiers: SMTP, webhook (Slack/Teams/Discord), ntfy, desktop notification
- [ ] `patchtacio ack <id>`; daily/weekly digest option
- [ ] `patchtacio test-alert` to verify notification setup

**Done when:** a new KEV entry for a ticked product produces exactly one clear alert.

### M4: Scheduling
- [ ] `patchtacio watch --install / --uninstall / --status`
- [ ] Linux: systemd user timer (fallback: cron). Windows: Task Scheduler. macOS: launchd agent.
- [ ] Log file in cache dir with rotation

**Done when:** install → reboot → scheduled check runs on each OS (manual test checklist in docs/).

### M5: Local web UI
- [ ] `patchtacio ui` opens the browser on 127.0.0.1:<random port>
- [ ] Product picker with search, notification setup + test button, findings list with ack

**Done when:** a non-technical tester can set everything up without touching the CLI.

### M6: Release + portfolio polish
- [ ] GoReleaser: checksums, cosign signing, build provenance, SBOM for our own release
- [ ] Homebrew tap, Scoop bucket, Docker image, `.deb`/`.rpm`
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
