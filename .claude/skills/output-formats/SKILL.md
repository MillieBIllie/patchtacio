---
name: output-formats
description: How Patchtacio produces machine-readable output (SARIF 2.1.0 for GitHub code scanning, CycloneDX annotations/VEX-style data, and JSON) in developer mode and the GitHub Action. Use this whenever working on internal/output/, the --format flag, the GitHub Action, --fail-on thresholds, or when findings don't show up correctly in GitHub's Security tab.
---

# Output formats (Phase 2)

**Before implementing, fetch the current SARIF 2.1.0 spec, GitHub's SARIF upload docs, and the
current CycloneDX spec** (web fetch / Context7). Details and limits change; don't rely on memory.

## SARIF

- One `run`; `tool.driver` = name `patchtacio`, `version`, `informationUri`, and a `rules` array.
- Stable rule IDs: `PATCHTACIO-EOL` (past EOL), `PATCHTACIO-EOL-SOON` (within threshold),
  `PATCHTACIO-KEV` (known exploited), `PATCHTACIO-VULN` (other advisory).
- Level mapping: KEV → `error`; EOL passed → `error`; EOL soon → `warning`; other → `note`/`warning`.
- `locations`: the manifest/lockfile/SBOM path relative to repo root, with a line number if known.
- `partialFingerprints` from PURL + rule ID so GitHub tracks the same finding across runs.
- Message text follows the `alert-writing` skill, shortened.
- Validate every golden file against the official SARIF JSON schema in tests.

## CycloneDX

- When input is a CycloneDX SBOM, output the same BOM enriched with properties such as
  `patchtacio:eol`, `patchtacio:eolDate`, `patchtacio:kev`. Keep the original data intact.
- Use `cyclonedx-go` for reading/writing; validate against the schema for the spec version used.

## Exit codes

`0` no findings at/above `--fail-on` and all data fresh; `1` findings at/above threshold;
`2` tool error or a feed with no usable data; `3` finished but some data was stale.
Findings + stale → `1`; no findings + stale → `3` (never `0`). Constants live in
`cmd/patchtacio/exitcode.go`; commands return `&exitError{code: …}` for outcomes.
Stale data is a warning, not success: print it and include it in the SARIF run properties.
The GitHub Action treats `3` as a warning annotation and passes, unless `fail-on-stale: true`.
