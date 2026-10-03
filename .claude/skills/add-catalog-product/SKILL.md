---
name: add-catalog-product
description: Add, fix, or verify a product entry in Patchtacio's product catalog (catalog/products/*.yaml), which maps one canonical product to its CISA KEV vendor/product aliases, CPE prefixes, endoflife.date slug, and vendor advisory feed. Use this whenever the task involves adding products, improving KEV coverage, fixing a missed or false match, seeding the catalog, or any mention of aliases, CPEs, or endoflife.date slugs, even if the word "catalog" isn't used.
---

# Adding a product to the catalog

The catalog is Patchtacio's most important asset. A wrong mapping means a missed alert (dangerous)
or a false alarm (erodes trust). **Accuracy beats speed. Never guess an identifier.**

## Schema

```yaml
# catalog/products/fortinet-fortios.yaml
id: fortinet-fortios              # vendor-product, lowercase, hyphens; never change once released
display: "Fortinet FortiOS (FortiGate firewalls)"
vendor: Fortinet
category: firewall-vpn            # firewall-vpn | email | os | hypervisor | web-app | file-transfer | remote-access | other
kev_aliases:                      # exact vendorProject/product strings as they appear in KEV
  - { vendor: "Fortinet", product: "FortiOS" }
  - { vendor: "Fortinet", product: "FortiOS and FortiProxy" }
  # A broad pair matches only entries whose name or description names the product (whole word):
  - { vendor: "Fortinet", product: "Multiple Products", mentions: ["FortiOS"] }
cpe_prefixes:
  - "cpe:2.3:o:fortinet:fortios"
eol_slug: fortios                 # endoflife.date product slug, or null if not tracked
advisory:
  kind: rss                       # csaf | rss | api | none
  url: "https://..."              # verified vendor PSIRT URL, or omit
aliases_search: [FortiGate]       # extra words users might type in the picker
notes: ""
verified: 2026-09-30              # date identifiers were last checked against the sources
```

## Procedure

1. **Find every KEV spelling.** Run `patchtacio feeds update`, then use the saved KEV copy
   (`kev.json` in the cache dir, e.g. `~/.cache/patchtacio/cache/kev.json`; set
   `PATCHTACIO_CACHE_DIR` to put it somewhere else):
   ```
   jq -r '.vulnerabilities[] | select(.vendorProject | test("forti"; "i")) | "\(.vendorProject)|\(.product)"' \
     kev.json | sort | uniq -c
   ```
   KEV is free text and inconsistent: include every variant that genuinely refers to this product.
   Matching already ignores case and extra spaces, so `"Synacor| Zimbra..."` needs no extra alias.
   If one KEV product string covers two catalog products ("FortiOS and FortiProxy"), list it on both.
   For `Multiple Products` style pairs, add `mentions:` with the product name exactly as CISA's
   descriptions write it, after reading those descriptions. Never list the bare pair.
   `patchtacio catalog coverage` lists the most common pairs that no product covers yet.
2. **Find the endoflife.date slug** from the cached product list. If none exists, set `eol_slug: null`.
3. **Find the CPE prefix** from NVD CPE data or an existing KEV CVE's NVD record. If you can't
   confirm it from source data, leave the list empty and add `notes: "TODO: verify CPE"`.
   A prefix is `cpe:2.3:<part>:<vendor>:<product>`, and `Product.MatchesCPE` compares those three
   fields exactly, never as a string prefix. So list every name NVD has used for the product,
   including old ones (a renamed vendor or product, separate firmware/model names), checking
   the NVD records of the product's older KEV CVEs too. If you checked only some, keep
   `TODO: verify CPE (only current NVD naming checked)` in the notes.
4. **Find the advisory feed** only from the vendor's official PSIRT pages. Prefer CSAF if offered.
5. **Write the YAML**, one product per file, file name = `id`.
6. **Validate:** `go run ./cmd/patchtacio catalog lint`. With saved feeds, it also fails on an
   unknown `eol_slug` and warns about any alias that matches no real KEV entry.
7. **Test:** copy at least one real KEV entry per new alias, verbatim, into
   `internal/match/testdata/kev_sample.json` and update its `count`.
   `TestEveryAliasMatchesARealEntry` fails until you do. Add a `TestProducts` case for anything
   subtle (shared pairs, `mentions`, near-misses that must not match).
8. **Coverage:** run the coverage report and mention the before/after % in the PR description.

## Rules

- Never fabricate a CPE, slug, or URL. Empty + TODO is always better than a guess.
- Don't merge distinct products to save effort (e.g. Cisco ASA and Cisco IOS XE stay separate).
- Never rename an existing `id`. Add a new one and mark the old one `deprecated: <new-id>`.
- Update `verified:` whenever you re-check identifiers.
