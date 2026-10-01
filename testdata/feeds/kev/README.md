# CISA KEV fixture

`known_exploited_vulnerabilities.json` is a trimmed copy of the real CISA Known Exploited
Vulnerabilities catalog (catalogVersion 2026.09.30), from
<https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>, recorded on
2026-10-01 with `go run ./tools/record kev`. Entries are copied verbatim; only the list was
shortened and `count` updated to match.

KEV data is published by CISA and dedicated to the public domain under CC0 1.0
(see <https://github.com/cisagov/kev-data>). Linked third-party pages keep their own terms.

`golden.json` is Patchtacio's normalized output for the fixture (`go test ./internal/feeds/kev -update`).
