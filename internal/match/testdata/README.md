# Matcher fixtures

`kev_sample.json` is a subset of the real CISA Known Exploited Vulnerabilities catalog
(catalogVersion 2026.10.01, recorded 2026-10-02). It holds, for every KEV alias in
`catalog/products/`, the newest real entry that alias matches, plus a few real near-misses that
must not match anything:

- CVE-2025-32756: Fortinet "Multiple Products", but FortiMail/FortiVoice, not FortiOS
- CVE-2026-93616: Check Point "Multiple Products", management servers, not Security Gateway
- CVE-2019-12989: Citrix "SD-WAN and NetScaler", which is SD-WAN, not NetScaler ADC/Gateway
- CVE-2025-20393: Cisco "Multiple Products", email gateways

Entries are copied verbatim, in KEV's order, with `count` updated. When you add a product or
alias, add a real entry for it here (the matcher test fails until you do).

KEV data is published by CISA and dedicated to the public domain under CC0 1.0
(see <https://github.com/cisagov/kev-data>). Linked third-party pages keep their own terms.
