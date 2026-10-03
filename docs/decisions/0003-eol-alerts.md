# 0003: End-of-life alerts

- **Status:** accepted
- **Date:** 2026-10-03
- **Scope:** end-of-life findings in `check`, alerts and `ack` (split out of M3, see 0002)

endoflife.date says when each release of a product stops getting security updates. Patchtacio
turns that into findings and alerts, under these rules.

## Matching a version to a release

- Only products with a catalog `eol_slug` and a `version:` in the user's configuration are looked
  up. Without a version nothing is guessed: `check` lists the product as "no version" and says to
  add one.
- A version matches a release (endoflife.date "cycle") only:
  - exactly, ignoring case, a leading `v`, and spaces written as hyphens (`2012 R2` is `2012-r2`);
  - or as a dotted prefix: `7.2.8` is release `7.2`, never `7.20`. The longest match wins.
- No match is reported as "no matching release", listing the valid names. Fuzzy matching was
  rejected: a wrong cycle could show a product as supported when it is not (CLAUDE.md rule 6).
- endoflife.date is fetched only when there is something to look up, so KEV-only users see no
  extra traffic.

## When something is a finding

- **Ended:** endoflife.date says `isEol`, or the end-of-life date has passed (a lagging flag is not
  trusted over the date).
- **Ending:** the date is 90 days away or nearer.
- Anything else is `supported` (until a stated date) or `no-end-date` (still maintained, no date
  announced). A release endoflife.date marks as not maintained, with no date, counts as ended.
- Two releases that match a version equally well (duplicate names) give "no match", never a guess.
- **No answer is never silent.** These states say why there is none:
  - `no-version`: the user gave none;
  - `no-match`: the valid names are listed;
  - `no-data`: endoflife.date data could not be read;
  - `not-listed`: the data no longer has the product, for example after a rename.
  For `not-listed`, `check` warns and exits 3, and `--notify` sends a daily "end of life cannot be
  checked" notice. Unreadable or stale data always sends the "could not update" notice. The JSON
  report carries `eolFeed` and `eolStale` next to the KEV `feed` and `stale`.
- A bare ID given to `ack` is a CVE: it never acknowledges end-of-life findings, whose release
  names (`2019`) repeat across products. Those take their full `eol/...` ID.
- Feed links in alerts must be `https`.
- Spelling like "7.0 U3" is not matched to release `7.0`: allowing "-" as a separator would also
  match "2012-r2" to release `2012`, a different release. It is reported as no match instead.
- Findings are `eol/<product>/<release>`, use the same store tables, dedupe and
  acknowledgements as KEV (0002), and make `check` exit 1.

## Alerts

- First alert when the release is first found ending or ended; one reminder 30 days before the
  date; one after it passes; then quiet until acknowledged.
- They travel in the same one-message-per-channel-per-run as KEV alerts.
- The text (`alert-writing` skill) gives the date security updates stop and any extended (often paid)
  support date endoflife.date lists.
  - It names the newest supported release only if endoflife.date lists one, using its label
    ("Subscription Edition SU9"). Otherwise it points to the vendor's lifecycle page.
  - It always adds "limit who can reach it until you can upgrade".
- If endoflife.date cannot be updated, a separate "could not update the endoflife.date data" notice
  goes out at most once a day, as for KEV.
