# 0002: Alerts, finding identity, and acknowledgements (M3)

- **Status:** accepted
- **Date:** 2026-10-03
- **Scope:** M3 (alerts); M4 (scheduling) and M5 (UI) inherit these contracts

Record 0001 left finding identity and dedupe to M3. These are the choices made, and why.

## Finding identity

- A finding is one KEV entry matching one catalog product: id `kev/<product-id>/<CVE>`.
- Rows are never merged or split by catalog or config changes. A product that is unticked keeps
  its rows, so ticking it again does not alert again for entries already delivered.
- `check` records findings on every run, not only with `--notify`, so `ack` works after a plain
  check. Recording never sends anything.

## Delivery and dedupe

- Deliveries are stored per **finding, channel and kind** (`new`, `due-soon`, `overdue`).
  - A channel that fails records nothing and is retried alone on the next run.
  - A channel that worked is never repeated because another one failed.
- **One message per channel per run.** Several findings become one summary, and findings sharing
  a CVE (Windows desktop and server) become one item naming both products.
- **First run:** everything already on CISA's list is "new" to that channel and arrives as one
  summary. Nothing is silently treated as already seen, because that would amount to telling the
  user "nothing to do" about exploited, unpatched flaws.
- **Reminders** go only for unacknowledged findings: once when CISA's due date is 3 days away or
  nearer, once after it passes, and then never again.
  - A `new` alert for a finding already near or past its deadline also counts as those reminders,
    so a first run is not followed by a burst of them.
  - Weekly nagging was rejected: old KEV entries would nag forever.
- **Digest** (`daily` or `weekly`): a channel holds alerts until a period has passed since its last
  delivery. The period is one hour short, so a run scheduled at the same time each day is not
  held back by a few minutes of drift. There is no extra table; the last delivery time is
  `MAX(sent_at)` for the channel.

## Acknowledgements

- `patchtacio ack <CVE>` acknowledges the CVE for every product it matched. `--product` narrows
  it, and a finding id names exactly one. CVE IDs were chosen over short hashes because they can
  be typed from an email or SMS without copying.
- An acknowledgement stops all alerts and reminders. The finding stays listed (`ACK yes`).
  `--undo` resumes reminders for the kinds not yet delivered.

## Exit codes (extends 0001)

- `check --notify` exits **2** if any channel failed, even when there are findings (which would
  otherwise be 1). A scheduled run that cannot deliver must be noticed, not reported as "findings
  as usual".
- `check --notify` with no channel configured fails with 2 before downloading anything.
- `test-alert` exits 0 when every channel worked, and 2 otherwise.

## Channels and secrets

- Secrets come only from environment variables, read when a channel sends:
  `PATCHTACIO_SMTP_PASSWORD`, `PATCHTACIO_WEBHOOK_URL`, `PATCHTACIO_NTFY_URL`, and
  `PATCHTACIO_NTFY_TOKEN`. The ntfy topic URL is treated as a secret because on ntfy.sh the topic
  name is the only protection. OS keychain support is a follow-up.
- Webhook and ntfy URLs:
  - must be `https://`; `http://` is allowed only to a server on the same computer.
  - Redirects are never followed, because the token would travel with them.
  - URLs never appear in errors (`*url.Error` is unwrapped).
  - Only a 429 is retried, once. Any other failure may mean the message was already posted.
- SMTP:
  - STARTTLS is required when configured, with no plaintext fallback.
  - Plaintext is allowed only to 127.0.0.1 or ::1. The name "localhost" is refused, because DNS could resolve it to another computer.
  - Uses the standard library (`net/smtp`), so no new dependency.
- Teams uses Workflows webhooks with an Adaptive Card, because Microsoft is retiring the
  Microsoft 365 connector webhooks.
- Desktop notifications never pass alert text through a shell or into a script.
  - Linux: arguments after `--`.
  - macOS: AppleScript `argv`.
  - Windows: a fixed PowerShell 5.1 script, passed as `-EncodedCommand` and run from its full
    System32 path, that reads the text from environment variables.

## Not in M3

- End-of-life alerts. They need the user's version mapped to an endoflife.date release cycle, so
  they are tracked as a separate roadmap task.
