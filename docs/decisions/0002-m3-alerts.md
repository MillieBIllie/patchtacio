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

- Deliveries are stored per **finding, destination and kind** (`new`, `due-soon`, `overdue`).
  The destination key is the channel type plus a short HMAC-SHA-256 of the recipients (email) or
  URL (webhook, ntfy), or `desktop`. A changed address or URL is a new destination that gets
  everything again, instead of silently missing what went elsewhere. Only the hash is stored, so a
  webhook token never reaches the database.
  - The HMAC key is a random per-install secret in `install.key` (owner-only), beside the database
    but not in it, so a copy of the database alone cannot be used to confirm a guessed ntfy topic.
    Someone with the whole data folder has the key too; that is the limit of this protection.
  - A damaged key file is replaced, with a warning: every destination then counts as new and gets
    one summary again (noisy, never silent).
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

- **Feed problems are reported on the alert channels.** If the KEV data is stale or missing,
  `check --notify` sends a "[Check needed] ... alerts may be missing" notice on every channel, at
  most once a day per destination (`notices` table), and still sends alerts from the saved copy.
  It is sent only when the saved copy is actually out of date, not after one failed fetch.
  Otherwise someone who only reads email would take silence as an all clear (CLAUDE.md rule 3).
- `--since` narrows the report, never the alerts.
- A store lock (`notify`, 5-minute TTL kept alive by a heartbeat, as the feed updater does) is held around sending, so a scheduled and a manual run
  cannot both send the same alert. The second waits up to a minute, then exits 2 without sending.

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

- Secrets come from environment variables (`PATCHTACIO_SMTP_PASSWORD`, `PATCHTACIO_WEBHOOK_URL`,
  `PATCHTACIO_NTFY_URL`, `PATCHTACIO_NTFY_TOKEN`) or the OS keychain, read when a channel sends,
  never from the config file. The ntfy topic URL is treated as a secret because on ntfy.sh the
  topic name is the only protection.
- **OS keychain** (`patchtacio secret set|delete|status`): a secret is looked up in its
  environment variable first, then the keychain (service `patchtacio`, account = the variable
  name).
  - **Opt-in per secret.** The keychain is asked only for secrets saved with `secret set`, listed
    by name in `secrets-in-keychain` in the config folder. Someone who uses environment variables
    never meets a keychain unlock prompt.
  - **Never stalls a run.** Each read has a 5-second limit, and all secrets are read before the
    notify lock is taken. On Linux the keychain is skipped without a D-Bus session bus, so
    `dbus-launch` is never started. A keychain that cannot be read just means "not set", and the
    run says so ("saved with `secret set`, but this run could not read it"), because scheduled tasks
    often cannot reach the user's keychain.
  - `secret set` never takes the value as an argument (shell history, process list): it asks
    without echo, or reads one line (at most 8 KB) from stdin. `status` never shows values.
- The notify lock's heartbeat stops after 30 minutes, so a run that hangs (a channel or keychain
  that never answers) cannot block every later run.
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
