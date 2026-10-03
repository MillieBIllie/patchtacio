# Alerts

`patchtacio check --notify` checks your products against the CISA KEV catalog and sends what is
new on the channels you configure: email, a chat webhook (Slack, Microsoft Teams, Discord), the
ntfy phone app, or a desktop notification. M4 will run it on a schedule; until then, run it
yourself or from cron / Task Scheduler.

## What you get, and when

- **One message per channel per run.** One new finding gets a full alert. Several (for example on
  the first run, when everything already on CISA's list is new to you) arrive as one summary,
  most urgent first.
- **Each finding is alerted once.** A CVE that matches two of your products (KEV does not say
  whether a Windows flaw affects desktop or server editions) is one alert naming both.
- **Reminders**, for findings nobody has acknowledged: one when CISA's deadline is 3 days away,
  and one after it passes. Then nothing more; `patchtacio check` always lists them.
- **Digest** (optional): `digest: daily` or `digest: weekly` collects alerts and sends at most one
  message per day or week per channel.
- If a channel fails, `check --notify` exits `2` (so a scheduled run is noticed) and retries
  that channel on the next run. The other channels are not repeated.

CISA's deadlines are set for US government agencies. Alerts show them as a guide to urgency.

Every alert says what is affected (with the version and notes from your configuration), why it
matters, what to do (the vendor advisory for the fixed version, CISA's required action, or
restricting access until you can update), and how to acknowledge it. Patchtacio matches by
product name and does not compare versions yet, and every alert says so.

## Acknowledging

When you have dealt with a finding (patched, mitigated, or the product is not exposed):

```sh
patchtacio ack CVE-2024-21762                                   # every product it matched
patchtacio ack CVE-2024-21762 --note "upgraded to 7.4.3"        # keep a note of what you did
patchtacio ack CVE-2026-81963 --product microsoft-windows-server  # just one product
patchtacio ack CVE-2024-21762 --undo                            # reminders resume
```

Acknowledged findings get no more alerts or reminders. `patchtacio check` still lists them, with
`ACK yes` (and `"acknowledged": true` in `--json`).

## Setting it up

Add a `notify:` section to your configuration file (the path is printed by `patchtacio init`).
A channel is on when its section is there. **Secrets never go in this file**: each comes from an
environment variable, read when an alert is sent.

```yaml
version: 1
products:
  - id: fortinet-fortios
    version: "7.4.2"
    notes: "head office firewall"
notify:
  digest: off            # off (default), daily or weekly
  email:
    host: smtp.example.org
    port: 587            # default 587; 465 with security: tls
    security: starttls   # starttls (default), tls, or none (only to a server on localhost)
    username: alerts@example.org   # optional; password in PATCHTACIO_SMTP_PASSWORD
    from: "Patchtacio <alerts@example.org>"
    to: [it@example.org]
  webhook:
    kind: slack          # slack, teams or discord; URL in PATCHTACIO_WEBHOOK_URL
  ntfy:
    priority: 4          # 1 to 5, default 4; topic URL in PATCHTACIO_NTFY_URL
  desktop: true
```

| Channel | Environment variables |
|---|---|
| email | `PATCHTACIO_SMTP_PASSWORD` (only if `username` is set) |
| webhook | `PATCHTACIO_WEBHOOK_URL` (the URL contains the token) |
| ntfy | `PATCHTACIO_NTFY_URL` (e.g. `https://ntfy.sh/<a-long-random-topic>`; on ntfy.sh anyone who knows the topic can read it), optional `PATCHTACIO_NTFY_TOKEN` |
| desktop | none |

Then check each channel:

```sh
patchtacio test-alert                    # every configured channel
patchtacio test-alert --channel email    # just one
```

Test messages say they are tests and are not recorded, so real alerts are unaffected.

### Notes per channel

- **Email.** Patchtacio insists on encryption: with `starttls`, a server that does not offer
  STARTTLS gets no login and no message. Plaintext (`none`) is only allowed to a mail server on
  the same computer. Messages are plain text and marked as automatic, so auto-replies stay quiet.
- **Slack.** Create an incoming webhook for the channel.
- **Microsoft Teams.** Microsoft is retiring the old "Incoming Webhook" connectors. In the channel,
  open **Workflows**, choose **Send webhook alerts to a channel**, and copy the URL it gives you.
  Patchtacio sends an Adaptive Card to it.
- **Discord.** Channel settings → Integrations → Webhooks. Alerts never ping anyone.
- **ntfy.** Pick a long random topic name, subscribe to it in the app, and put its URL in
  `PATCHTACIO_NTFY_URL`. A self-hosted server works too (`http://` only on the same computer).
- **Desktop.** Linux needs `notify-send` (package `libnotify-bin` on Debian and Ubuntu). macOS uses
  `osascript`. Windows shows a toast through Windows PowerShell. A notification from a scheduled
  run needs the user to be logged in.

Webhook and ntfy URLs must be `https://`. Patchtacio never follows a redirect from them (the token
would travel with it) and never prints them in errors.
