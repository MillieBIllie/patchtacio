# 0005: Local web UI

- **Status:** accepted
- **Date:** 2026-10-04
- **Scope:** M5 (`patchtacio ui`, `internal/ui`)

`patchtacio ui` lets someone who has never used a terminal set Patchtacio up: choose products, set up
and test alerts, see and acknowledge findings, and set up the daily check. These are the choices
made, and why.

## What it does, and what it does not

- Four pages behind a setup overview: Products, Alerts, Findings, Daily check.
- **The UI never sends alerts.** "Download the latest data" runs `check` without `--notify`, so it records
  findings and acknowledgements and nothing else. Alerts have one sending path: the daily check
  (`watch run`), which the Daily check page can start now ("Run it now"). Two paths could double-send
  or disagree about dedupe.
- Every action calls the same code as the CLI: `runCheck` (split out of `check`), `installWatch`,
  `uninstallWatch`, `runWatchNow` and `watchState` (split out of `watch`), `store.Acknowledge`,
  `secrets.Store`, `config.Save`. The UI cannot drift from the CLI's rules: no install without a
  channel, no feed problem reported as "nothing found", exit-code meanings unchanged.
- Finding cards use the same wording blocks as email and chat (`advice.KEVCard`, `advice.EOLCard`), with
  golden tests.

## Who can use it

The UI runs on a computer that other people may use too (a school or council PC with several
accounts), so "it only listens on 127.0.0.1" is not enough.

- **Network:** a random port on `127.0.0.1` only, never `0.0.0.0` or `::`.
- **Linux: same user only.** Accepted connections are looked up in `/proc/net/tcp` and
  `/proc/net/tcp6` (an IPv6 socket can connect to `::ffff:127.0.0.1`). One whose other end is owned by
  another uid, or **cannot be found** (a connected socket is always listed), is closed before any HTTP
  is read, so another user's program cannot use a stolen link or cookie at all. Only when `/proc/net`
  cannot be read at all is the check skipped, with a warning. Addresses are compared in the machine's
  own byte order, so big-endian Linux works too. macOS and Windows have
  no cheap unprivileged equivalent, so there the link and the cookie are the protection.
- **Host check:** every request must carry `Host: 127.0.0.1:<port>` exactly. A web page on another
  site that makes its own name resolve to 127.0.0.1 (DNS rebinding) sends its own name and gets 421.
  `localhost` is refused too: the server opens and prints `127.0.0.1` only.
- **Session:** at start the server makes a 256-bit launch token. The browser opens
  `/login?token=…` once, and that exchanges it for a session cookie (`HttpOnly`, `SameSite=Strict`, host-only,
  no expiry: it ends with the browser session), then redirects to `/` so the token leaves the address bar.
  - The token works **once** and for **2 minutes**. A wrong guess does not burn it.
  - **The right token used a second time ends the session**: the link may have been stolen, and
    whoever used it first, attacker or not, loses access. The terminal says so; the user restarts.
  - The terminal says "A browser opened Patchtacio at HH:MM:SS", so a session the user did not open
    can be noticed.
  - There is one session per run. A second browser has to restart `patchtacio ui`.
  - Without the cookie, every page (except the stylesheet and script) answers 401 with "start
    Patchtacio with `patchtacio ui`".
  - The cookie name carries the port, so two runs do not overwrite each other's cookie.
- **CSRF:** every POST needs the session's CSRF token (a hidden field, compared in constant time).
  As defence in depth, a POST is refused if `Sec-Fetch-Site` is present and not `same-origin`, or if
  `Origin` is present and not `http://127.0.0.1:<port>`. The `SameSite=Strict` cookie already keeps
  cross-site requests out. POST bodies are capped at 64 KB.
- **Headers:** `Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self';
  img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, plus
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `nosniff`, `Cache-Control: no-store`.
  External links use `rel="noopener noreferrer"`.
- **Escaping:** `html/template` throughout. Feed text with links goes through `linkify`, which
  escapes everything and turns only `http(s)://` URLs into links.

### Opening the browser

- **Windows:** `ShellExecute` (`golang.org/x/sys/windows`): no subprocess, no command line to quote.
- **macOS:** `/usr/bin/open <link>`.
- **Linux and others:** `xdg-open <link>`, found on `PATH` (like `systemctl` and `crontab` in 0004).
- `OpenBrowser` refuses anything that is not `http://127.0.0.1:` without spaces or quotes.
- The link is also printed. If the browser did not open, the user can copy it within the 2 minutes.
  `--no-browser` only prints it.

### Accepted risks

These are what is left after the protections above. Both need a hostile account on the same computer.

- **The launch token is visible on the command line of the browser process** while it starts (`xdg-open`,
  `open`, or the browser itself). On Linux another local user can read other processes' command lines.
  The token works once and for 2 minutes. If an attacker uses it first, the real browser's use ends
  the attacker's session too, and the terminal warns. On Linux the peer check refuses the attacker's
  connection anyway. We chose this over opening a redirect file, as Jupyter does: snap and Flatpak
  browsers (Ubuntu's default Firefox) cannot read files in `/tmp` or hidden folders, so on the most common
  Linux desktop the browser would not open at all. Windows does not show other users' command lines
  to a standard user.
- **Cookies are per host, not per port.** Any page the user's browser loads from
  `127.0.0.1:<another port>` (a hostile local server, or a harmless dev server that logs headers)
  gets the session cookie. On Linux another user's program still cannot connect (peer check); on
  macOS and Windows it could use the cookie until the UI stops (Stop, Ctrl+C, or one idle hour).
  `Secure` or `__Host-` cookies would stop it, but browsers do not reliably keep them over plain http
  on `127.0.0.1`.
- On Windows the browser is started with `ShellExecute`, so a browser that was not already running
  inherits this process's environment, including any `PATCHTACIO_*` secrets set in it. Only the same
  user (or an administrator) can read it. On Linux and macOS the browser gets the environment without
  them.
- No TLS: traffic never leaves the computer.

## Secrets

- The Alerts page takes the SMTP password, webhook URL and ntfy URL and token in password fields,
  and saves them with `secrets.Store.Set` in the OS keychain, as `patchtacio secret set` does. They
  never go in the configuration file, and **no page ever shows a secret's value**. Pages show only
  where a secret comes from: keychain, environment variable (used first), or not set.
- A field left empty keeps the saved value. A secret for a channel that is turned off is ignored.
- Webhook and ntfy URLs are checked (`notify.CheckURL`: https, or http to 127.0.0.1 only) with the
  rest of the form, before anything is saved.
- Messages that may quote a server's reply (a failed test, an SMTP or webhook error) are shown as
  plain text, never with links, so a hostile endpoint cannot put a link in Patchtacio's page. Only
  Patchtacio's own feed warnings get links.
- If the keychain cannot be reached (a Linux server without a desktop session), the page says so and
  the environment-variable route (docs/ALERTS.md) still applies.

## The configuration file

- The UI writes `config.yaml` with `config.Save` (atomic), like `init`. Comments in the file are not
  kept, as with `init`.
- **No lost edits.** Each form carries the SHA-256 of the file as it was read. If the file has
  changed since then (hand edit, another tab, `init`), the save is refused and the page reloads the
  current file. The hash is compared just before the atomic write; an edit in the milliseconds
  between can still be overwritten, which is accepted.
- **No overwriting a broken file.** A file that cannot be parsed or validated is shown with its
  error, and every save is refused until it is fixed, as `init` refuses.
- Renamed catalog entries are shown and saved as their successors (`Config.Resolve`).
- Versions (64 characters) and notes (200) must be one line, and acknowledgement notes 500.

## Lifetime

- `patchtacio ui` runs until **Stop Patchtacio** (a POST, so another site cannot trigger it), Ctrl+C,
  or **one hour without a request from the session** (a stranger's requests do not count), which bounds how long a forgotten window or a stolen session
  lasts. Shutdown waits up to 5 seconds for requests in flight, then for any backend call still
  running (a keychain write, a schedule install) to finish, so nothing is left half done.
- Showing a page runs `check` on the saved data, which records the findings it sees (as every
  `check` does, 0002), so that "Mark as dealt with" works for anything on the page. That is the only
  write a GET makes, and it changes nothing a user could notice.
- One backend call at a time (a mutex), because the app's lazily built pieces (the secrets store)
  are not safe for concurrent use, and one user does not need parallel checks.
- No write timeout, because downloading the feeds can take minutes. Each feed keeps its own limits
  (0001), and headers must arrive within 10 seconds.

## Windows double-click

Double-clicking `patchtacio.exe` in Explorer, with no arguments, runs `patchtacio ui`. Cobra's
"this is a command line tool" message is turned off only in that case, through
`inconshreveable/mousetrap`, which cobra already depends on: it is now direct, not a new module.
The console window stays open while the UI runs and says to keep it open. Closing it stops
Patchtacio. A Start-menu shortcut belongs to packaging (M6).

## Many findings at once

A first run with Windows Server lists more than 200 KEV entries, most of them fixed by cumulative
updates the user installed long ago. Acknowledging them one by one is not realistic, and a user who
gives up never sees the next real alert for what is left.

- The Findings page can mark every open KEV entry of **one product** as dealt with, or only those
  added to KEV **more than 30 days ago** (the default), so a newly added flaw is never swept up
  with the old ones by default.
- It needs a **note** (kept with every entry, as `ack --note` does) and a ticked confirmation that
  the entries were checked against the version run. Patchtacio does not compare versions, so it
  never offers to decide that for the user (CLAUDE.md rule 7: nothing is called safe to ignore).
- The server works out which findings to mark from the saved data, at the moment of the request.
  The browser sends only the product and the choice, never a list of IDs.
- "Move all back to open" undoes it per product. End-of-life findings are not included: each is
  one release and is acknowledged on its own.
- The CLI keeps `ack <CVE>...`. A product-wide `ack` can follow if someone needs it in scripts.

## Data sources

The Findings page shows each feed's saved copy, its state (up to date, out of date, missing), its
last successful check, why it is out of date, and the last update's error (redacted), as
`feeds status` does. It reads only the database and never downloads.

## Not in M5

- Editing the catalog or importing inventory.
- Accessibility audit beyond semantic HTML, labels, and working without JavaScript.
