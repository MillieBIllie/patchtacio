# Manual test checklist: web UI

M5 is done when **a non-technical tester can set everything up without touching the CLI**. The unit
and end-to-end tests (`go test ./internal/ui/ ./cmd/patchtacio/ -run UI`) cover the server, its
security checks and each page with recorded feed data. Only a person can show that the pages make
sense. Do this before a release that changes `internal/ui` or `cmd/patchtacio/ui.go`, and record the
result below.

## With a tester

Give the tester a computer with Patchtacio installed (or `patchtacio.exe` on the desktop), this
sheet's task list, and nothing else. Do not help unless they are stuck for more than two minutes,
and note where that happened.

Tasks for the tester:

1. Start Patchtacio. (Windows: double-click `patchtacio.exe`. Mac or Linux: you may start
   `patchtacio ui` for them; that is the one command allowed.)
2. Tell Patchtacio that you run FortiGate firewalls (version 7.2.8, in the head office) and Microsoft
   Exchange.
3. Make Patchtacio send alerts to your email address (or a Teams channel), and check that a test
   arrives.
4. Find out which problems Patchtacio knows about for your products, and which one is newest.
5. Say that you have dealt with that newest one ("patched today").
6. Make Patchtacio check every day at 07:30, and make it run once now.
7. Stop Patchtacio.

| Check | Windows | macOS | Linux |
|---|---|---|---|
| Browser opens on the Setup page by itself (Windows: double-click) | | | |
| Tester finds products by search, including by a former name ("FortiGate", "Pulse") | | | |
| Saving products leads to the Alerts page | | | |
| Secrets saved; the page shows "Saved in this computer's keychain" and never the value | | | |
| Test message arrives; a wrong password or URL shows a clear failure | | | |
| "Download the latest data" fills the Findings page; newest entries first | | | |
| "Mark as dealt with" moves the entry to "Dealt with"; `patchtacio check` shows ACK yes | | | |
| "Mark many as dealt with at once" for older Windows entries; the recent ones stay open; "Move all back" undoes it | | | |
| Data sources table shows both feeds "up to date" after a download | | | |
| Daily check set up at 07:30; "Run it now" sends the alerts; the page shows the last run | | | |
| Stop Patchtacio: the page says it has stopped; the window closes (Windows double-click) | | | |
| The settings file has no password or URL in it | | | |
| Where did the tester hesitate or need help? | | | |

## Security spot checks (developer)

With `patchtacio ui --no-browser` running and the printed link opened once:

```sh
curl -s -o /dev/null -w "%{http_code}\n" "<the link again>"                            # 403: works once
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:<port>/                       # 401: no session
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: evil.example" http://127.0.0.1:<port>/  # 421
netstat -an | grep <port>                                                               # 127.0.0.1 only
```

## Results

### 2026-10-04, Windows 11, branch `feat/m5-web-ui` (developer walkthrough, no tester yet)

Real binary, real feeds, throwaway `PATCHTACIO_*_DIR`, driven with curl and checked with headless Edge
screenshots at desktop and phone width:

- Launch link: 303 to `/` with the cookie; used again from another client: 403. No cookie: 401.
  `Host: evil.example`: 421. POST without the CSRF token: 403. Security headers present.
- Products: FortiOS 7.2.8 (with a note), Exchange, Windows Server 2016 saved; the file is as `init`
  writes it.
- Alerts: desktop channel and daily digest saved; **Test** showed a real Windows notification.
- Findings: "no vulnerability data yet" before the first download (never "nothing found"). Download
  took about 3 seconds: KEV 2026.10.02 (1,733 entries) and endoflife.date. Showed 245 KEV entries
  (2 added in the last 30 days, listed first) and FortiOS 7.2 past end of life on 30 Sep 2026.
- Acknowledged CVE-2025-25249 with a note; `patchtacio check --offline` then showed `ACK yes` for it.
- Daily check page: picked up the real Task Scheduler task from M4 testing (its records are in the
  normal data folder, not the throwaway one), so it showed "set up, but it needs attention", with a
  "set it up again" hint. Install was not run here, to leave the real task alone. Install, run now and
  uninstall are covered by the end-to-end test with a fake scheduler.
- **Stop Patchtacio** ended the process with exit code 0.

Not yet done: a session with a non-technical tester, the Windows double-click (it opens the real
browser and settings), and macOS and Linux desktops.
