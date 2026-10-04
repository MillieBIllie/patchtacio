# Manual test checklist: scheduled checks

Unit tests cover the generated scheduler files and the command sequences, but only a real machine
shows that a job survives a reboot and runs on time. Do this on each OS before a release that changes
`internal/schedule`, `cmd/patchtacio/watch.go` or the desktop notifier, and record the result in the
PR.

Use a throwaway configuration so the test does not touch real alert history. On Windows the task
cannot carry `PATCHTACIO_*_DIR`, so the run uses your normal data folder: back up `patchtacio.db`
first, or test on a machine without a real setup.

## Setup (every OS)

```sh
patchtacio --config ./test-config.yaml init --products citrix-netscaler
# add to test-config.yaml:
#   notify:
#     desktop: true
patchtacio --config ./test-config.yaml test-alert            # a notification appears
```

Use an absolute path for `--config` (or let install turn it into one).

## Checklist

| Step | Linux (systemd) | Linux (cron) | macOS | Windows |
|---|---|---|---|---|
| `watch --install --at <in 5 min>` prints the method, time and next run | | | | |
| Linux: a linger note appears when `loginctl show-user $USER -p Linger` is `no` | | n/a | n/a | n/a |
| Windows: "Started: patchtaciow.exe (no console window)" | n/a | n/a | n/a | |
| `watch --run-now`; a notification appears; **no window flashes** | | n/a | | |
| `watch --status` a minute later: "Last run: … just now", exit 0 | | | | |
| The log file has a start line, the check output, and "finished, exit code 1", and no "Usage:" | | | | |
| **Reboot**, log in, leave the machine on past the `--at` time | | | | |
| `watch --status` shows a run at the scheduled time | | | | |
| Missed run: shut down over the scheduled time, boot: the check runs soon after (Linux systemd, Windows) | | skip | skip | |
| `watch --install --at <another time>` replaces the job (one job in the scheduler's list) | | | | |
| `watch --uninstall` removes it; `watch --status` says not set up and exits 2 | | | | |

Where to look in each scheduler:

- Linux: `systemctl --user list-timers patchtacio-check.timer`, `journalctl --user -u patchtacio-check`;
  cron: `crontab -l`.
- macOS: `launchctl print gui/$(id -u)/io.github.milliebillie.patchtacio.check`.
- Windows: Task Scheduler → Task Scheduler Library → "Patchtacio check (<your user name>)" → History;
  or `schtasks /Query /TN "Patchtacio check (<your user name>)" /V /FO LIST`.

## Automated pieces

The `Scheduling end to end` workflow (`.github/workflows/scheduling-e2e.yml`) runs these on
GitHub's runners, on pull requests that touch scheduling code, weekly, and by hand. Neither covers a
reboot or a missed run, so the table below still matters.

- `go test -tags integration -run LaunchdEndToEnd ./cmd/patchtacio/` (macOS) builds Patchtacio,
  installs a real launchd agent with every Patchtacio folder in a temp directory, and checks a run
  started on demand, a run launchd starts by itself at the scheduled minute (alerts go to an SMTP
  receiver inside the test), `watch --status`, and uninstall. It fetches the live KEV catalog, and
  skips itself if a real Patchtacio agent is installed.
- `go test -tags integration -run TaskScheduler ./internal/schedule/` (Windows) registers a real task
  from the generated definition, checks the stored settings, starts it, and deletes it.

## Results

### 2026-10-04, branch `m4-scheduling`

Windows 11 (Task Scheduler) and Linux in WSL 2 (Kali, systemd 259 user manager, cron), each with a
throwaway configuration. On Linux, `PATCHTACIO_*_DIR` pointed at a scratch folder and alerts went to
a local ntfy-style HTTP receiver on 127.0.0.1, because WSL has no desktop notification daemon.

| Step | Linux (systemd) | Linux (cron) | macOS | Windows |
|---|---|---|---|---|
| Install prints method, time, next run | pass | pass | not run | pass |
| Linux: linger note when linger is off | pass | n/a | n/a | n/a |
| Windows: started by `patchtaciow.exe`; task named per user | n/a | n/a | n/a | pass |
| `--run-now` runs the job through the scheduler | pass | n/a (explains `watch run`) | not run | pass |
| Runs **by itself** at the `--at` time | pass (00:08:42) | pass (00:14:02) | not run | pass (00:17:00) |
| Alert delivered from the scheduled run | pass (ntfy, secret from a private `EnvironmentFile` drop-in) | expected failure: cron cannot see the secret | not run | pass (desktop toast) |
| Log: start line, check output, exit code, no "Usage:"; files mode 600 | pass | pass | not run | pass |
| A second run sends nothing new (dedupe) | pass | n/a | not run | pass |
| Failed run: `--status` exits 2 with the reason; desktop notification tried | n/a | pass (no display in WSL, so the attempt is logged) | not run | pass (toast shown) |
| Restart, then the job is still installed and runs | pass (`wsl --terminate`, then start) | not run | not run | pass (restarted 11:49; ran 12:00:00) |
| Missed run while off runs at the next start | pass (due 00:11 while off; ran 00:11:45 after boot) | n/a (cron skips) | not run | pass (due 12:18 while shut down; ran 12:36:54, 6 min after power-on) |
| Missed run while asleep runs on wake | n/a | n/a | not run | pass (due 12:09 while asleep; ran 12:12:13, 2 s after waking) |
| Reinstall at another time replaces the job (one job) | pass | n/a | not run | pass |
| Uninstall removes it (and the drop-in); `--status` exits 2 | pass | pass (removes the crontab when ours was its only line) | not run | pass |
| No window flashes | n/a | n/a | n/a | pass (watched at 12:00: toast shown, no console window) |

Found and fixed during these runs: cobra's usage text in the log (Windows), and an empty crontab left
behind where there had been none (cron).

### 2026-10-04, Windows 11 restart and power-off, `main` at `bf22687`

Patchtacio installed in `%LOCALAPPDATA%\Programs\patchtacio` (both programs), desktop channel,
times read from the Windows event log and Task Scheduler:

- **Restart:** installed 11:47 for 12:00; restarted from Start at 11:49; the task ran at 12:00:00
  through `patchtaciow.exe`. The tester saw the toast and no console window.
- **Asleep:** installed 12:06 for 12:09; Modern Standby 12:07 to 12:12:11; the missed run started
  at 12:12:13.
- **Shut down** (Start → Shut down, Fast Startup on): installed 12:15 for 12:18; off from 12:15 to
  12:30:56; Task Scheduler counted one missed run and started it at 12:36:54. Windows waits up to
  about 10 minutes after startup before running a missed task, so a catch-up is not instant.

### 2026-10-04, macOS on GitHub's runner (`macos-latest`)

`TestLaunchdEndToEnd` in the `Scheduling end to end` workflow (run 37185508481, PR #11): a real
launchd agent installed and loaded, a run started on demand, launchd started the run by itself at
the scheduled 07:23, the alert reached the test's mail receiver, dedupe sent nothing the second
time, `--status` exited 0, and uninstall removed the agent.

Still to do on a real Mac: restart, a run missed while asleep or shut down, and the desktop
notification (the runner test uses email).
