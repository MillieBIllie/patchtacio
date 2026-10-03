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

`go test -tags integration -run TaskScheduler ./internal/schedule/` (Windows) registers a real task
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
| Restart, then the job is still installed and runs | pass (`wsl --terminate`, then start) | not run | not run | **not run** |
| Missed run while off runs at the next start | pass (due 00:11 while off; ran 00:11:45 after boot) | n/a (cron skips) | not run | **not run** |
| Reinstall at another time replaces the job (one job) | pass | n/a | not run | pass |
| Uninstall removes it (and the drop-in); `--status` exits 2 | pass | pass (removes the crontab when ours was its only line) | not run | pass |
| No window flashes | n/a | n/a | n/a | **not confirmed by eye**: `patchtaciow.exe` is a GUI-subsystem program, and PowerShell starts with `CREATE_NO_WINDOW` |

Found and fixed during these runs: cobra's usage text in the log (Windows), and an empty crontab left
behind where there had been none (cron).

Still to do: macOS entirely; on Windows, a real reboot, a run missed while the PC was off, and
watching the screen during a run.
