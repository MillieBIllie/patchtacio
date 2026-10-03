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
- Windows: Task Scheduler → Task Scheduler Library → "Patchtacio check" → History; or
  `schtasks /Query /TN "Patchtacio check" /V /FO LIST`.

## Automated pieces

`go test -tags integration -run TaskScheduler ./internal/schedule/` (Windows) registers a real task
from the generated definition, checks the stored settings, starts it, and deletes it.
