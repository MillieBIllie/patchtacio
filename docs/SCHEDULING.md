# Running the check every day

`patchtacio watch --install` asks your computer's own scheduler to run `patchtacio check --notify`
once a day, so alerts arrive without anyone remembering to run Patchtacio. It runs as you and needs
no administrator rights. Design details: [decision 0004](decisions/0004-m4-scheduling.md).

Before installing, set up at least one alert channel and try it ([ALERTS.md](ALERTS.md)):

```sh
patchtacio test-alert
patchtacio watch --install            # a time between 08:00 and 08:59, picked for you
patchtacio watch --install --at 07:30 # or your own time (local time, 24-hour clock)
patchtacio watch --run-now            # start it now through the scheduler, to test the setup
patchtacio watch --status             # how the last run went; exits 2 if something needs attention
patchtacio watch --uninstall
```

`watch --install` refuses to set up a check with no alert channel, because it would tell no one.
Run it again to change the time; it replaces the old job. If you use `--config`, give it on the
install command too (`patchtacio --config /path/config.yaml watch --install`) and the job uses it.

## What each system uses

| System | Scheduler | Missed run (computer off or asleep) |
|---|---|---|
| Linux | systemd user timer `patchtacio-check.timer` in `~/.config/systemd/user` | runs at the next boot |
| Linux without systemd (WSL, containers) | a line in your crontab, ending `# patchtacio-check` | skipped |
| macOS | launchd agent `~/Library/LaunchAgents/io.github.milliebillie.patchtacio.check.plist` | runs on wake; skipped if the Mac was shut down |
| Windows | Task Scheduler task "Patchtacio check" | runs as soon as possible |

- **Linux servers:** a user timer runs only while you are logged in unless "linger" is on. Install
  tells you when it is off; turn it on with `loginctl enable-linger`.
- **Windows:** the task starts `patchtaciow.exe`, a copy of Patchtacio built without a console
  window, so nothing flashes on screen. It ships next to `patchtacio.exe` in the release zip. If it
  is missing (a `go install` build, say), the task uses `conhost.exe --headless` instead, and failing
  that `patchtacio.exe` itself, which briefly shows a window; `watch --status` says which.
  The task runs only while you are logged on, so it can use your Credential Manager and show
  notifications.

## Secrets in scheduled runs

A scheduled job does not see the environment variables of the terminal you installed it from.
Install warns about any secret it found only there. Either:

- save it in the keychain with `patchtacio secret set <name>` (works on Windows and macOS, and on
  Linux desktops; a Linux server usually has no keychain the job can reach), or
- set it for your user account: `setx PATCHTACIO_WEBHOOK_URL "https://..."` on Windows; on Linux
  with systemd, `systemctl --user edit patchtacio-check.service` and add an
  `Environment=PATCHTACIO_WEBHOOK_URL=...` line under `[Service]`, then make the file readable only
  by you: `chmod 600 ~/.config/systemd/user/patchtacio-check.service.d/override.conf`. Never put
  secrets in `config.yaml`.

`PATCHTACIO_CONFIG_DIR`, `PATCHTACIO_CACHE_DIR` and `PATCHTACIO_DATA_DIR`, if set when you install,
are copied into the job on Linux and macOS. Windows tasks cannot carry them: set them with `setx`.

## Log file and status

Each run appends to `patchtacio.log` in the `logs` folder of the cache directory (`watch --status`
prints the path). It holds what `check` printed, which alerts went out, and any errors, with
secrets removed. When it grows past 1 MB it is renamed `patchtacio.log.1`; three old copies are
kept.

`watch --status` exits 2 when the check is not installed, when the program it runs has gone (moved
or uninstalled: run `watch --install` again), when the last run failed, or when it has not run for
26 hours. That last one usually means the computer was off, or (on Linux) you were logged out
without linger.
