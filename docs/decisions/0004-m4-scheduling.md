# 0004: Scheduled checks

- **Status:** accepted
- **Date:** 2026-10-03
- **Scope:** M4 (`patchtacio watch`, the scheduled run, the log file)

`patchtacio watch --install` sets up a daily `check --notify` with the operating system's own
scheduler, so alerts arrive without anyone remembering to run Patchtacio.

## Commands

- `watch --install [--at HH:MM]`, `watch --uninstall`, `watch --status` (the default) and
  `watch --run-now` (asks the scheduler to start the job now, to test the real setup).
- The scheduler runs `patchtacio watch run` (hidden). It does exactly what `check --notify` does,
  with the same exit codes, and also:
  - writes its output and an info-level log (redacted as on the terminal, with timestamps) to the
    log file instead of a terminal;
  - records the run (start, end, exit code, one-line reason) in `watch-last-run.json` in the data
    directory, for `--status`.
- Install records what it set up (method, time, program, arguments) in `watch-install.json` in the
  data directory. `--status` reads both files and asks the scheduler whether the job is still there.
- Installing again replaces the job. Uninstall removes every kind of job it finds.

## When it runs

- Once a day at a fixed local time. Without `--at`, install picks a random minute from 08:00 to
  08:59 and prints it, so installs do not all hit CISA and endoflife.date at the same second.
- Daily only: weekly email is what `digest: weekly` is for, and a daily run keeps the
  "data could not be updated" notices timely.
- A run missed while the computer was off or asleep runs when it is next available (systemd
  `Persistent=true`; Task Scheduler `StartWhenAvailable`). launchd catches up after sleep but not
  after the Mac was shut down; cron does not catch up at all. Both are accepted for now.

## Refusing to install a job that would tell no one

- Install fails (exit 2) without a configuration, with no products, or with no `notify:` channel:
  `check --notify` fails with no channel, so the job would fail every day, while the user believed
  they were being watched.
- Install warns (and continues) when a secret a channel needs is found only in this shell's
  environment, because a scheduled job does not inherit it. The fix is `patchtacio secret set`, or a
  user-wide variable (`setx` on Windows, an `Environment=` line via `systemctl --user edit`). Secrets
  are never written into anything the scheduler reads (CLAUDE.md rule 5).
- Install refuses to run from a `go run` build (the program would vanish), and prefers the
  `patchtacio` on `PATH` when it is the same file as the running one, so a Homebrew upgrade or a
  Scoop `current` link keeps working.

## Per operating system

Everything is per user; nothing needs admin or root. Every command runs with an argument list, never
through a shell.

- **Linux:** a systemd user service and timer (`patchtacio-check.service`, `patchtacio-check.timer`
  in `~/.config/systemd/user`), enabled with `systemctl --user`. `SuccessExitStatus=1 3`, so findings
  or stale data do not mark the service failed; exit 2 does. Install checks linger: without it the
  timer runs only while the user is logged in, so it explains `loginctl enable-linger` (it does not
  run it).
- **Linux without a systemd user manager** (WSL, containers): one crontab line ending in the marker
  `# patchtacio-check`, edited with `crontab -l` / `crontab -`, leaving other lines alone. Cron runs
  the line through `/bin/sh`, so every value is single-quoted and `%` escaped; values with control
  characters are refused.
- **macOS:** a launchd agent `~/Library/LaunchAgents/io.github.milliebillie.patchtacio.check.plist`
  (`StartCalendarInterval`, `ProcessType` Background), loaded with `launchctl bootstrap gui/<uid>`,
  falling back to `launchctl load -w`. launchd's own output goes to a file next to the log, so a run
  that cannot open its log is still recorded.
- **Windows:** Task Scheduler task `Patchtacio check`, created with `schtasks /Create /XML` from a
  generated UTF-16 task definition: runs only while the user is logged on (no stored password, and
  Credential Manager and toasts still work), also on battery, catches up on missed runs, 30-minute
  limit, a second copy is not started while one runs.
  - **No console window.** A console program started by Task Scheduler flashes a window. The task
    runs, in order of preference:
    1. `patchtaciow.exe`, the same program built as a Windows GUI program (`-H windowsgui`, like
       `pythonw.exe`), shipped next to `patchtacio.exe`;
    2. otherwise `conhost.exe --headless patchtacio.exe ...` (Windows 10 1809 and later;
       undocumented, so only a fallback);
    3. otherwise `patchtacio.exe` itself, which flashes; `--status` says so and how to fix it.
  - The desktop notifier starts Windows PowerShell with `CREATE_NO_WINDOW`, or a windowless run would
    open a PowerShell window.
  - `PATCHTACIO_*_DIR` overrides cannot be passed to a task, so install warns that they must be set
    user-wide. On Linux and macOS they are copied into the job.

## Log file

- `<cache>/logs/patchtacio.log`, readable only by the user. Logs live with the cache because they
  are safe to delete.
- When it is over 1 MiB at the start of a run it becomes `patchtacio.log.1` (older copies shift up
  to `.3`, the oldest is removed). On Windows a rename that fails (file open elsewhere) is ignored and
  the run appends.
- Each run starts with a header line (time, version) and ends with its exit code.

## `watch --status`

- Prints how the check is installed, when it runs, the program, the last run and its result, and
  the log path, plus warnings (linger off, console window on Windows, program missing).
- Exits **0** when installed and healthy, **2** when not installed, when the program it runs is
  gone, when the last run exited 2, or when it is overdue: no run for 26 hours (or, before a first
  run, 26 hours after install). Overdue catches a sleeping laptop, a missing linger, or a job the
  scheduler dropped.

## Testing

- Each generated file (systemd unit and timer, crontab edit, plist, task XML) has golden tests that
  run on every OS in CI. Paths with spaces, quotes and `%` are included.
- The install, uninstall and status steps run their commands through a fake in unit tests.
- Installing for real, then reboot, is in `docs/manual-testing.md`; a Windows integration test
  (`-tags integration`) registers, queries and deletes a real task.
