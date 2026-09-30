---
name: cross-platform
description: Rules and per-OS details for making Patchtacio work identically on Linux, Windows, and macOS, covering config/cache paths, scheduled checks (systemd/cron, Task Scheduler, launchd), local installed-software inventory, desktop notifications, file handling, and CI testing. Use this for any code touching the filesystem, subprocesses, scheduling, notifications, or OS-specific behavior, and whenever a test fails on only one OS.
---

# Cross-platform rules

## Per-OS reference

| Concern | Linux | Windows | macOS |
|---|---|---|---|
| Config dir (`os.UserConfigDir`) | `~/.config/patchtacio` | `%AppData%\patchtacio` | `~/Library/Application Support/patchtacio` |
| Cache dir (`os.UserCacheDir`) | `~/.cache/patchtacio` | `%LocalAppData%\patchtacio` | `~/Library/Caches/patchtacio` |
| Scheduled check | systemd **user** timer; fallback cron | Task Scheduler (`schtasks` with args, or COM API) | launchd agent in `~/Library/LaunchAgents` |
| Installed software | dpkg, rpm, snap, flatpak | registry Uninstall keys (HKLM + HKCU, 32/64-bit views), winget | `/Applications` bundle Info.plist, Homebrew |
| Desktop notification | `notify-send` / D-Bus | toast notification | `osascript` / UserNotifications |
| Secrets | Secret Service (keyring) | Credential Manager | Keychain |

## Rules

- Always `filepath.Join`; never hardcode `/` or `\`. Use `os.UserConfigDir` / `os.UserCacheDir`.
- OS code lives in `foo_linux.go`, `foo_windows.go`, `foo_darwin.go` behind a shared interface,
  with a `foo_other.go` fallback that returns a clear "not supported" error.
- Subprocesses: `exec.CommandContext(ctx, name, args...)`. Never `sh -c` / `cmd /c` with
  interpolated strings. Handle "command not found" gracefully.
- Don't require admin/root. Everything installs per-user by default.
- Windows: files can't be replaced while open, so close before rename. Watch for CRLF in fixtures
  (`.gitattributes`: `testdata/** -text`). Paths can have spaces, so quote in generated task definitions.
- macOS: launchd plist `ProgramArguments` needs the absolute path to the binary; Homebrew paths
  differ on Intel (`/usr/local`) vs Apple Silicon (`/opt/homebrew`).
- Linux: systemd user timers need `loginctl enable-linger` to run when logged out. Detect and
  explain, don't silently fail.

## Testing

- Scheduler, inventory, and notification code: unit-test the **generated artifact** (unit file,
  task XML, plist) with golden files on every OS; the actual install goes in integration tests.
- CI matrix runs `go test ./...` on ubuntu, windows, and macos for every PR.
- Keep a manual checklist in `docs/manual-testing.md` for install → reboot → scheduled run.
