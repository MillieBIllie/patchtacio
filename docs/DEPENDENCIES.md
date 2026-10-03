# Dependencies

CLAUDE.md rule 9: prefer the standard library and justify every new dependency. This page records
the justification, so a reviewer can tell at a glance why each direct dependency is here.

Every dependency must be pure Go (`CGO_ENABLED=0`). CI runs `govulncheck` on all three OSes, and
Dependabot opens one grouped `build(deps)` PR a week for Go modules.

## Direct

| Module | Why | Added |
|---|---|---|
| `github.com/spf13/cobra` | CLI commands, flags, help (named in CLAUDE.md) | M0 |
| `modernc.org/sqlite` | SQLite without cgo (named in CLAUDE.md) | M1 |
| `go.yaml.in/yaml/v3` | Strict YAML for the catalog and config (`KnownFields`). The maintained successor of `gopkg.in/yaml.v3`; cobra already pulled it in | M2 |
| `charm.land/huh/v2` | The `init` product picker: a searchable multi-select with an accessible mode (named in CLAUDE.md) | M2 |
| `github.com/charmbracelet/x/term` | Detects whether stdin/stdout are a terminal before showing the picker, and reads `secret set` values without echo. huh already depends on it; `golang.org/x/term` would add a module for the same job | M2 |
| `github.com/zalando/go-keyring` | Keeps alert secrets in the OS keychain (`patchtacio secret`), which CLAUDE.md rule 5 allows besides env vars. Pure Go on Linux (D-Bus Secret Service via `godbus/dbus`), Windows (Credential Manager via `danieljoos/wincred`) and macOS (drives `/usr/bin/security`, passing the secret over stdin, not argv; checked in v0.2.8's source). Writing three keychain bindings ourselves would be more code to trust than this small, widely used module. Only the BSDs need cgo, and we do not ship BSD builds | M3 |
| `golang.org/x/sys` | `windows.GetSystemDirectory`, so `schtasks.exe`, `conhost.exe` and `powershell.exe` are run by a full path that Windows itself reports rather than one built from the `SystemRoot` variable (`internal/sysdir`). Already in the module graph through `charmbracelet/x/term` at the same version, so it adds no module; the standard library's `syscall` does not expose this call | M4 |

## Indirect modules worth watching

- **Pseudo-versions** (a commit, not a release) come in through huh and through modernc's
  SQLite. Dependabot only moves them when a parent module asks for a newer commit, so check them
  when reviewing a Dependabot PR or a huh upgrade:
  - `github.com/charmbracelet/ultraviolet` (terminal rendering for huh/bubbletea v2)
  - `github.com/charmbracelet/x/exp/strings`
  - `github.com/xo/terminfo`
  - `github.com/remyoudompheng/bigfft` (modernc)
- **`github.com/atotto/clipboard`** comes in through `charm.land/bubbles` text inputs, which the
  picker's search box uses (checked in bubbles v2.0.0 and clipboard v0.1.4):
  - On Linux and the BSDs, its `init` looks up, in order, `wl-copy`/`wl-paste` (only when
    `WAYLAND_DISPLAY` is set), `xclip`, `xsel`, the Termux tools, then `clip.exe` +
    `powershell.exe` (for WSL) on `PATH` when Patchtacio starts, but runs nothing.
  - On macOS there is no lookup: it always uses `pbpaste` from `PATH`.
  - Pressing **Ctrl+V while searching in the `init` picker** runs the chosen program to read the
    clipboard; under WSL with none of the Linux tools installed, that is
    `powershell.exe Get-Clipboard`. On Windows it calls the clipboard API in `user32.dll`; no
    program is started.
  - Nothing else in Patchtacio triggers it. Revisit this if a form ever runs without a person at
    the keyboard, or if a later huh version changes the binding.

To see why a module is present: `go mod why -m <module>`.
