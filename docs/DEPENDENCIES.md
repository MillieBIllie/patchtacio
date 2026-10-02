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
| `github.com/charmbracelet/x/term` | Detects whether stdin/stdout are a terminal before showing the picker. huh already depends on it; `golang.org/x/term` would add a module for the same job | M2 |

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
  - On Linux and macOS, its `init` looks up `wl-copy`/`wl-paste`, `xclip`, `xsel` or the Termux
    tools on `PATH` when Patchtacio starts, but runs nothing.
  - Pressing **Ctrl+V while searching in the `init` picker** runs one of them to read the
    clipboard. On Windows it calls the clipboard API in `user32.dll`; no program is started.
  - Nothing else in Patchtacio triggers it. Revisit this if a form ever runs without a person at
    the keyboard, or if a later huh version changes the binding.

To see why a module is present: `go mod why -m <module>`.
