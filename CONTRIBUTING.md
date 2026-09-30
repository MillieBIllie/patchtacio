# Contributing to Patchtacio

Thanks for helping. Patchtacio is used by people who aren't security specialists, so correctness
and clear wording matter more than features.

## Setup

You need Go (latest stable), `golangci-lint`, and optionally `goreleaser`.
[docs/SETUP.md](docs/SETUP.md) has per-OS install commands.

## Before you open a pull request

Run these from the repo root. CI runs the same checks on Linux, Windows, and macOS.

```sh
go build ./...
go vet ./...
go test ./...
golangci-lint run
```

## Rules

- **Pure Go only.** Builds use `CGO_ENABLED=0`. Don't add dependencies that need cgo.
- **Tests never call live APIs.** Use recorded fixtures in `testdata/`. Anything that hits the
  network goes behind the `integration` build tag.
- **Never invent security facts.** No made-up CPEs, fixed versions, or dates. If the source data
  doesn't say, the alert says "check the vendor advisory" and links to it.
- **Cross-platform.** Use `filepath.Join`, `os.UserConfigDir()`, and `os.UserCacheDir()`. Put
  OS-specific code in `_linux.go`, `_windows.go`, and `_darwin.go` files. Run subprocesses with
  argument slices, never through a shell.
- **No secrets** in code, fixtures, logs, or error messages.
- **Errors** are wrapped with `%w`. No `panic` outside `main`.
- **Dependencies:** prefer the standard library, and explain any new dependency in the PR.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
  `test:`, `ci:`, `build:`, `chore:`, `refactor:`.
- Keep PRs small and link them to a task in [docs/ROADMAP.md](docs/ROADMAP.md).

## Product catalog

Entries in `catalog/products/` are CC0, so by contributing one you agree to release it into the
public domain. Every alias, CPE, and endoflife.date slug must come from a source you can link to.

## License

By contributing, you agree that your contributions are licensed under Apache-2.0 (code) or
CC0 1.0 (catalog data).
