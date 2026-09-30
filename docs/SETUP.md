# Patchtacio development setup

> New here? Follow **docs/GETTING-STARTED.md**. This file is the reference behind it.

Follow these once per machine. Commands and URLs were written in Sept 2026; if one fails,
check that tool's official install page, since installers and package IDs change.

## 1. Toolchain

| Tool | Why | macOS (Homebrew) | Windows (winget / scoop) | Linux |
|---|---|---|---|---|
| Git | version control | `brew install git` | `winget install Git.Git` (includes Git Bash, needed by hooks) | `sudo apt install git` / `dnf install git` |
| Go (latest stable) | the language | `brew install go` | `winget install GoLang.Go` | tarball from go.dev/dl (distro packages are often old) |
| gh | GitHub CLI | `brew install gh` | `winget install GitHub.cli` | see cli.github.com |
| jq | used by Claude Code hooks | `brew install jq` | `winget install jqlang.jq` | `sudo apt install jq` |
| gopls | Go language server + MCP | `go install golang.org/x/tools/gopls@latest` | same | same |
| golangci-lint | linting | `brew install golangci-lint` | `scoop install golangci-lint` | install script on golangci-lint.run |
| GoReleaser | releases | `brew install goreleaser` | `scoop install goreleaser` | see goreleaser.com/install |
| Syft | SBOMs (Phase 2 + comparing output) | `brew install syft` | `scoop install syft` | install script in anchore/syft README |
| Docker | container images, Action testing | Docker Desktop / OrbStack | Docker Desktop | Docker Engine |
| Claude Code | the builder | see docs.claude.com (Claude Code → setup) | same | same |

Make sure `$(go env GOPATH)/bin` is on your PATH so `gopls` is found.

Check everything:
```
git --version && go version && gh --version && jq --version && gopls version && golangci-lint --version && goreleaser --version && syft version && docker --version
```

## 2. Accounts and secrets

1. Create the GitHub repo: `gh repo create patchtacio --public --source . --push`
2. Create a **fine-grained personal access token** limited to the patchtacio repo
   (contents, issues, pull requests, actions: read/write; code scanning alerts: read).
3. Request a free **NVD API key**.
4. Copy `.env.example` to `.env` and fill it in, or export the variables in your shell profile.
   `.env` is git-ignored. Never paste keys into a chat.

Claude Code reads `${GITHUB_PAT}` from your **environment**, so the variable must be set in the
shell you launch `claude` from:
- macOS/Linux: add `export GITHUB_PAT=...` to `~/.zshrc` or `~/.bashrc`
- Windows (PowerShell): `setx GITHUB_PAT "..."`, then open a new terminal

## 3. MCP servers

The repo's `.mcp.json` already defines three servers. Claude Code asks you to approve
project MCP servers the first time you open the folder, so say yes.

| Server | What Claude Code uses it for |
|---|---|
| `github` | issues, PRs, Actions runs, code-scanning alerts (checks our SARIF shows up) |
| `context7` | up-to-date docs for Syft, cyclonedx-go, go-sarif, GoReleaser, cobra |
| `gopls` | accurate Go symbol search, references, diagnostics (experimental gopls feature) |

Check status inside Claude Code with `/mcp`.

If you'd rather add them manually (user scope, all projects):
```
claude mcp add --transport http github https://api.githubcopilot.com/mcp/ --header "Authorization: Bearer $GITHUB_PAT"
claude mcp add --transport http context7 https://mcp.context7.com/mcp
claude mcp add gopls -- gopls mcp
```

**Add later (milestone M5, local web UI):** Playwright MCP, so Claude Code can click through the UI:
```
claude mcp add playwright -- npx @playwright/mcp@latest
```

If a server fails to connect, check its official README for the current URL/command.
`gopls mcp` needs a recent gopls; update it with the `go install` line above.

## 4. Skills, agent, and hooks (already in the repo)

Nothing to install. Claude Code loads these automatically from `.claude/`:

- `.claude/skills/*/SKILL.md`: add-catalog-product, new-feed-adapter, cross-platform,
  alert-writing, output-formats
- `.claude/agents/security-reviewer.md`: view with `/agents`
- `.claude/settings.json`: hooks (gofmt after edits; build + vet before finishing)

To confirm, ask Claude Code: *"Which skills and agents can you see in this project?"*

**Optional:** Anthropic's `skill-creator` skill (github.com/anthropics/skills) helps you write
and improve skills as the project grows.

## 5. First run

```
cd patchtacio
claude
```
Then:
> Read CLAUDE.md and docs/ROADMAP.md, then complete milestone M0. Stop and show me the result before starting M1.
