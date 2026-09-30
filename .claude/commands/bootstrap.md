---
description: Install missing dev tools and initialize the Patchtacio repo. Asks before every install and before anything that touches GitHub.
argument-hint: "[github-username]"
---

Bootstrap this machine and repo for Patchtacio. Work step by step and **ask me before running
any install command, any command using sudo/admin, and anything that creates or pushes to GitHub.**

1. **Assess:** run `bash scripts/verify-setup.sh` (or the `.ps1` on Windows without bash).
   List what's missing.
2. **Install plan:** detect the package manager (macOS: brew; Windows: winget, else scoop;
   Linux: apt/dnf/pacman). Show a numbered plan with exact commands, split into
   "required now" and "later (syft, docker)". Wait for my yes.
   - Use `go install golang.org/x/tools/gopls@latest` for gopls.
   - Don't script Docker Desktop or Claude Code installs; tell me to install those myself.
   - Prefer the latest stable Go from go.dev if the distro package is older than 1.23.
3. **PATH:** if `$(go env GOPATH)/bin` isn't on PATH, show me the exact line for my shell profile
   (or the Windows steps). Don't edit my profile without asking.
4. **GitHub login:** if `gh auth status` fails, tell me to run `gh auth login` myself (it's interactive).
5. **Owner:** use `$ARGUMENTS` as my GitHub username, or else `gh api user --jq .login`.
   Replace every `OWNER` placeholder in the repo (`grep -rn "OWNER" .`), then show me the diff.
6. **Git:** if not a repo, `git init -b main`. Confirm `.gitignore` covers `.env` and that `.env`
   isn't staged. Commit with `chore: add project kit`.
7. **Remote:** ask me, then run `gh repo create patchtacio --public --source . --push`.
   If the repo already exists, add it as `origin` and push instead.
8. **Re-verify:** run the checker again and summarize what's left, marking which items only I can do.

Rules: never print, log, or write secret values; never create tokens for me; if any command fails,
stop and show me the error with a suggested fix.
