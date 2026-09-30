# Getting started with Patchtacio (step by step)

About 60–90 minutes the first time. The flow:

- **Part A** (you, ~15 min): install Git and Claude Code, and unzip the kit
- **Part B** (Claude Code, ~20 min): `/verify-setup` → `/bootstrap` installs tools and creates the repo
- **Part C** (you, ~15 min): create the GitHub token and NVD key, and set environment variables
- **Part D** (Claude Code): `/verify-setup` again, until it says READY FOR M0
- **Part E** (Claude Code): `/milestone M0`
- **Part F** (you, in parallel): start the product seed list

Anything that involves creating credentials or clicking "approve" stays with you, on purpose.

---

## Part A: Manual essentials

### Step 1: Check the name
1. Search github.com for `patchtacio` (repositories and users).
2. Search pkg.go.dev and formulae.brew.sh for `patchtacio`.
3. Do a web search for "patchtacio" to spot any product or trademark clash.
If it's taken, pick a new name **now**: rename the folder and ask Claude Code in Part B to
replace "patchtacio" everywhere.

### Step 2: Install Git
- **macOS:** run `xcode-select --install` or `brew install git`
- **Windows:** install **Git for Windows** from git-scm.com, keeping the defaults. This includes
  **Git Bash**, which Claude Code and this repo's hooks need on Windows.
- **Linux:** `sudo apt install git` (Debian/Ubuntu) or `sudo dnf install git` (Fedora)

### Step 3: Install Claude Code
Follow the current instructions at docs.claude.com (Claude Code → Quickstart/Setup).
At the time of writing, the native installers are:
- macOS/Linux: `curl -fsSL https://claude.ai/install.sh | bash`
- Windows (PowerShell): `irm https://claude.ai/install.ps1 | iex`

Then run `claude --version`, and run `claude` once to log in.

### Step 4: Unzip the kit
1. Unzip `patchtacio-claude-kit.zip` to where you keep code, e.g. `~/code/patchtacio`.
2. Hidden files (`.claude/`, `.mcp.json`, `.gitignore`) must be there. Check with `ls -a`
   (macOS/Linux) or `dir /a` (Windows).
3. Open a terminal in that folder: `cd ~/code/patchtacio`

---

## Part B: Let Claude Code set up the machine

### Step 5: Verify, then bootstrap
1. Run `claude` inside the folder.
2. When asked to trust the folder and approve the project MCP servers, say **yes**.
   (`github` will fail until Part C. That's expected.)
3. Type: `/verify-setup`
   It runs `scripts/verify-setup.sh` and gives you a table of what's missing.
4. Type: `/bootstrap your-github-username`
   Claude Code proposes install commands, and **you approve each step**. It will:
   - install Go, gh, jq, gopls, golangci-lint, and GoReleaser with your package manager
   - tell you when **you** must run `gh auth login` (a browser login; choose HTTPS and "Login with a web browser")
   - replace the `OWNER` placeholders, create the first commit, and (after asking) create and push the GitHub repo
5. Docker Desktop and Syft are only needed from Phase 2, so you can skip them for now.

> **If slash commands don't appear:** paste this instead:
> "Read `.claude/commands/verify-setup.md` and follow it exactly." (Same for `bootstrap.md`.)

---

## Part C: Credentials (only you can do these)

### Step 6a: GitHub fine-grained token
Do this **after** the repo exists (Step 5), so you can limit the token to it.
1. github.com → your avatar → **Settings** → **Developer settings** → **Personal access tokens** →
   **Fine-grained tokens** → **Generate new token**.
2. Name: `patchtacio-claude-code`. Expiration: 90 days (set a reminder to renew).
3. Repository access: **Only select repositories** → `patchtacio`.
4. Repository permissions:
   - Actions: **Read and write**
   - Code scanning alerts: **Read-only**
   - Contents: **Read and write**
   - Issues: **Read and write**
   - Pull requests: **Read and write**
   - Workflows: **Read and write**
   - Metadata: Read-only (added automatically)
5. Generate the token and copy it. You won't see it again.
(GitHub renames settings sometimes. Pick the closest match.)

### Step 6b: NVD API key
1. Go to nvd.nist.gov/developers/request-an-api-key.
2. Enter your email and organization type, then accept the terms.
3. Open the email NVD sends and **click the activation link**. The key doesn't work until you do.

### Step 6c: Put them in your environment
Claude Code reads these from the terminal you launch it from. Use an editor, not `echo`,
so the secrets don't end up in your shell history.

**macOS (zsh):** `open -e ~/.zshrc` (or `nano ~/.zshrc`), add:
```
export GITHUB_PAT="github_pat_..."
export NVD_API_KEY="..."
```
Save, then **close and reopen the terminal**.

**Linux (bash):** `nano ~/.bashrc`, add the same two lines, save, and reopen the terminal.

**Windows:** press Win+R, type `rundll32 sysdm.cpl,EditEnvironmentVariables`, and press Enter.
Under **User variables**, click **New** and add `GITHUB_PAT` and `NVD_API_KEY`. Click OK, then
**close all terminals** and open a new one.

Never paste these values into Claude, a chat, an issue, or a commit.

---

## Part D: Verify everything

### Step 7: Run the checks again
1. In the new terminal: `cd ~/code/patchtacio && claude`
2. Run `/mcp`. `github`, `context7`, and `gopls` should all show as connected.
   (`gopls` may show errors until `go.mod` exists after M0. That's fine.)
3. Run `/verify-setup`. Repeat any fixes until it ends with **READY FOR M0**.

You can also run the checker yourself without Claude:
- macOS/Linux/Git Bash: `bash scripts/verify-setup.sh --online`
- Windows PowerShell: `powershell -ExecutionPolicy Bypass -File scripts/verify-setup.ps1 -Online`

---

## Part E: Build M0

### Step 8: `/milestone M0`
1. Claude Code reads the roadmap and shows a plan. Read it, ask questions, then say OK.
2. It builds the scaffold and CI, runs tests, runs the security reviewer, pushes, and watches CI.
3. It stops with a summary. Check it yourself:
   - `go run ./cmd/patchtacio version` prints a version
   - GitHub → your repo → **Actions**: the latest run is green on ubuntu, windows, and macos
   - `ls dist/` after the snapshot build shows 6 binaries
4. If you're happy, start a **new session** for M1: `/milestone M1`.

Tip: use `/clear` or a new session between milestones. CLAUDE.md and the roadmap carry the context.

---

## Part F: Product seed list (do this in parallel)

Open `catalog/seed-list.csv` in a spreadsheet and replace the example rows with 20–30 products
that schools, councils, or small businesses actually run. Fill in:
- **product** and **vendor**: as the users call them
- **where_it_runs**: e.g. "edge firewall", "staff laptops"
- **version_if_known**
- **who_told_you**: e.g. "IT lead at X school", "my own guess"

Real input beats guesses. In M2, Claude Code turns this list into catalog entries using the
`add-catalog-product` skill.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `command not found` right after installing | Close and reopen the terminal; check PATH |
| `gopls` not found | Add `$(go env GOPATH)/bin` to PATH (Windows: `%USERPROFILE%\go\bin`) |
| `github` MCP fails | `GITHUB_PAT` isn't set in *this* terminal, or the token lacks access to the repo |
| NVD returns 403/404 | You haven't clicked the activation email yet |
| Hooks error on Windows | Make sure Git for Windows is installed and `jq` is on PATH |
| Slash commands missing | Run `claude` from the repo root; check `.claude/commands/` exists |
| MCP server URL errors | Check that server's official README; URLs change |
