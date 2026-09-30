#!/usr/bin/env bash
# Patchtacio setup checker (macOS, Linux, Git Bash on Windows).
# Read-only. Never prints secret values.
# Usage: scripts/verify-setup.sh [--online]
set -u
ONLINE=0; [ "${1:-}" = "--online" ] && ONLINE=1
fails=0; warns=0
pass(){ printf '  [PASS] %s\n' "$1"; }
fail(){ printf '  [FAIL] %s\n' "$1"; fails=$((fails+1)); }
warn(){ printf '  [WARN] %s\n' "$1"; warns=$((warns+1)); }
have(){ command -v "$1" >/dev/null 2>&1; }
tool(){ # name level "version command" hint
  if have "$1"; then pass "$1: $(eval "$3" 2>&1 | head -n1)"
  elif [ "$2" = req ]; then fail "$1 not found. $4"
  else warn "$1 not found (needed in a later milestone). $4"; fi
}

echo "== Toolchain"
tool git           req "git --version"            "Install Git (Windows: Git for Windows, includes Git Bash)."
tool go            req "go version"               "Install Go from go.dev/dl."
tool gh            req "gh --version"             "Install GitHub CLI: cli.github.com"
tool jq            req "jq --version"             "Install jq (used by Claude Code hooks)."
tool gopls         req "gopls version"            "go install golang.org/x/tools/gopls@latest"
tool golangci-lint req "golangci-lint --version"  "See golangci-lint.run/welcome/install"
tool goreleaser    req "goreleaser --version"     "See goreleaser.com/install"
tool curl          req "curl --version"           "Install curl."
tool claude        req "claude --version"         "Install Claude Code: docs.claude.com"
tool syft          opt "syft version"             "Phase 2. See github.com/anchore/syft"
tool docker        opt "docker --version"         "Phase 2. Docker Desktop / Docker Engine"

if have go; then
  v=$(go env GOVERSION | sed 's/^go//'); major=${v%%.*}; rest=${v#*.}; minor=${rest%%[!0-9]*}
  if [ "${major:-0}" -gt 1 ] || [ "${minor:-0}" -ge 23 ]; then pass "Go version $v (>= 1.23)"
  else fail "Go $v is too old; install the latest stable from go.dev/dl"; fi
  gp="$(go env GOPATH)/bin"
  if ! have gopls && { [ -x "$gp/gopls" ] || [ -x "$gp/gopls.exe" ]; }; then
    warn "gopls is in $gp but that folder is not on PATH. Add it to your shell profile."
  fi
fi
if have docker; then
  if docker info >/dev/null 2>&1; then pass "Docker daemon running"; else warn "Docker installed but not running"; fi
fi
if have gh; then
  if gh auth status >/dev/null 2>&1; then pass "gh is logged in"; else fail "gh not logged in. Run: gh auth login"; fi
fi

echo "== Secrets (values are never shown)"
for v in GITHUB_PAT NVD_API_KEY; do
  if [ -n "$(printenv "$v" 2>/dev/null)" ]; then pass "$v is set"
  else fail "$v is not set in this shell. See docs/GETTING-STARTED.md step 6"; fi
done
[ -f .env ] && [ -z "${GITHUB_PAT:-}" ] && warn ".env exists, but Claude Code does not load it. Export the variables in your shell profile."

if [ "$ONLINE" = 1 ] && have curl; then
  echo "== Online checks"
  if [ -n "${GITHUB_PAT:-}" ]; then
    code=$(curl -s -o /tmp/pt_gh.json -w '%{http_code}' -H "Authorization: Bearer $GITHUB_PAT" https://api.github.com/user)
    if [ "$code" = 200 ]; then pass "GITHUB_PAT works (user: $(jq -r .login /tmp/pt_gh.json 2>/dev/null))"
    else fail "GITHUB_PAT rejected by GitHub (HTTP $code)"; fi
    rm -f /tmp/pt_gh.json
  fi
  if [ -n "${NVD_API_KEY:-}" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "apiKey: $NVD_API_KEY" "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1")
    if [ "$code" = 200 ]; then pass "NVD_API_KEY works"; else fail "NVD API returned HTTP $code (key not activated yet? check your email)"; fi
  fi
  for u in "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" "https://endoflife.date/api/go.json"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -L "$u")
    if [ "$code" = 200 ]; then pass "reachable: $u"; else warn "HTTP $code from $u"; fi
  done
fi

echo "== Repository"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  pass "inside a git repo"
  if git remote get-url origin >/dev/null 2>&1; then pass "remote origin: $(git remote get-url origin)"; else warn "no 'origin' remote yet (run /bootstrap)"; fi
  if git ls-files --error-unmatch .env >/dev/null 2>&1; then fail ".env is tracked by git! Run: git rm --cached .env"; else pass ".env is not tracked"; fi
else
  warn "not a git repo yet (run /bootstrap)"
fi
if grep -rqs "github.com/OWNER" CLAUDE.md docs; then warn "placeholder OWNER still present (run /bootstrap)"; else pass "OWNER placeholder replaced"; fi
n=$(ls -d .claude/skills/*/ 2>/dev/null | wc -l | tr -d ' ')
[ "$n" -ge 5 ] && pass "$n project skills present" || fail "expected 5 skills in .claude/skills, found $n"
[ -f .claude/agents/security-reviewer.md ] && pass "security-reviewer agent present" || fail "security-reviewer agent missing"
if have jq; then
  jq -e .mcpServers .mcp.json >/dev/null 2>&1 && pass ".mcp.json valid ($(jq -r '.mcpServers|keys|join(", ")' .mcp.json))" || fail ".mcp.json missing or invalid"
  jq -e . .claude/settings.json >/dev/null 2>&1 && pass ".claude/settings.json valid" || fail ".claude/settings.json invalid"
fi

echo
echo "Result: $fails failed, $warns warnings"
[ "$fails" -eq 0 ] && echo "READY" || echo "NOT READY"
exit "$fails"
