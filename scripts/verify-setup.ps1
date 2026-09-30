# Patchtacio setup checker for Windows PowerShell. Read-only. Never prints secret values.
# Usage: powershell -ExecutionPolicy Bypass -File scripts/verify-setup.ps1 [-Online]
param([switch]$Online)
$script:fails = 0; $script:warns = 0
function Pass($m) { Write-Host "  [PASS] $m" -ForegroundColor Green }
function Fail($m) { Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:fails++ }
function Warn($m) { Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:warns++ }
function Tool($name, $level, $vargs, $hint) {
  if (Get-Command $name -ErrorAction SilentlyContinue) {
    $v = (& $name @vargs 2>&1 | Select-Object -First 1); Pass "${name}: $v"
  } elseif ($level -eq 'req') { Fail "$name not found. $hint" }
  else { Warn "$name not found (needed in a later milestone). $hint" }
}

Write-Host "== Toolchain"
Tool git 'req' @('--version') 'Install Git for Windows (includes Git Bash).'
Tool go 'req' @('version') 'Install Go from go.dev/dl or: winget install GoLang.Go'
Tool gh 'req' @('--version') 'winget install GitHub.cli'
Tool jq 'req' @('--version') 'winget install jqlang.jq'
Tool gopls 'req' @('version') 'go install golang.org/x/tools/gopls@latest'
Tool golangci-lint 'req' @('--version') 'scoop install golangci-lint'
Tool goreleaser 'req' @('--version') 'scoop install goreleaser'
Tool claude 'req' @('--version') 'Install Claude Code: docs.claude.com'
Tool syft 'opt' @('version') 'Phase 2: scoop install syft'
Tool docker 'opt' @('--version') 'Phase 2: Docker Desktop'

if (Get-Command gh -ErrorAction SilentlyContinue) {
  gh auth status *> $null
  if ($LASTEXITCODE -eq 0) { Pass 'gh is logged in' } else { Fail 'gh not logged in. Run: gh auth login' }
}

Write-Host "== Secrets (values are never shown)"
foreach ($v in 'GITHUB_PAT', 'NVD_API_KEY') {
  if ([Environment]::GetEnvironmentVariable($v)) { Pass "$v is set" }
  else { Fail "$v is not set in this terminal. See docs/GETTING-STARTED.md step 6" }
}

if ($Online) {
  Write-Host "== Online checks"
  if ($env:GITHUB_PAT) {
    try { $r = Invoke-RestMethod -Headers @{ Authorization = "Bearer $env:GITHUB_PAT" } -Uri https://api.github.com/user
          Pass "GITHUB_PAT works (user: $($r.login))" } catch { Fail "GITHUB_PAT rejected by GitHub" }
  }
  if ($env:NVD_API_KEY) {
    try { Invoke-WebRequest -UseBasicParsing -Headers @{ apiKey = $env:NVD_API_KEY } -Uri 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1' | Out-Null
          Pass 'NVD_API_KEY works' } catch { Fail 'NVD API rejected the key (not activated yet? check your email)' }
  }
  foreach ($u in 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'https://endoflife.date/api/go.json') {
    try { Invoke-WebRequest -UseBasicParsing -Method Head -Uri $u | Out-Null; Pass "reachable: $u" } catch { Warn "could not reach $u" }
  }
}

Write-Host "== Repository"
git rev-parse --is-inside-work-tree *> $null
if ($LASTEXITCODE -eq 0) {
  Pass 'inside a git repo'
  git ls-files --error-unmatch .env *> $null
  if ($LASTEXITCODE -eq 0) { Fail '.env is tracked by git! Run: git rm --cached .env' } else { Pass '.env is not tracked' }
} else { Warn 'not a git repo yet (run /bootstrap)' }
if (Select-String -Path CLAUDE.md -Pattern 'github.com/OWNER' -Quiet) { Warn 'placeholder OWNER still present (run /bootstrap)' } else { Pass 'OWNER placeholder replaced' }
$n = (Get-ChildItem .claude/skills -Directory -ErrorAction SilentlyContinue).Count
if ($n -ge 5) { Pass "$n project skills present" } else { Fail "expected 5 skills, found $n" }
try { Get-Content .mcp.json -Raw | ConvertFrom-Json | Out-Null; Pass '.mcp.json valid' } catch { Fail '.mcp.json missing or invalid' }

Write-Host ""
Write-Host "Result: $script:fails failed, $script:warns warnings"
if ($script:fails -eq 0) { Write-Host 'READY' } else { Write-Host 'NOT READY' }
exit $script:fails
