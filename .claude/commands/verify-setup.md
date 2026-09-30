---
description: Check that this machine and repo are ready to build Patchtacio (tools, secrets, MCP servers, skills). Read-only.
---

Verify the Patchtacio development setup. **Do not install, edit, or commit anything.**

1. Detect the OS. Run `bash scripts/verify-setup.sh --online`. On Windows, if bash isn't
   available, run `powershell -ExecutionPolicy Bypass -File scripts/verify-setup.ps1 -Online`.
2. Check the MCP servers from inside this session, one harmless read-only call each:
   - `github`: get the authenticated user (report the login only).
   - `context7`: resolve the library ID for "spf13/cobra".
   - `gopls`: if `go.mod` exists, request workspace diagnostics; otherwise report "N/A until M0".
   If a server isn't available to you, say so. Don't guess.
3. State which **project skills** (add-catalog-product, new-feed-adapter, cross-platform,
   alert-writing, output-formats) and which **agents** (security-reviewer) you can actually use
   in this session, based on what's loaded, not just what's in the folder.
4. Report a table: **Item | Status | How to fix**. Mark each fix as either
   "Claude can do it (/bootstrap)" or "You must do it" (creating tokens, activating the NVD key,
   `gh auth login`, approving MCP servers, restarting the terminal, installing Docker Desktop).
5. End with exactly one line: `READY FOR M0` or `NOT READY: <n> items left`.

Rules: never print, echo, or write secret values; never open or read `.env`.
