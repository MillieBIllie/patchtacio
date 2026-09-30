---
description: Implement one ROADMAP milestone end to end, verify it, and stop for review.
argument-hint: "<milestone, e.g. M0>"
---

Implement milestone **$ARGUMENTS** from docs/ROADMAP.md.

1. Read CLAUDE.md and the milestone's tasks and "done when" line. Read any skills that apply.
2. Write a short plan (files to create, tests to write, open questions) and **wait for my OK**.
3. Implement in small steps. Commit after each logical step (Conventional Commits).
   Use Context7 before writing code against third-party libraries.
4. Verify: `go build ./...`, `go vet ./...`, `go test ./...`, `golangci-lint run`, plus the
   milestone's own "done when" check. For M0, also run `goreleaser release --snapshot --clean`
   and confirm 6 binaries in `dist/`.
5. Run the `security-reviewer` agent on the diff and fix anything Critical or High.
6. Push, then use the `github` MCP server (or `gh run watch`) to confirm CI passes on
   ubuntu, windows, and macos. Fix failures.
7. Tick the completed boxes in docs/ROADMAP.md and commit.
8. **Stop.** Give me: what was built, how to try it myself (exact commands), test/CI results,
   anything you were unsure about, and suggested follow-ups. Do not start the next milestone.
