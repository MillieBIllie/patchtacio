//go:build darwin

package ui

import (
	"context"
	"fmt"
	"os/exec"
)

// openBrowser runs /usr/bin/open with the link as its one argument.
func openBrowser(u string) error {
	cmd := exec.CommandContext(context.Background(), "/usr/bin/open", u) //nolint:gosec // fixed program; u is our own checked link
	cmd.Env = browserEnv()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open the browser: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
