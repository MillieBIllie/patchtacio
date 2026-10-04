//go:build darwin

package ui

import (
	"fmt"
	"os/exec"
)

// openBrowser runs /usr/bin/open with the link as its one argument.
func openBrowser(u string) error {
	cmd := exec.Command("/usr/bin/open", u) //nolint:gosec // fixed program; u is our own checked link
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open the browser: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
