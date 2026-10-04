//go:build !windows && !darwin

package ui

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// openBrowser runs xdg-open (from PATH, like systemctl and crontab in
// internal/schedule) with the link as its one argument. Some browsers keep
// xdg-open waiting, so it is not waited for.
func openBrowser(u string) error {
	prog, err := exec.LookPath("xdg-open")
	if err != nil {
		return errors.New("xdg-open is not installed, so the browser cannot be opened for you")
	}
	cmd := exec.CommandContext(context.Background(), prog, u) //nolint:gosec // xdg-open from PATH; u is our own checked link. Not cancelled: it must outlive the request.
	cmd.Env = browserEnv()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open the browser: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
