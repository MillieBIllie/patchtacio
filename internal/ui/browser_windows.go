//go:build windows

package ui

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// openBrowser asks the shell to open the link (ShellExecute), as a click on
// it would: no subprocess, no command line to quote.
func openBrowser(u string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return fmt.Errorf("open the browser: %w", err)
	}
	target, err := windows.UTF16PtrFromString(u)
	if err != nil {
		return fmt.Errorf("open the browser: %w", err)
	}
	if err := windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("open the browser: %w", err)
	}
	return nil
}
