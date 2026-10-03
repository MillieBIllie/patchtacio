package sysdir

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// System returns the Windows system directory.
func System() (string, error) {
	d, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("find the Windows system directory: %w", err)
	}
	return d, nil
}
