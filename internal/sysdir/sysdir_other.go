//go:build !windows

package sysdir

import "errors"

// System returns the Windows system directory; there is none here.
func System() (string, error) {
	return "", errors.New("no Windows system directory on this operating system")
}
