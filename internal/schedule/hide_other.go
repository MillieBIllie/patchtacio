//go:build !windows

package schedule

import "os/exec"

func hideWindow(*exec.Cmd) {}
