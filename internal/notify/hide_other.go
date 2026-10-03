//go:build !windows

package notify

import "os/exec"

func hideWindow(*exec.Cmd) {}
