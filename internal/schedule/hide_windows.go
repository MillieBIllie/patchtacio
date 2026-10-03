package schedule

import (
	"os/exec"
	"syscall"
)

// createNoWindow is CREATE_NO_WINDOW: a console program started from the
// windowless patchtaciow.exe would otherwise open its own console window.
const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
