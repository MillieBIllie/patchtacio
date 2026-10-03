package notify

import (
	"os/exec"
	"syscall"
)

// createNoWindow is CREATE_NO_WINDOW. The scheduled check runs as the
// windowless patchtaciow.exe; without this flag Windows PowerShell, a console
// program, would open its own window to show the notification.
const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
