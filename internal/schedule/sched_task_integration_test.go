//go:build integration && windows

package schedule

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/milliebillie/patchtacio/internal/sysdir"
)

// TestTaskSchedulerAcceptsDefinition registers a real task from the
// generated definition (under its own name, running whoami), checks the
// settings Windows stored, starts it, and deletes it.
//
//	go test -tags integration -run TaskScheduler ./internal/schedule/
func TestTaskSchedulerAcceptsDefinition(t *testing.T) {
	o, err := DefaultOptions(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o.SystemDir = "" // no conhost: register the program itself
	w := &Windows{O: o, Name: fmt.Sprintf("Patchtacio integration test (%d)", os.Getpid())}
	ctx := context.Background()
	t.Cleanup(func() { _, _ = w.Uninstall(ctx) })

	sys, err := sysdir.System()
	if err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(sys, "whoami.exe")
	if _, err := w.Install(ctx, Job{Program: prog, Args: []string{"/user"}, Hour: 3, Minute: 7}); err != nil {
		t.Fatal(err)
	}
	st, err := w.Status(ctx)
	if err != nil || !st.Installed {
		t.Fatalf("status after install: %+v %v", st, err)
	}
	out, err := ExecRunner(ctx, nil, "schtasks", "/Query", "/TN", w.Name, "/XML")
	if err != nil {
		t.Fatal(err)
	}
	stored := string(out)
	for _, want := range []string{
		"<StartWhenAvailable>true</StartWhenAvailable>",
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
		"<LogonType>InteractiveToken</LogonType>",
		"<ExecutionTimeLimit>PT30M</ExecutionTimeLimit>",
		"T03:07:00</StartBoundary>",
		"whoami.exe</Command>",
	} {
		if !strings.Contains(stored, want) {
			t.Errorf("stored task lacks %s:\n%s", want, stored)
		}
	}
	if err := w.RunNow(ctx); err != nil {
		t.Fatal(err)
	}
	removed, err := w.Uninstall(ctx)
	if err != nil || len(removed) != 1 {
		t.Fatalf("uninstall: %q %v", removed, err)
	}
	if st, _ := w.Status(ctx); st.Installed {
		t.Error("task still there after uninstall")
	}
}
