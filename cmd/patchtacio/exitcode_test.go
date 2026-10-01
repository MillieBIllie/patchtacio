package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExitCodeFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, exitOK},
		{"plain error", errors.New("boom"), exitToolError},
		{"findings", &exitError{code: exitFindings}, exitFindings},
		{"stale", &exitError{code: exitStale}, exitStale},
		{"wrapped stale", fmt.Errorf("feeds update: %w", &exitError{code: exitStale}), exitStale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeFor(tt.err); got != tt.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestUnknownCommandIsToolError(t *testing.T) {
	_, err := run(t, "no-such-command")
	if got := exitCodeFor(err); got != exitToolError {
		t.Errorf("exit code = %d, want %d (err: %v)", got, exitToolError, err)
	}
}

func TestHelpDocumentsExitCodes(t *testing.T) {
	out, err := run(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}
	if !strings.Contains(out, exitCodesHelp) {
		t.Errorf("--help is missing the exit code table:\n%s", out)
	}
}
