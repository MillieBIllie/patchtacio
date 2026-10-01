// Package testutil holds helpers shared by tests.
package testutil

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Golden compares v, encoded as indented JSON, with the golden file at path.
// Run `go test ./... -update` to rewrite golden files after a deliberate change.
func Golden(t *testing.T, path string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := buf.Bytes()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(filepath.Clean(path)) // fixture path chosen by the test
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s; run `go test -update` if the change is intended.\n--- got (first 2 KB) ---\n%.2048s", path, got)
	}
}

// ReadFile reads a fixture or fails the test.
func ReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path)) // fixture path chosen by the test
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}
