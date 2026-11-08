package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestInitThenLintFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "set.json")
	if _, err := run(t, "init", "--org", "Example Co", "--product", "Example Notes", "-o", path); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "init", "--org", "X", "--product", "Y", "-o", path); err == nil {
		t.Fatal("init overwrote an existing file without --force")
	}
	out, err := run(t, "lint", path)
	if !errors.Is(err, errFindings) {
		t.Fatalf("lint on a scaffold: want errFindings, got %v", err)
	}
	if !strings.Contains(out, "status-todo") {
		t.Fatalf("lint output lacks status-todo:\n%s", out)
	}
	if _, err := run(t, "lint", "--fail-on", "none", path); err != nil {
		t.Fatalf("--fail-on none: %v", err)
	}
}

func TestLintAndRenderExample(t *testing.T) {
	example := "../../examples/example-notes/security-docs.json"
	if _, err := run(t, "lint", "--now", "2026-11-05", "--fail-on", "warning", example); err != nil {
		t.Fatalf("lint example: %v", err)
	}
	out, err := run(t, "lint", "--format", "json", "--now", "2026-11-05", example)
	if err != nil || !strings.Contains(out, `"findings"`) {
		t.Fatalf("lint json: %v\n%s", err, out)
	}
	if _, err := run(t, "render", example, "-o", t.TempDir(), "--audience", "nda"); err != nil {
		t.Fatalf("render: %v", err)
	}
	if _, err := run(t, "render", example, "--audience", "everyone", "-o", t.TempDir()); err == nil {
		t.Fatal("unknown audience accepted")
	}
	dir := t.TempDir()
	if _, err := run(t, "render", example, "--json", "-o", dir); err != nil {
		t.Fatalf("render --json: %v", err)
	}
	if out, err := run(t, "export", example); err != nil || !strings.Contains(out, `"schemaVersion"`) {
		t.Fatalf("export: %v\n%s", err, out)
	}
	if out, err := run(t, "security-txt", example); err != nil || !strings.HasPrefix(out, "Contact: mailto:") {
		t.Fatalf("security-txt: %v\n%s", err, out)
	}
}
