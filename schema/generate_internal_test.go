package schema

import (
	"path/filepath"
	"testing"
)

func TestSlashKeys(t *testing.T) {
	// Built the way AddGoComments builds keys on the current OS.
	in := map[string]string{
		"example.test/m/schema/" + filepath.Join("..", "spec") + ".DocumentSet": "doc",
	}
	got := slashKeys(in)
	if got["example.test/m/spec.DocumentSet"] != "doc" || len(got) != 1 {
		t.Errorf("slashKeys = %v", got)
	}
}
