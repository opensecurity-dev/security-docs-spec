package render_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opensecurity-dev/security-docs-spec/render"
	"github.com/opensecurity-dev/security-docs-spec/spec"
)

var update = flag.Bool("update", false, "rewrite the golden files under examples/")

const dir = "../examples/example-notes"

func load(t *testing.T) *spec.DocumentSet {
	t.Helper()
	set, err := spec.Load(filepath.Join(dir, "security-docs.json"))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func golden(t *testing.T, path, got string) {
	t.Helper()
	path = filepath.Join(dir, path)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./render -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from rendered output; run go test ./render -update and review the diff", path)
	}
}

func TestGoldenPublic(t *testing.T) {
	// Matches `secdocs render --json`: the index links to the JSON export,
	// which TestExportJSONMatchesAudience writes beside it.
	files, err := render.Render(load(t), render.Options{LinkJSON: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 7 {
		t.Fatalf("want 6 documents and an index, got %d files", len(files))
	}
	for _, f := range files {
		golden(t, filepath.Join("public", f.Name), f.Content)
	}
}

func TestGoldenNDASingle(t *testing.T) {
	set := load(t)
	opts := render.Options{Audience: spec.VisibilityNDA, FrontMatter: true}
	files, err := render.Render(set, opts)
	if err != nil {
		t.Fatal(err)
	}
	view, err := set.ForAudience(opts.Audience)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "nda/security-nda.md", render.Combine(view, files, true))
}

func TestGoldenSecurityTxt(t *testing.T) {
	s, err := render.SecurityTxt(load(t))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "public/security.txt", s)
}

// TestNoLeaks checks that content above the audience never reaches output.
func TestNoLeaks(t *testing.T) {
	set := load(t)
	leaks := map[spec.Visibility][]string{
		spec.VisibilityPublic: {"Process isolation", "Known risks", "kernel compromise", "private infrastructure repo", "evidence/", "engineering lead", "infra-inventory"},
		spec.VisibilityNDA:    {"Known risks", "kernel compromise", "private infrastructure repo", "evidence/", "engineering lead"},
	}
	for audience, banned := range leaks {
		files, err := render.Render(set, render.Options{Audience: audience, Draft: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			for _, s := range banned {
				if strings.Contains(f.Content, s) {
					t.Errorf("%s output %s contains %q", audience, f.Name, s)
				}
			}
		}
	}
}

func TestDraftShowsTodo(t *testing.T) {
	set := spec.Scaffold("Example Co", "Example Notes")
	files, err := render.Render(set, render.Options{Draft: true, Only: []string{"security-overview"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !strings.Contains(files[0].Content, "**TODO:**") || !strings.Contains(files[0].Content, "DRAFT") {
		t.Fatalf("draft lacks TODO markers:\n%s", files[0].Content)
	}
	files, err = render.Render(set, render.Options{Only: []string{"security-overview"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(files[0].Content, "TODO") || strings.Contains(files[0].Content, "## Encryption") {
		t.Fatalf("non-draft render shows unassessed claims:\n%s", files[0].Content)
	}
}

func TestHideGaps(t *testing.T) {
	files, err := render.Render(load(t), render.Options{HideGaps: true, Only: []string{"security-overview"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(files[0].Content, "not yet on a fixed schedule") || !strings.Contains(files[0].Content, "> **In progress.**") {
		t.Fatalf("gaps not hidden:\n%s", files[0].Content)
	}
}

func TestExportJSONMatchesAudience(t *testing.T) {
	b, err := render.ExportJSON(load(t), spec.VisibilityPublic, false)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, banned := range []string{"sandboxing", "internal-risks", "private infrastructure repo", "evidence/", "engineering lead"} {
		if strings.Contains(out, banned) {
			t.Errorf("public JSON contains %q", banned)
		}
	}
	if _, err := spec.ParseBytes(b); err != nil {
		t.Fatalf("exported JSON does not parse as a document set: %v", err)
	}
	golden(t, "public/security-docs.json", out)
}

func TestExportJSONRefusesUnassessed(t *testing.T) {
	set := spec.Scaffold("Example Co", "Example Notes")
	if _, err := render.ExportJSON(set, spec.VisibilityPublic, false); err == nil || !strings.Contains(err.Error(), "unassessed") {
		t.Fatalf("want unassessed error, got %v", err)
	}
	if _, err := render.ExportJSON(set, spec.VisibilityPublic, true); err != nil {
		t.Fatalf("draft export: %v", err)
	}
}

func TestSecurityTxtNeedsExpiry(t *testing.T) {
	set := load(t)
	set.Documents.SecurityResponse.SecurityTxtExpires = ""
	if _, err := render.SecurityTxt(set); err == nil {
		t.Fatal("want error without Expires")
	}
}
