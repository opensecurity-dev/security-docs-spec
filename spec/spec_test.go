package spec_test

import (
	"strings"
	"testing"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

const example = "../examples/example-notes/security-docs.json"

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := spec.ParseBytes([]byte(`{"schemaVersion":"0.1","organisation":{}}`))
	if err == nil || !strings.Contains(err.Error(), "organisation") {
		t.Fatalf("want unknown-field error naming the key, got %v", err)
	}
}

func TestLoadExampleRoundTrips(t *testing.T) {
	set, err := spec.Load(example)
	if err != nil {
		t.Fatal(err)
	}
	b, err := spec.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	again, err := spec.ParseBytes(b)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if again.Product.Name != "Example Notes" || len(again.Documents.List()) != 6 {
		t.Fatalf("round trip lost data: %+v", again.Product)
	}
}

func TestAllows(t *testing.T) {
	tests := []struct {
		audience, v spec.Visibility
		want        bool
	}{
		{spec.VisibilityPublic, "", true},
		{spec.VisibilityPublic, spec.VisibilityNDA, false},
		{spec.VisibilityPublic, spec.VisibilityInternal, false},
		{spec.VisibilityNDA, spec.VisibilityNDA, true},
		{spec.VisibilityNDA, spec.VisibilityInternal, false},
		{spec.VisibilityInternal, spec.VisibilityInternal, true},
	}
	for _, tt := range tests {
		if got := tt.audience.Allows(tt.v); got != tt.want {
			t.Errorf("%s.Allows(%q) = %v, want %v", tt.audience, tt.v, got, tt.want)
		}
	}
}

func TestForAudienceStripsWhatTheAudienceMayNotSee(t *testing.T) {
	set, err := spec.Load(example)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := set.ForAudience(spec.VisibilityPublic)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range pub.Documents.SecurityOverview.Sections {
		if s.ID == "internal-risks" {
			t.Error("internal section kept for the public")
		}
		for _, p := range s.Practices {
			if p.ID == "sandboxing" {
				t.Error("NDA practice kept for the public")
			}
		}
	}
	if pub.Facts.Hosting.Notes != "" || pub.Facts.Hosting.Source != nil {
		t.Error("internal notes or source kept for the public")
	}
	for _, e := range pub.Facts.Encryption.Evidence {
		if !e.Public {
			t.Errorf("non-public evidence %q kept", e.Ref)
		}
	}
	if pub.Documents.SecurityOverview.Owner != "" {
		t.Error("document owner kept for the public")
	}
	// The original is untouched.
	if set.Facts.Hosting.Notes == "" {
		t.Error("ForAudience modified the original set")
	}
	if _, err := set.ForAudience("everyone"); err == nil {
		t.Error("unknown audience accepted")
	}
}

func TestExpand(t *testing.T) {
	set := spec.Scaffold("Example Co", "Example Notes")
	set.Contacts.Security.Email = "security@example.com"
	vals := set.Placeholders()
	got := spec.Expand("{{ product.name }} by {{org.name}}: [mail]({{contact.security}}) see {{doc.subprocessors}} {{nope}}", vals)
	want := "Example Notes by Example Co: [mail](mailto:security@example.com) see subprocessors.md {{nope}}"
	if got != want {
		t.Fatalf("Expand =\n%q\nwant\n%q", got, want)
	}
	if keys := spec.PlaceholderKeys("{{a.b}} x {{ c }}"); len(keys) != 2 || keys[0] != "a.b" || keys[1] != "c" {
		t.Fatalf("PlaceholderKeys = %v", keys)
	}
}

func TestDocURL(t *testing.T) {
	for base, want := range map[string]string{
		"https://x.example/policies":  "https://x.example/policies/a",
		"https://x.example/policies/": "https://x.example/policies/a",
		"":                            "",
	} {
		if got := (spec.Publication{BaseURL: base}).DocURL("a"); got != want {
			t.Errorf("DocURL(%q) = %q, want %q", base, got, want)
		}
	}
}
