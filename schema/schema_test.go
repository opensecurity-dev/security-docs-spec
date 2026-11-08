package schema_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/opensecurity-dev/security-docs-spec/schema"
)

func TestEmbeddedSchemaIsCurrent(t *testing.T) {
	got, err := schema.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, schema.JSON) {
		t.Fatal("security-docs.schema.json is stale; run go generate ./schema")
	}
}

func TestSchemaShape(t *testing.T) {
	var s struct {
		Defs map[string]struct {
			Required []string `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(schema.JSON, &s); err != nil {
		t.Fatal(err)
	}
	for _, def := range []string{"DocumentSet", "SecurityOverview", "SecurityResponse", "Subprocessors", "DataHandling", "IncidentResponse", "Availability", "Facts"} {
		if _, ok := s.Defs[def]; !ok {
			t.Errorf("schema lacks $defs.%s", def)
		}
	}
}
