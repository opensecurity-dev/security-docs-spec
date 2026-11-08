package schema

import (
	"encoding/json"
	"fmt"

	"github.com/invopop/jsonschema"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

// ID is the schema's $id.
const ID = "https://github.com/opensecurity-dev/security-docs-spec/schema/security-docs.schema.json"

// Generate builds the JSON Schema for spec.DocumentSet from the Go types. It
// reads field comments from ../spec, so it runs from this directory, as
// go generate and go test do.
func Generate() ([]byte, error) {
	r := &jsonschema.Reflector{
		// Go structs are the source of truth: a field is required only when its
		// JSON tag has no omitempty or omitzero.
		RequiredFromJSONSchemaTags: false,
		DoNotReference:             false,
	}
	if err := r.AddGoComments("github.com/opensecurity-dev/security-docs-spec/schema", "../spec"); err != nil {
		return nil, fmt.Errorf("schema: read Go comments: %w", err)
	}
	s := r.Reflect(&spec.DocumentSet{})
	s.ID = ID
	s.Title = "Security documentation set"
	s.Description = "One product's security documentation: shared facts and typed documents, rendered to Markdown."
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("schema: encode: %w", err)
	}
	return append(b, '\n'), nil
}
