// Command gen writes security-docs.schema.json from the Go types.
package main

import (
	"log"
	"os"

	"github.com/opensecurity-dev/security-docs-spec/schema"
)

func main() {
	b, err := schema.Generate()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("security-docs.schema.json", b, 0o644); err != nil { //nolint:gosec // a schema file is meant to be world-readable
		log.Fatal(err)
	}
}
