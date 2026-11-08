// Package schema holds the JSON Schema for the security documentation IR,
// generated from the Go types in package spec. Run `go generate ./schema`
// after changing them.
package schema

import _ "embed"

//go:generate go run ./gen

// JSON is the generated schema for spec.DocumentSet.
//
//go:embed security-docs.schema.json
var JSON []byte
