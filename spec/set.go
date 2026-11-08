// Package spec defines the security documentation IR: a DocumentSet holding
// one product's facts and documents, from which the renderer produces
// Markdown and the linter reports what remains to be done.
package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SchemaVersion is the IR version this package reads and writes.
const SchemaVersion = "0.1"

// DocumentSet is one product's security documentation.
type DocumentSet struct {
	// Schema is an optional $schema URL for editors.
	Schema        string       `json:"$schema,omitempty"`
	SchemaVersion string       `json:"schemaVersion"`
	Organization  Organization `json:"organization"`
	Product       Product      `json:"product"`
	Contacts      Contacts     `json:"contacts"`
	// Publication says where the rendered documents are served.
	Publication Publication `json:"publication,omitzero"`
	// Review sets how often documents must be reviewed.
	Review    ReviewPolicy `json:"review,omitzero"`
	Facts     Facts        `json:"facts,omitzero"`
	Documents Documents    `json:"documents"`
}

// Organization is the company that runs the product.
type Organization struct {
	Name      string `json:"name"`
	LegalName string `json:"legalName,omitempty"`
	URL       string `json:"url,omitempty"`
	// PolicyHistoryURL shows the history of changes to these documents.
	PolicyHistoryURL string `json:"policyHistoryUrl,omitempty"`
}

// Product is the service the documents describe.
type Product struct {
	Name        string `json:"name"`
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

// Contacts are the addresses the documents refer to.
type Contacts struct {
	Security *Contact `json:"security,omitempty"`
	Support  *Contact `json:"support,omitempty"`
	Privacy  *Contact `json:"privacy,omitempty"`
	Abuse    *Contact `json:"abuse,omitempty"`
}

// Contact is an email address, a URL, or both.
type Contact struct {
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Link returns a Markdown link target for the contact: mailto first, then URL.
func (c *Contact) Link() string {
	switch {
	case c == nil:
		return ""
	case c.Email != "":
		return "mailto:" + c.Email
	default:
		return c.URL
	}
}

// Publication says where the rendered documents are served.
type Publication struct {
	// BaseURL is the URL the document slugs are relative to, such as
	// "https://example.com/policies/". It makes links in security.txt absolute.
	BaseURL string `json:"baseUrl,omitempty"`
	// SecurityTxtURL is where security.txt is served, for its Canonical field.
	SecurityTxtURL string `json:"securityTxtUrl,omitempty"`
}

// DocURL returns the absolute URL of a slug, or "" when BaseURL is unset.
func (p Publication) DocURL(slug string) string {
	if p.BaseURL == "" {
		return ""
	}
	if !strings.HasSuffix(p.BaseURL, "/") {
		return p.BaseURL + "/" + slug
	}
	return p.BaseURL + slug
}

// ReviewPolicy sets how often documents are reviewed.
type ReviewPolicy struct {
	// IntervalDays after a document's reviewedAt before lint reports it as stale. Defaults to 365.
	IntervalDays int `json:"intervalDays,omitempty"`
}

// Documents holds the documents in the set. A nil document is not produced.
type Documents struct {
	SecurityOverview *SecurityOverview `json:"securityOverview,omitempty"`
	SecurityResponse *SecurityResponse `json:"securityResponse,omitempty"`
	Subprocessors    *Subprocessors    `json:"subprocessors,omitempty"`
	DataHandling     *DataHandling     `json:"dataHandling,omitempty"`
	IncidentResponse *IncidentResponse `json:"incidentResponse,omitempty"`
	Availability     *Availability     `json:"availability,omitempty"`
	Custom           []CustomDocument  `json:"custom,omitempty"`
}

// DocKind identifies a document type.
type DocKind string

const (
	KindSecurityOverview DocKind = "securityOverview"
	KindSecurityResponse DocKind = "securityResponse"
	KindSubprocessors    DocKind = "subprocessors"
	KindDataHandling     DocKind = "dataHandling"
	KindIncidentResponse DocKind = "incidentResponse"
	KindAvailability     DocKind = "availability"
	KindCustom           DocKind = "custom"
)

// DefaultSlugs are the file names used when a document sets no slug.
var DefaultSlugs = map[DocKind]string{
	KindSecurityOverview: "security-overview",
	KindSecurityResponse: "security-response",
	KindSubprocessors:    "subprocessors",
	KindDataHandling:     "data-handling",
	KindIncidentResponse: "incident-response",
	KindAvailability:     "availability",
}

// DocRef is one document in the set, in rendering order.
type DocRef struct {
	Kind DocKind
	// Path is the JSON path to the document, such as "documents.custom[0]".
	Path string
	Meta *DocMeta
	// Doc is the typed document pointer, such as *SecurityOverview.
	Doc any
}

// Slug returns the document's slug, falling back to the default for its kind.
func (r DocRef) Slug() string {
	if r.Meta.Slug != "" {
		return r.Meta.Slug
	}
	return DefaultSlugs[r.Kind]
}

// List returns the set's documents in rendering order.
func (d *Documents) List() []DocRef {
	var refs []DocRef
	if d.SecurityOverview != nil {
		refs = append(refs, DocRef{KindSecurityOverview, "documents.securityOverview", &d.SecurityOverview.DocMeta, d.SecurityOverview})
	}
	if d.SecurityResponse != nil {
		refs = append(refs, DocRef{KindSecurityResponse, "documents.securityResponse", &d.SecurityResponse.DocMeta, d.SecurityResponse})
	}
	if d.Subprocessors != nil {
		refs = append(refs, DocRef{KindSubprocessors, "documents.subprocessors", &d.Subprocessors.DocMeta, d.Subprocessors})
	}
	if d.DataHandling != nil {
		refs = append(refs, DocRef{KindDataHandling, "documents.dataHandling", &d.DataHandling.DocMeta, d.DataHandling})
	}
	if d.IncidentResponse != nil {
		refs = append(refs, DocRef{KindIncidentResponse, "documents.incidentResponse", &d.IncidentResponse.DocMeta, d.IncidentResponse})
	}
	if d.Availability != nil {
		refs = append(refs, DocRef{KindAvailability, "documents.availability", &d.Availability.DocMeta, d.Availability})
	}
	for i := range d.Custom {
		refs = append(refs, DocRef{KindCustom, fmt.Sprintf("documents.custom[%d]", i), &d.Custom[i].DocMeta, &d.Custom[i]})
	}
	return refs
}

// Parse decodes a DocumentSet, rejecting unknown fields so a misspelled key
// is an error rather than a silently missing claim.
func Parse(r io.Reader) (*DocumentSet, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var set DocumentSet
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("spec: decode document set: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("spec: decode document set: trailing data after the JSON object")
	}
	return &set, nil
}

// ParseBytes decodes a DocumentSet from bytes.
func ParseBytes(b []byte) (*DocumentSet, error) {
	return Parse(bytes.NewReader(b))
}

// Load reads a DocumentSet from a file.
func Load(path string) (*DocumentSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("spec: %w", err)
	}
	set, err := ParseBytes(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return set, nil
}

// Marshal encodes a DocumentSet as indented JSON with a trailing newline.
func Marshal(set *DocumentSet) ([]byte, error) {
	b, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("spec: encode document set: %w", err)
	}
	return append(b, '\n'), nil
}
