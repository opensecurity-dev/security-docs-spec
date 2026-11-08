// Package render turns a DocumentSet into Markdown files, one per document,
// suitable for a static site or for Pandoc to convert to DOCX or PDF.
package render

import (
	"fmt"
	"slices"
	"strings"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

// Options control rendering.
type Options struct {
	// Audience is the widest visibility rendered. Defaults to public.
	Audience spec.Visibility
	// Draft renders unassessed (todo) claims and not-applicable ones with
	// visible markers, for review. Without it they are left out.
	Draft bool
	// HideGaps leaves out the gap text of partial and planned claims. By
	// default gaps are published as gaps.
	HideGaps bool
	// FrontMatter writes YAML front matter (title, description, date) for
	// Pandoc and static-site generators, instead of a Markdown title.
	FrontMatter bool
	// Only limits output to these slugs. Empty renders every document.
	Only []string
	// LinkJSON makes the index link to the machine-readable copy (ExportName).
	LinkJSON bool
}

// File is one rendered document.
type File struct {
	// Name is the file name, such as "security-overview.md".
	Name    string
	Slug    string
	Title   string
	Content string
}

// Render renders every document the audience may see, plus an index.
func Render(set *spec.DocumentSet, opts Options) ([]File, error) {
	if opts.Audience == "" {
		opts.Audience = spec.VisibilityPublic
	}
	view, err := set.ForAudience(opts.Audience)
	if err != nil {
		return nil, err
	}
	r := &renderer{set: view, opts: opts, values: view.Placeholders()}
	var files []File
	for _, ref := range view.Documents.List() {
		if len(opts.Only) > 0 && !slices.Contains(opts.Only, ref.Slug()) {
			continue
		}
		files = append(files, File{
			Name:    ref.Slug() + ".md",
			Slug:    ref.Slug(),
			Title:   r.x(ref.Meta.Title),
			Content: r.document(ref),
		})
	}
	if len(opts.Only) == 0 {
		files = append(files, File{Name: "index.md", Slug: "index", Title: "Security", Content: r.index(view.Documents.List())})
	}
	return files, nil
}

// Combine joins rendered files into one Markdown document, for a single
// DOCX or PDF. Each document's title is a top-level heading and its
// sections stay second-level.
func Combine(set *spec.DocumentSet, files []File, frontMatter bool) string {
	var b strings.Builder
	title := set.Product.Name + " Security"
	if frontMatter {
		fmt.Fprintf(&b, "---\ntitle: %s\nsubtitle: %s\n---\n\n", yamlString(title), yamlString(set.Organization.Name))
	} else {
		fmt.Fprintf(&b, "# %s\n\n", title)
	}
	for _, f := range files {
		if f.Slug == "index" {
			continue
		}
		body := stripTitle(f.Content)
		fmt.Fprintf(&b, "# %s\n\n%s\n", f.Title, body)
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

type renderer struct {
	set    *spec.DocumentSet
	opts   Options
	values map[string]string
}

// x expands placeholders in prose.
func (r *renderer) x(s string) string { return spec.Expand(s, r.values) }

// shown reports whether a claim is rendered, and the note that goes with it.
func (r *renderer) shown(c spec.Claim) (bool, string) {
	switch c.Status {
	case spec.StatusImplemented, spec.StatusAlternative:
		return true, ""
	case spec.StatusPartial:
		return true, r.gapNote("In progress", c)
	case spec.StatusPlanned:
		return true, r.gapNote("Planned", c)
	case spec.StatusNotApplicable:
		if r.opts.Draft {
			return true, "> **Not applicable:** " + r.x(c.Justification)
		}
		return false, ""
	default: // todo or unset
		if r.opts.Draft {
			return true, "> **TODO:** not yet assessed."
		}
		return false, ""
	}
}

func (r *renderer) gapNote(label string, c spec.Claim) string {
	if r.opts.HideGaps || c.Gap == "" {
		return "> **" + label + ".**"
	}
	return "> **" + label + ":** " + r.x(c.Gap)
}

func (r *renderer) header(b *strings.Builder, m *spec.DocMeta) {
	if r.opts.FrontMatter {
		b.WriteString("---\n")
		fmt.Fprintf(b, "title: %s\n", yamlString(r.x(m.Title)))
		if m.Description != "" {
			fmt.Fprintf(b, "description: %s\n", yamlString(r.x(m.Description)))
		}
		if m.LastUpdated != "" {
			fmt.Fprintf(b, "date: %s\n", yamlString(m.LastUpdated))
		}
		b.WriteString("---\n\n")
	} else {
		fmt.Fprintf(b, "# %s\n\n", r.x(m.Title))
	}
	if m.LastUpdated != "" {
		fmt.Fprintf(b, "*Last updated: %s*\n\n", m.LastUpdated)
	}
	if r.opts.Draft {
		b.WriteString("> **DRAFT** — includes unassessed and not-applicable items. Do not publish.\n\n")
	}
}

func (r *renderer) para(b *strings.Builder, s string) {
	if s = strings.TrimSpace(r.x(s)); s != "" {
		b.WriteString(s)
		b.WriteString("\n\n")
	}
}

func (r *renderer) document(ref spec.DocRef) string {
	var b strings.Builder
	r.header(&b, ref.Meta)
	switch d := ref.Doc.(type) {
	case *spec.SecurityOverview:
		r.para(&b, d.Intro)
		r.sections(&b, d.Sections)
	case *spec.SecurityResponse:
		r.securityResponse(&b, d)
	case *spec.Subprocessors:
		r.subprocessors(&b, d)
	case *spec.DataHandling:
		r.para(&b, d.Intro)
		r.sections(&b, d.Sections)
	case *spec.IncidentResponse:
		r.incidentResponse(&b, d)
	case *spec.Availability:
		r.availability(&b, d)
	case *spec.CustomDocument:
		r.para(&b, d.Intro)
		r.sections(&b, d.Sections)
	}
	r.footer(&b)
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func (r *renderer) footer(b *strings.Builder) {
	if u := r.set.Organization.PolicyHistoryURL; u != "" {
		fmt.Fprintf(b, "---\n\nThe history of changes to this document is [public](%s).\n", u)
	}
}

func (r *renderer) sections(b *strings.Builder, ss []spec.Section) {
	for _, s := range ss {
		var body strings.Builder
		r.para(&body, s.Intro)
		if s.Include != "" {
			r.include(&body, s.Include)
		}
		r.practices(&body, s.Practices)
		r.para(&body, s.Outro)
		if body.Len() == 0 {
			continue // nothing the audience may see
		}
		fmt.Fprintf(b, "## %s\n\n%s", r.x(s.Title), body.String())
	}
}

func (r *renderer) practices(b *strings.Builder, ps []spec.Practice) {
	for _, p := range ps {
		ok, note := r.shown(p.Claim)
		if !ok {
			continue
		}
		stmt := strings.TrimSpace(r.x(p.Statement))
		switch {
		case p.Title != "" && stmt != "":
			fmt.Fprintf(b, "**%s.** %s\n\n", strings.TrimSuffix(r.x(p.Title), "."), stmt)
		case p.Title != "":
			fmt.Fprintf(b, "**%s.**\n\n", strings.TrimSuffix(r.x(p.Title), "."))
		case stmt != "":
			fmt.Fprintf(b, "%s\n\n", stmt)
		}
		r.evidence(b, p.Evidence)
		if note != "" {
			b.WriteString(note + "\n\n")
		}
	}
}

func (r *renderer) evidence(b *strings.Builder, ev []spec.EvidenceRef) {
	var links []string
	for _, e := range ev {
		if !e.Public || !strings.HasPrefix(e.Ref, "http") {
			continue
		}
		label := e.Description
		if label == "" {
			label = e.Ref
		}
		links = append(links, fmt.Sprintf("[%s](%s)", label, e.Ref))
	}
	if len(links) > 0 {
		fmt.Fprintf(b, "Evidence: %s.\n\n", strings.Join(links, ", "))
	}
}

func (r *renderer) index(refs []spec.DocRef) string {
	var b strings.Builder
	title := r.set.Product.Name + " security"
	if r.opts.FrontMatter {
		fmt.Fprintf(&b, "---\ntitle: %s\n---\n\n", yamlString(title))
	} else {
		fmt.Fprintf(&b, "# %s\n\n", title)
	}
	fmt.Fprintf(&b, "Security documentation for %s, published by %s.\n\n", r.set.Product.Name, r.set.Organization.Name)
	for _, ref := range refs {
		line := fmt.Sprintf("- [%s](%s.md)", r.x(ref.Meta.Title), ref.Slug())
		if ref.Meta.Description != "" {
			line += ": " + strings.TrimSpace(r.x(ref.Meta.Description))
		}
		b.WriteString(line + "\n")
	}
	if r.opts.LinkJSON {
		fmt.Fprintf(&b, "\nThis information is also available as [JSON](%s).\n", ExportName)
	}
	if c := r.set.Contacts.Security; c != nil {
		fmt.Fprintf(&b, "\nReport a security concern: %s.\n", contactText(c))
	}
	return b.String()
}

func contactText(c *spec.Contact) string {
	if c.Email != "" {
		return fmt.Sprintf("[%s](mailto:%s)", c.Email, c.Email)
	}
	return fmt.Sprintf("<%s>", c.URL)
}

// yamlString quotes a YAML scalar.
func yamlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ").Replace(s) + `"`
}

// stripTitle removes a leading H1 or YAML front matter from a rendered file.
func stripTitle(s string) string {
	if strings.HasPrefix(s, "---\n") {
		if i := strings.Index(s[4:], "\n---\n"); i >= 0 {
			return strings.TrimLeft(s[4+i+5:], "\n")
		}
	}
	if strings.HasPrefix(s, "# ") {
		if i := strings.Index(s, "\n"); i >= 0 {
			return strings.TrimLeft(s[i+1:], "\n")
		}
	}
	return s
}
