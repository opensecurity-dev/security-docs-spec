// Package lint reports what a DocumentSet still needs before it can be
// published: invalid values, claims nobody has assessed, gaps without a
// description, unverified public claims, stale reviews and leftover TODOs.
package lint

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

// Severity orders findings. Errors make a set invalid; warnings are work that
// remains before publication; info is advice.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Rank returns a number that is higher for more severe findings.
func (s Severity) Rank() int {
	switch s {
	case SeverityError:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// ParseSeverity parses error, warning, info or none.
func ParseSeverity(s string) (Severity, error) {
	switch v := Severity(s); v {
	case SeverityError, SeverityWarning, SeverityInfo:
		return v, nil
	case "none":
		return "", nil
	}
	return "", fmt.Errorf("lint: unknown severity %q; want error, warning, info or none", s)
}

// Finding is one problem at one JSON path.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Path     string   `json:"path"`
	Message  string   `json:"message"`
}

func (f Finding) String() string {
	return fmt.Sprintf("%-7s %-26s %s: %s", f.Severity, f.Rule, f.Path, f.Message)
}

// Options control a lint run.
type Options struct {
	// Now is the date stale reviews and expiries are measured against. Defaults to time.Now.
	Now time.Time
	// Strict raises unverified public claims from info to warning.
	Strict bool
}

// Report is the result of a lint run.
type Report struct {
	Findings []Finding      `json:"findings"`
	Counts   map[string]int `json:"counts"`
}

// Max returns the most severe finding's severity, or "" when there are none.
func (r Report) Max() Severity {
	var m Severity
	for _, f := range r.Findings {
		if f.Severity.Rank() > m.Rank() {
			m = f.Severity
		}
	}
	return m
}

// Run lints a DocumentSet.
func Run(set *spec.DocumentSet, opts Options) Report {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	l := &linter{set: set, opts: opts, placeholders: set.Placeholders(), ids: map[string]string{}}
	l.run()
	slices.SortStableFunc(l.findings, func(a, b Finding) int { return b.Severity.Rank() - a.Severity.Rank() })
	r := Report{Findings: l.findings, Counts: map[string]int{}}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	for _, f := range r.Findings {
		r.Counts[string(f.Severity)]++
	}
	return r
}

type linter struct {
	set          *spec.DocumentSet
	opts         Options
	placeholders map[string]string
	findings     []Finding
	ids          map[string]string // id -> first path, per scope
}

func (l *linter) add(sev Severity, rule, path, format string, args ...any) {
	l.findings = append(l.findings, Finding{Rule: rule, Severity: sev, Path: path, Message: fmt.Sprintf(format, args...)})
}

func (l *linter) run() {
	s := l.set
	if s.SchemaVersion == "" {
		l.add(SeverityError, "required", "schemaVersion", "schemaVersion is required (current: %s)", spec.SchemaVersion)
	} else if s.SchemaVersion != spec.SchemaVersion {
		l.add(SeverityError, "schema-version", "schemaVersion", "unsupported schemaVersion %q; this tool reads %q", s.SchemaVersion, spec.SchemaVersion)
	}
	l.required("organization.name", s.Organization.Name)
	l.required("product.name", s.Product.Name)
	l.url("organization.url", s.Organization.URL)
	l.url("product.url", s.Product.URL)
	if s.Contacts.Security == nil || (s.Contacts.Security.Email == "" && s.Contacts.Security.URL == "") {
		l.add(SeverityError, "required", "contacts.security", "a security contact (email or URL) is required")
	}
	if s.Review.IntervalDays < 0 {
		l.add(SeverityError, "invalid", "review.intervalDays", "must not be negative")
	}
	l.facts()
	refs := s.Documents.List()
	if len(refs) == 0 {
		l.add(SeverityError, "required", "documents", "the set has no documents")
	}
	slugs := map[string]string{}
	for _, ref := range refs {
		if prev, ok := slugs[ref.Slug()]; ok {
			l.add(SeverityError, "duplicate-slug", ref.Path+".slug", "slug %q is also used by %s", ref.Slug(), prev)
		}
		slugs[ref.Slug()] = ref.Path
		l.document(ref)
	}
}

// --- field helpers ---

func (l *linter) required(path, v string) {
	if strings.TrimSpace(v) == "" {
		l.add(SeverityError, "required", path, "is required")
	}
}

func (l *linter) url(path, v string) {
	if v != "" && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "mailto:") && !strings.HasPrefix(v, "{{") {
		l.add(SeverityError, "invalid-url", path, "%q is not an absolute URL", v)
	}
}

func (l *linter) date(path, v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	l.add(SeverityError, "invalid-date", path, "%q is not a YYYY-MM-DD date or RFC 3339 time", v)
	return time.Time{}, false
}

func (l *linter) id(scope, path, id string) {
	if strings.TrimSpace(id) == "" {
		l.add(SeverityError, "required", path+".id", "is required")
		return
	}
	key := scope + "\x00" + id
	if prev, ok := l.ids[key]; ok {
		l.add(SeverityError, "duplicate-id", path+".id", "id %q is also used at %s", id, prev)
		return
	}
	l.ids[key] = path
}

// controlIDFormats are the ID shapes of the frameworks lint knows.
var controlIDFormats = map[string]*regexp.Regexp{
	spec.FrameworkNIST80053R5: regexp.MustCompile(`^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$`),
	spec.FrameworkFedRAMPKSI:  regexp.MustCompile(`^KSI-[A-Z]{3}-[A-Z0-9]{2,3}$`),
	spec.FrameworkFedRAMPRule: regexp.MustCompile(`^[A-Z]{3}-[A-Z]{3}-[A-Z]{3}$`),
}

var todoMarkers = []string{"TODO", "TBD", "FIXME", "XXX", "[placeholder]"}

// prose checks Markdown text for leftover markers and unknown placeholders.
func (l *linter) prose(path, text string) {
	if text == "" {
		return
	}
	for _, m := range todoMarkers {
		if strings.Contains(text, m) {
			l.add(SeverityWarning, "todo-marker", path, "contains %q", m)
			break
		}
	}
	for _, k := range spec.PlaceholderKeys(text) {
		if _, ok := l.placeholders[k]; !ok {
			l.add(SeverityError, "unknown-placeholder", path, "{{%s}} has no value; check the key or set the field it names", k)
		}
	}
}

func (l *linter) visibility(path string, v spec.Visibility) {
	if v != "" && !slices.Contains(spec.Visibilities, v) {
		l.add(SeverityError, "invalid-enum", path, "visibility %q; want one of %v", v, spec.Visibilities)
	}
}

// claim checks the metadata every claim carries. label names the claim in
// messages, such as a practice's title.
func (l *linter) claim(path, label string, c *spec.Claim, statement string) {
	about := ""
	if label != "" {
		about = " (" + label + ")"
	}
	sp := path + ".status"
	switch {
	case c.Status == "":
		l.add(SeverityWarning, "status-missing", sp, "has no status%s; assess it and set one of %v", about, spec.Statuses)
	case !slices.Contains(spec.Statuses, c.Status):
		l.add(SeverityError, "invalid-enum", sp, "status %q; want one of %v", c.Status, spec.Statuses)
	case c.Status == spec.StatusTodo:
		l.add(SeverityWarning, "status-todo", sp, "not yet assessed%s", about)
	}
	l.visibility(path+".visibility", c.Visibility)
	if c.Verification != "" && !slices.Contains(spec.Verifications, c.Verification) {
		l.add(SeverityError, "invalid-enum", path+".verification", "verification %q; want one of %v", c.Verification, spec.Verifications)
	}
	switch c.Status {
	case spec.StatusPartial, spec.StatusPlanned:
		if strings.TrimSpace(c.Gap) == "" {
			l.add(SeverityError, "gap-required", path+".gap", "a %s claim%s must say what is missing", c.Status, about)
		}
	case spec.StatusNotApplicable:
		if strings.TrimSpace(c.Justification) == "" {
			l.add(SeverityError, "justification-required", path+".justification", "a not-applicable claim%s must say why", about)
		}
	case spec.StatusImplemented, spec.StatusAlternative:
		if c.EffectiveVisibility() != spec.VisibilityInternal && c.EffectiveVerification() == spec.VerificationUnverified {
			sev := SeverityInfo
			if l.opts.Strict {
				sev = SeverityWarning
			}
			l.add(sev, "unverified-claim", path+".verification", "%s claim%s has not been reviewed or verified", c.EffectiveVisibility(), about)
		}
	}
	if c.EffectiveVerification() == spec.VerificationVerified && len(c.Evidence) == 0 {
		l.add(SeverityWarning, "evidence-missing", path+".evidence", "a verified claim%s must cite evidence", about)
	}
	if c.Status == spec.StatusImplemented && statement != "-" && strings.TrimSpace(statement) == "" {
		l.add(SeverityWarning, "statement-empty", path+".statement", "an implemented practice%s needs a statement readers can see", about)
	}
	l.prose(path+".gap", c.Gap)
	l.prose(path+".justification", c.Justification)
	if c.Source != nil {
		l.date(path+".source.collectedAt", c.Source.CollectedAt)
	}
	for i, cr := range c.ControlRefs {
		cp := fmt.Sprintf("%s.controlRefs[%d]", path, i)
		if cr.Framework == "" || cr.Control == "" {
			l.add(SeverityError, "required", cp, "framework and control are required")
			continue
		}
		if re, ok := controlIDFormats[cr.Framework]; ok && !re.MatchString(cr.Control) {
			l.add(SeverityError, "control-id", cp+".control", "%q is not a %s control ID", cr.Control, cr.Framework)
		}
	}
}
