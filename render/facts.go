package render

import (
	"fmt"
	"strings"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

// include renders a fact group as standard sentences, so every document that
// includes it says the same thing.
func (r *renderer) include(b *strings.Builder, in spec.Include) {
	f := &r.set.Facts
	switch in {
	case spec.IncludeHosting:
		if f.Hosting != nil {
			r.hosting(b, f.Hosting)
		}
	case spec.IncludeEncryption:
		if f.Encryption != nil {
			r.encryption(b, f.Encryption)
		}
	case spec.IncludeBackups:
		if f.Backups != nil {
			r.backups(b, f.Backups)
		}
	case spec.IncludeDataLifecycle:
		if f.DataLifecycle != nil {
			r.dataLifecycle(b, f.DataLifecycle)
		}
	case spec.IncludeAccessControl:
		if f.AccessControl != nil {
			r.accessControl(b, f.AccessControl)
		}
	case spec.IncludeIncidentNotification:
		if f.IncidentNotification != nil {
			r.incidentNotification(b, f.IncidentNotification)
		}
	case spec.IncludeLawEnforcement:
		if f.LawEnforcement != nil {
			r.lawEnforcement(b, f.LawEnforcement)
		}
	case spec.IncludeCertifications:
		r.certifications(b, f.Certifications)
	}
}

// group writes bullets for a fact group if its claim is shown.
func (r *renderer) group(b *strings.Builder, c spec.Claim, lead string, bullets []string) {
	ok, note := r.shown(c)
	if !ok {
		return
	}
	r.para(b, lead)
	for _, s := range bullets {
		if s != "" {
			fmt.Fprintf(b, "- %s\n", strings.TrimSpace(r.x(s)))
		}
	}
	if len(nonEmpty(bullets)) > 0 {
		b.WriteString("\n")
	}
	r.evidence(b, c.Evidence)
	if note != "" {
		b.WriteString(note + "\n\n")
	}
}

func (r *renderer) hosting(b *strings.Builder, h *spec.Hosting) {
	var bullets []string
	if len(h.Locations) > 0 {
		bullets = append(bullets, "Customer data is stored in "+locations(h.Locations)+".")
	}
	if len(h.Providers) > 0 {
		bullets = append(bullets, "Infrastructure providers: "+strings.Join(h.Providers, ", ")+".")
	}
	r.group(b, h.Claim, h.Description, bullets)
}

func (r *renderer) encryption(b *strings.Builder, e *spec.Encryption) {
	ok, note := r.shown(e.Claim)
	if !ok {
		return
	}
	if t := e.InTransit; t != nil {
		s := "All data sent between you and {{product.name}} is encrypted with HTTPS"
		if t.MinTLSVersion != "" {
			s += ", using TLS " + t.MinTLSVersion + " or later"
		}
		s += "."
		if t.HSTS {
			s += " HTTP Strict Transport Security (HSTS) tells browsers never to connect without encryption."
		}
		if t.ReportURL != "" {
			s += fmt.Sprintf(" You can [check our TLS configuration](%s).", t.ReportURL)
		}
		r.para(b, s)
		r.para(b, t.Internal)
	}
	if len(e.AtRest) > 0 {
		b.WriteString("| Data | Encrypted at rest | How |\n|---|---|---|\n")
		for _, s := range e.AtRest {
			how := strings.TrimSpace(strings.Join(nonEmpty([]string{s.Method, s.Note}), ". "))
			fmt.Fprintf(b, "| %s | %s | %s |\n", cell(r.x(s.Store)), yesNo(s.Encrypted), cell(r.x(how)))
		}
		b.WriteString("\n")
	}
	if ph := e.PasswordHashing; ph != nil {
		switch {
		case ph.NotApplicable != "":
			r.para(b, ph.NotApplicable)
		case ph.Parameters != "":
			r.para(b, fmt.Sprintf("Passwords are never stored; we store a salted hash made with %s (%s).", ph.Algorithm, ph.Parameters))
		default:
			r.para(b, fmt.Sprintf("Passwords are never stored; we store a salted hash made with %s.", ph.Algorithm))
		}
	}
	r.para(b, e.ApplicationLevel)
	r.evidence(b, e.Evidence)
	if note != "" {
		b.WriteString(note + "\n\n")
	}
}

func (r *renderer) backups(b *strings.Builder, k *spec.Backups) {
	var bullets []string
	if k.Frequency != "" {
		bullets = append(bullets, "Backups are taken "+k.Frequency+".")
	}
	if k.RetentionDays > 0 {
		bullets = append(bullets, fmt.Sprintf("Backups are kept for %s.", days(k.RetentionDays)))
	}
	switch {
	case k.Encrypted && k.Offsite:
		bullets = append(bullets, "Backups are encrypted and stored in a separate location from the live systems.")
	case k.Encrypted:
		bullets = append(bullets, "Backups are encrypted.")
	case k.Offsite:
		bullets = append(bullets, "Backups are stored in a separate location from the live systems.")
	}
	if k.RestoreTesting != "" {
		bullets = append(bullets, "Restores are tested: "+k.RestoreTesting+".")
	}
	r.group(b, k.Claim, "", bullets)
}

func (r *renderer) dataLifecycle(b *strings.Builder, d *spec.DataLifecycle) {
	var bullets []string
	if d.TrashRetentionDays > 0 {
		bullets = append(bullets, fmt.Sprintf("Content you delete stays in the trash for %s, where you can restore it.", days(d.TrashRetentionDays)))
	}
	if d.PurgeAfterCancellationDays > 0 {
		bullets = append(bullets, fmt.Sprintf("When you cancel your account, your content is deleted from our live systems within %s.", days(d.PurgeAfterCancellationDays)))
	}
	if d.BackupExpiryDays > 0 {
		bullets = append(bullets, fmt.Sprintf("Copies in backups expire, and all of your data is gone, within %s.", days(d.BackupExpiryDays)))
	}
	bullets = append(bullets, d.Export)
	r.group(b, d.Claim, "", bullets)
	if ok, _ := r.shown(d.Claim); ok {
		r.para(b, d.Retention)
	}
}

func (r *renderer) accessControl(b *strings.Builder, a *spec.AccessControl) {
	var bullets []string
	if a.MFARequired {
		bullets = append(bullets, "Staff access to production systems requires multi-factor authentication.")
	}
	bullets = append(bullets, a.LeastPrivilege, a.CustomerDataAccess, a.Personnel, a.Endpoints)
	r.group(b, a.Claim, "", bullets)
}

func (r *renderer) incidentNotification(b *strings.Builder, n *spec.IncidentNotification) {
	s := "If a security incident affects your data, we will notify "
	s += orDefault(n.Recipient, "you")
	switch {
	case n.NotifyWithinHours > 0:
		s += fmt.Sprintf(" within %s of confirming it", hours(n.NotifyWithinHours))
	case n.Timing != "":
		s += " " + n.Timing
	}
	if n.Channel != "" {
		s += " by " + n.Channel
	}
	s += ", and work with you until it is resolved."
	r.group(b, n.Claim, s, nil)
}

func (r *renderer) lawEnforcement(b *strings.Builder, le *spec.LawEnforcement) {
	var bullets []string
	if le.RequiresLegalProcess {
		bullets = append(bullets, "We do not hand over customer data to law enforcement or other government bodies without valid legal process, such as a court order.")
	}
	if le.NotifiesCustomers {
		bullets = append(bullets, "Unless the law prevents it, we tell affected customers when we receive such a request.")
	}
	if le.TransparencyURL != "" {
		bullets = append(bullets, fmt.Sprintf("We publish a [transparency report](%s).", le.TransparencyURL))
	}
	r.group(b, le.Claim, le.Description, bullets)
}

var certKinds = map[spec.CertificationKind]string{
	spec.CertificationAudit:          "Independent audit",
	spec.CertificationSelfAssessment: "Self-assessment (not audited)",
	spec.CertificationInherited:      "Held by our provider",
}

func (r *renderer) certifications(b *strings.Builder, cs []spec.Certification) {
	var rows []string
	var notes []string
	for _, c := range cs {
		ok, note := r.shown(c.Claim)
		if !ok {
			continue
		}
		name := cell(c.Name)
		if c.URL != "" {
			name = fmt.Sprintf("[%s](%s)", name, c.URL)
		}
		if c.Issuer != "" {
			name += " — " + cell(c.Issuer)
		}
		report := ""
		if c.AvailableUnderNDA {
			report = "On request, under NDA"
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s |", name, certKinds[c.Kind], cell(r.x(c.Scope)), c.ValidUntil, report))
		if note != "" {
			notes = append(notes, fmt.Sprintf("%s — %s", c.Name, strings.TrimPrefix(note, "> ")))
		}
	}
	if len(rows) == 0 {
		return
	}
	b.WriteString("| Certification | Type | Scope | Valid until | Report |\n|---|---|---|---|---|\n")
	b.WriteString(strings.Join(rows, "\n") + "\n\n")
	for _, n := range notes {
		b.WriteString("> " + n + "\n\n")
	}
}

func locations(ls []spec.Location) string {
	parts := make([]string, 0, len(ls))
	for _, l := range ls {
		name := countryName(l.Country)
		if l.Region != "" {
			name = l.Region + ", " + strings.TrimPrefix(name, "the ")
		}
		parts = append(parts, name)
	}
	return joinAnd(parts)
}

var countries = map[string]string{
	"US": "the United States", "EU": "the European Union", "GB": "the United Kingdom",
	"CA": "Canada", "DE": "Germany", "IE": "Ireland", "FR": "France", "NL": "the Netherlands",
	"AU": "Australia", "JP": "Japan", "SG": "Singapore", "IN": "India", "SE": "Sweden",
	"FI": "Finland", "CH": "Switzerland", "BR": "Brazil",
}

func countryName(code string) string {
	if n, ok := countries[strings.ToUpper(code)]; ok {
		return n
	}
	return code
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
}

func days(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

func hours(n int) string {
	if n == 1 {
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", n)
}

func yesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// cell escapes a value for a Markdown table cell.
func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
}
