package render

import (
	"fmt"
	"strings"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

func (r *renderer) securityResponse(b *strings.Builder, d *spec.SecurityResponse) {
	r.para(b, d.Intro)
	var channels strings.Builder
	for _, c := range d.Channels {
		ok, note := r.shown(c.Claim)
		if !ok {
			continue
		}
		target := c.URL
		label := c.URL
		if c.Kind == spec.ChannelEmail {
			target, label = "mailto:"+c.Address, c.Address
		}
		s := fmt.Sprintf("**%s:** [%s](%s).", strings.TrimSuffix(r.x(c.Purpose), "."), label, target)
		if c.ResponseTarget != "" {
			s += " We respond within " + c.ResponseTarget + "."
		}
		r.para(&channels, s)
		r.para(&channels, c.Note)
		if note != "" {
			channels.WriteString(note + "\n\n")
		}
	}
	if channels.Len() > 0 {
		b.WriteString("## Reporting security problems\n\n" + channels.String())
	}
	if k := d.EncryptionKey; k != nil {
		s := fmt.Sprintf("To encrypt a report, use our [public key](%s)", k.URL)
		if k.Fingerprint != "" {
			s += fmt.Sprintf(" (fingerprint `%s`)", k.Fingerprint)
		}
		r.para(b, s+".")
	}
	if len(d.Process) > 0 {
		b.WriteString("## What happens after you report\n\n")
		for i, s := range d.Process {
			fmt.Fprintf(b, "%d. %s\n", i+1, strings.TrimSpace(r.x(s)))
		}
		b.WriteString("\n")
		if d.DisclosureDays > 0 {
			r.para(b, fmt.Sprintf("We aim to fix and disclose confirmed issues within %s of the report, and coordinate the disclosure date with you.", days(d.DisclosureDays)))
		}
	}
	if len(d.InScope) > 0 || len(d.OutOfScope) > 0 {
		b.WriteString("## Scope\n\n")
		r.list(b, "In scope:", d.InScope)
		r.list(b, "Out of scope:", d.OutOfScope)
	}
	if d.SafeHarbor != "" {
		b.WriteString("## Safe harbor\n\n")
		r.para(b, d.SafeHarbor)
	}
	r.sections(b, d.Sections)
	if len(d.Acknowledgements) > 0 {
		b.WriteString("## Thanks\n\nThese researchers have helped us find, fix and disclose security issues safely:\n\n")
		for _, a := range d.Acknowledgements {
			name := a.Name
			if a.URL != "" {
				name = fmt.Sprintf("[%s](%s)", a.Name, a.URL)
			}
			if a.Year > 0 {
				name += fmt.Sprintf(" (%d)", a.Year)
			}
			b.WriteString("- " + name + "\n")
		}
		b.WriteString("\n")
	}
}

func (r *renderer) list(b *strings.Builder, lead string, items []string) {
	if len(items) == 0 {
		return
	}
	b.WriteString(lead + "\n\n")
	for _, s := range items {
		b.WriteString("- " + strings.TrimSpace(r.x(s)) + "\n")
	}
	b.WriteString("\n")
}

func (r *renderer) subprocessors(b *strings.Builder, d *spec.Subprocessors) {
	r.para(b, d.Intro)
	if d.DPAURL != "" {
		r.para(b, fmt.Sprintf("Our [data processing addendum](%s) sets out how we and our subprocessors protect personal data.", d.DPAURL))
	}
	var rows []string
	for _, s := range d.Subprocessors {
		if ok, _ := r.shown(s.Claim); !ok {
			continue
		}
		name := cell(s.Name)
		if s.URL != "" {
			name = fmt.Sprintf("[%s](%s)", name, s.URL)
		}
		var locs []string
		for _, l := range s.Locations {
			locs = append(locs, l.Country)
		}
		if h := s.Headquarters; h != nil {
			locs = append(locs, "based in "+h.Country)
		}
		purpose := cell(r.x(s.Purpose))
		if s.Status == spec.StatusPlanned {
			purpose += " (planned)"
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s |", name, purpose, cell(strings.Join(locs, ", ")), cell(strings.Join(s.DataCategories, ", "))))
	}
	if len(rows) > 0 {
		b.WriteString("| Subprocessor | Purpose | Location | Data |\n|---|---|---|---|\n")
		b.WriteString(strings.Join(rows, "\n") + "\n\n")
	} else {
		r.para(b, "We use no subprocessors.")
	}
	if d.ChangeNotificationURL != "" {
		r.para(b, fmt.Sprintf("To hear about changes to this list, [subscribe here](%s).", d.ChangeNotificationURL))
	}
}

func (r *renderer) incidentResponse(b *strings.Builder, d *spec.IncidentResponse) {
	r.para(b, d.Intro)
	var notify strings.Builder
	if n := r.set.Facts.IncidentNotification; n != nil {
		r.incidentNotification(&notify, n)
	}
	if notify.Len() > 0 {
		b.WriteString("## Notification\n\n" + notify.String())
	}
	if len(d.Process) > 0 {
		b.WriteString("## How we respond\n\n")
		for i, s := range d.Process {
			fmt.Fprintf(b, "%d. %s\n", i+1, strings.TrimSpace(r.x(s)))
		}
		b.WriteString("\n")
	}
	if d.Drills != "" {
		b.WriteString("## Drills\n\n")
		r.para(b, d.Drills)
	}
	if d.History != nil {
		var h strings.Builder
		r.practices(&h, []spec.Practice{*d.History})
		if h.Len() > 0 {
			b.WriteString("## Our record\n\n" + h.String())
		}
	}
	r.sections(b, d.Sections)
}

func (r *renderer) availability(b *strings.Builder, d *spec.Availability) {
	r.para(b, d.Intro)
	shown := false
	if c := d.Commitment; c != nil {
		if ok, note := r.shown(c.Claim); ok {
			shown = true
			s := fmt.Sprintf("We commit to %s%% %s uptime", formatPercent(c.TargetPercent), c.Period)
			if len(c.AppliesTo) > 0 {
				s += " for " + joinAnd(c.AppliesTo)
			}
			b.WriteString("## Commitment\n\n")
			r.para(b, s+".")
			if c.Measurement != "" {
				b.WriteString("## How we measure it\n\n")
				r.para(b, c.Measurement)
			}
			if len(c.Credits) > 0 {
				b.WriteString("## Service credits\n\n| When | Credit |\n|---|---|\n")
				for _, cr := range c.Credits {
					fmt.Fprintf(b, "| %s | %s |\n", cell(r.x(cr.Condition)), cell(r.x(cr.Credit)))
				}
				b.WriteString("\n")
			}
			r.list(b, "The commitment does not cover:", c.Exclusions)
			if note != "" {
				b.WriteString(note + "\n\n")
			}
		}
	}
	if !shown && d.NoCommitment != "" {
		r.para(b, d.NoCommitment)
	}
	var links []string
	if d.StatusPageURL != "" {
		links = append(links, fmt.Sprintf("Current status is at [%s](%s).", d.StatusPageURL, d.StatusPageURL))
	}
	if d.UptimeHistoryURL != "" {
		links = append(links, fmt.Sprintf("Past uptime is [public](%s).", d.UptimeHistoryURL))
	}
	r.para(b, strings.Join(links, " "))
	r.sections(b, d.Sections)
}

func formatPercent(p float64) string {
	s := fmt.Sprintf("%.3f", p)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	return s
}
