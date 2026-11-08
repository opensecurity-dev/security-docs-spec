package spec

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Allows reports whether content with visibility v may be shown to audience a.
// An empty visibility is public.
func (a Visibility) Allows(v Visibility) bool {
	if v == "" {
		v = VisibilityPublic
	}
	switch a {
	case VisibilityInternal:
		return true
	case VisibilityNDA:
		return v == VisibilityPublic || v == VisibilityNDA
	default:
		return v == VisibilityPublic
	}
}

// ForAudience returns a deep copy of the set with everything the audience may
// not see removed: documents, sections, practices, channels, subprocessors,
// certifications, fact groups, internal notes and evidence not marked public.
// Templates only ever see this copy, so a field the audience may not see
// cannot leak through a template.
func (s *DocumentSet) ForAudience(a Visibility) (*DocumentSet, error) {
	if !slices.Contains(Visibilities, a) {
		return nil, fmt.Errorf("spec: unknown audience %q; want one of %v", a, Visibilities)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("spec: copy document set: %w", err)
	}
	var c DocumentSet
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("spec: copy document set: %w", err)
	}
	f := filter{a}
	f.facts(&c.Facts)
	f.documents(&c.Documents)
	return &c, nil
}

type filter struct{ a Visibility }

// claim reports whether the claim is kept, and strips what no outside reader sees.
func (f filter) claim(c *Claim) bool {
	if !f.a.Allows(c.Visibility) {
		return false
	}
	if f.a != VisibilityInternal {
		c.Notes = ""
		c.Source = nil
		c.Evidence = slices.DeleteFunc(c.Evidence, func(e EvidenceRef) bool { return !e.Public })
	}
	return true
}

func keepPtr[T any](f filter, p *T, claim func(*T) *Claim) *T {
	if p == nil || !f.claim(claim(p)) {
		return nil
	}
	return p
}

func (f filter) facts(x *Facts) {
	x.Hosting = keepPtr(f, x.Hosting, func(v *Hosting) *Claim { return &v.Claim })
	x.Encryption = keepPtr(f, x.Encryption, func(v *Encryption) *Claim { return &v.Claim })
	x.Backups = keepPtr(f, x.Backups, func(v *Backups) *Claim { return &v.Claim })
	x.DataLifecycle = keepPtr(f, x.DataLifecycle, func(v *DataLifecycle) *Claim { return &v.Claim })
	x.AccessControl = keepPtr(f, x.AccessControl, func(v *AccessControl) *Claim { return &v.Claim })
	x.IncidentNotification = keepPtr(f, x.IncidentNotification, func(v *IncidentNotification) *Claim { return &v.Claim })
	x.LawEnforcement = keepPtr(f, x.LawEnforcement, func(v *LawEnforcement) *Claim { return &v.Claim })
	x.Certifications = slices.DeleteFunc(x.Certifications, func(c Certification) bool { return !f.claim(&c.Claim) })
	for i := range x.Certifications {
		f.claim(&x.Certifications[i].Claim)
	}
}

func (f filter) sections(ss []Section) []Section {
	ss = slices.DeleteFunc(ss, func(s Section) bool { return !f.a.Allows(s.Visibility) })
	for i := range ss {
		ss[i].Practices = f.practices(ss[i].Practices)
	}
	return ss
}

func (f filter) practices(ps []Practice) []Practice {
	ps = slices.DeleteFunc(ps, func(p Practice) bool { return !f.a.Allows(p.Visibility) })
	for i := range ps {
		f.claim(&ps[i].Claim)
	}
	return ps
}

func (f filter) meta(m *DocMeta) bool {
	if f.a != VisibilityInternal {
		m.Owner = ""
	}
	return f.a.Allows(m.Visibility)
}

func (f filter) documents(d *Documents) {
	if d.SecurityOverview != nil {
		if !f.meta(&d.SecurityOverview.DocMeta) {
			d.SecurityOverview = nil
		} else {
			d.SecurityOverview.Sections = f.sections(d.SecurityOverview.Sections)
		}
	}
	if d.SecurityResponse != nil {
		r := d.SecurityResponse
		if !f.meta(&r.DocMeta) {
			d.SecurityResponse = nil
		} else {
			r.Channels = slices.DeleteFunc(r.Channels, func(c ReportingChannel) bool { return !f.a.Allows(c.Visibility) })
			for i := range r.Channels {
				f.claim(&r.Channels[i].Claim)
			}
			r.Sections = f.sections(r.Sections)
		}
	}
	if d.Subprocessors != nil {
		s := d.Subprocessors
		if !f.meta(&s.DocMeta) {
			d.Subprocessors = nil
		} else {
			s.Subprocessors = slices.DeleteFunc(s.Subprocessors, func(p Subprocessor) bool { return !f.a.Allows(p.Visibility) })
			for i := range s.Subprocessors {
				f.claim(&s.Subprocessors[i].Claim)
			}
		}
	}
	if d.DataHandling != nil {
		if !f.meta(&d.DataHandling.DocMeta) {
			d.DataHandling = nil
		} else {
			d.DataHandling.Sections = f.sections(d.DataHandling.Sections)
		}
	}
	if d.IncidentResponse != nil {
		ir := d.IncidentResponse
		if !f.meta(&ir.DocMeta) {
			d.IncidentResponse = nil
		} else {
			if ir.History != nil && !f.claim(&ir.History.Claim) {
				ir.History = nil
			}
			ir.Sections = f.sections(ir.Sections)
		}
	}
	if d.Availability != nil {
		av := d.Availability
		if !f.meta(&av.DocMeta) {
			d.Availability = nil
		} else {
			if av.Commitment != nil && !f.claim(&av.Commitment.Claim) {
				av.Commitment = nil
			}
			av.Sections = f.sections(av.Sections)
		}
	}
	d.Custom = slices.DeleteFunc(d.Custom, func(c CustomDocument) bool { return !f.a.Allows(c.Visibility) })
	for i := range d.Custom {
		f.meta(&d.Custom[i].DocMeta)
		d.Custom[i].Sections = f.sections(d.Custom[i].Sections)
	}
}
