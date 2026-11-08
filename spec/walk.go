package spec

import "fmt"

// WalkClaims calls fn for every claim in the set, with its JSON path.
func (s *DocumentSet) WalkClaims(fn func(path string, c *Claim)) {
	f := &s.Facts
	if f.Hosting != nil {
		fn("facts.hosting", &f.Hosting.Claim)
	}
	if f.Encryption != nil {
		fn("facts.encryption", &f.Encryption.Claim)
	}
	if f.Backups != nil {
		fn("facts.backups", &f.Backups.Claim)
	}
	if f.DataLifecycle != nil {
		fn("facts.dataLifecycle", &f.DataLifecycle.Claim)
	}
	if f.AccessControl != nil {
		fn("facts.accessControl", &f.AccessControl.Claim)
	}
	if f.IncidentNotification != nil {
		fn("facts.incidentNotification", &f.IncidentNotification.Claim)
	}
	if f.LawEnforcement != nil {
		fn("facts.lawEnforcement", &f.LawEnforcement.Claim)
	}
	for i := range f.Certifications {
		fn(fmt.Sprintf("facts.certifications[%d]", i), &f.Certifications[i].Claim)
	}
	sections := func(path string, ss []Section) {
		for i := range ss {
			for j := range ss[i].Practices {
				fn(fmt.Sprintf("%s.sections[%d].practices[%d]", path, i, j), &ss[i].Practices[j].Claim)
			}
		}
	}
	for _, ref := range s.Documents.List() {
		switch d := ref.Doc.(type) {
		case *SecurityOverview:
			sections(ref.Path, d.Sections)
		case *SecurityResponse:
			for i := range d.Channels {
				fn(fmt.Sprintf("%s.channels[%d]", ref.Path, i), &d.Channels[i].Claim)
			}
			sections(ref.Path, d.Sections)
		case *Subprocessors:
			for i := range d.Subprocessors {
				fn(fmt.Sprintf("%s.subprocessors[%d]", ref.Path, i), &d.Subprocessors[i].Claim)
			}
		case *DataHandling:
			sections(ref.Path, d.Sections)
		case *IncidentResponse:
			if d.History != nil {
				fn(ref.Path+".history", &d.History.Claim)
			}
			sections(ref.Path, d.Sections)
		case *Availability:
			if d.Commitment != nil {
				fn(ref.Path+".commitment", &d.Commitment.Claim)
			}
			sections(ref.Path, d.Sections)
		case *CustomDocument:
			sections(ref.Path, d.Sections)
		}
	}
}
