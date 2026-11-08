package lint

import (
	"fmt"
	"slices"
	"strings"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

// noStatement marks a claim that has no statement field, such as a fact group.
const noStatement = "-"

func (l *linter) facts() {
	f := &l.set.Facts
	if h := f.Hosting; h != nil {
		l.claim("facts.hosting", "", &h.Claim, noStatement)
		if h.Status == spec.StatusImplemented && len(h.Locations) == 0 {
			l.add(SeverityWarning, "hosting-location", "facts.hosting.locations", "say where data is stored")
		}
		for i, loc := range h.Locations {
			l.location(fmt.Sprintf("facts.hosting.locations[%d]", i), loc)
		}
		l.prose("facts.hosting.description", h.Description)
		if sp := l.set.Documents.Subprocessors; sp != nil {
			for i, p := range h.Providers {
				if !slices.ContainsFunc(sp.Subprocessors, func(s spec.Subprocessor) bool { return strings.EqualFold(s.Name, p) }) {
					l.add(SeverityWarning, "provider-not-subprocessor", fmt.Sprintf("facts.hosting.providers[%d]", i),
						"hosting provider %q is not in the subprocessor list", p)
				}
			}
		}
	}
	if e := f.Encryption; e != nil {
		l.claim("facts.encryption", "", &e.Claim, noStatement)
		if e.Status == spec.StatusImplemented && e.InTransit == nil {
			l.add(SeverityWarning, "encryption-in-transit", "facts.encryption.inTransit", "state how data in transit is encrypted")
		}
		if t := e.InTransit; t != nil {
			l.url("facts.encryption.inTransit.reportUrl", t.ReportURL)
			if t.MinTLSVersion != "" && t.MinTLSVersion < "1.2" {
				l.add(SeverityWarning, "weak-tls", "facts.encryption.inTransit.minTlsVersion", "TLS %s is below 1.2", t.MinTLSVersion)
			}
		}
		if e.Status == spec.StatusImplemented && len(e.AtRest) == 0 {
			l.add(SeverityWarning, "encryption-at-rest", "facts.encryption.atRest", "state, per data store, whether it is encrypted at rest")
		}
		for i, s := range e.AtRest {
			l.required(fmt.Sprintf("facts.encryption.atRest[%d].store", i), s.Store)
		}
		if ph := e.PasswordHashing; ph != nil && ph.Algorithm == "" && ph.NotApplicable == "" {
			l.add(SeverityError, "required", "facts.encryption.passwordHashing.algorithm", "set the algorithm, or notApplicable to say why there is none")
		}
		l.prose("facts.encryption.applicationLevel", e.ApplicationLevel)
	}
	if b := f.Backups; b != nil {
		l.claim("facts.backups", "", &b.Claim, noStatement)
		if b.Status == spec.StatusImplemented {
			if b.Frequency == "" {
				l.add(SeverityWarning, "backup-frequency", "facts.backups.frequency", "say how often backups are taken")
			}
			if b.RetentionDays == 0 {
				l.add(SeverityWarning, "backup-retention", "facts.backups.retentionDays", "say how long backups are kept; deleted data lives in them until they expire")
			}
			if b.RestoreTesting == "" {
				l.add(SeverityInfo, "backup-restore-testing", "facts.backups.restoreTesting", "say whether restores are tested")
			}
		}
	}
	if d := f.DataLifecycle; d != nil {
		l.claim("facts.dataLifecycle", "", &d.Claim, noStatement)
		if d.Status == spec.StatusImplemented && d.PurgeAfterCancellationDays == 0 {
			l.add(SeverityWarning, "purge-window", "facts.dataLifecycle.purgeAfterCancellationDays", "say when a cancelled account's data is deleted")
		}
		if d.BackupExpiryDays != 0 && d.BackupExpiryDays < d.PurgeAfterCancellationDays {
			l.add(SeverityError, "lifecycle-inconsistent", "facts.dataLifecycle.backupExpiryDays",
				"backups expire (%d days) before live data is purged (%d days)", d.BackupExpiryDays, d.PurgeAfterCancellationDays)
		}
		if b := f.Backups; b != nil && b.RetentionDays > 0 && d.PurgeAfterCancellationDays > 0 && d.BackupExpiryDays > 0 &&
			d.BackupExpiryDays < d.PurgeAfterCancellationDays+b.RetentionDays {
			l.add(SeverityWarning, "lifecycle-inconsistent", "facts.dataLifecycle.backupExpiryDays",
				"backups are kept %d days, so data purged at day %d can survive until day %d, not %d",
				b.RetentionDays, d.PurgeAfterCancellationDays, d.PurgeAfterCancellationDays+b.RetentionDays, d.BackupExpiryDays)
		}
		l.prose("facts.dataLifecycle.export", d.Export)
		l.prose("facts.dataLifecycle.retention", d.Retention)
	}
	if a := f.AccessControl; a != nil {
		l.claim("facts.accessControl", "", &a.Claim, noStatement)
		l.prose("facts.accessControl.leastPrivilege", a.LeastPrivilege)
		l.prose("facts.accessControl.customerDataAccess", a.CustomerDataAccess)
		l.prose("facts.accessControl.personnel", a.Personnel)
		l.prose("facts.accessControl.endpoints", a.Endpoints)
	}
	if n := f.IncidentNotification; n != nil {
		l.claim("facts.incidentNotification", "", &n.Claim, noStatement)
		if n.Status == spec.StatusImplemented && n.NotifyWithinHours == 0 && n.Timing == "" {
			l.add(SeverityWarning, "notification-window", "facts.incidentNotification.notifyWithinHours", "say how soon affected customers are told")
		}
	}
	if le := f.LawEnforcement; le != nil {
		l.claim("facts.lawEnforcement", "", &le.Claim, noStatement)
		l.url("facts.lawEnforcement.transparencyUrl", le.TransparencyURL)
		l.prose("facts.lawEnforcement.description", le.Description)
	}
	for i := range f.Certifications {
		c := &f.Certifications[i]
		p := fmt.Sprintf("facts.certifications[%d]", i)
		l.claim(p, c.Name, &c.Claim, noStatement)
		l.required(p+".name", c.Name)
		if !slices.Contains([]spec.CertificationKind{spec.CertificationAudit, spec.CertificationSelfAssessment, spec.CertificationInherited}, c.Kind) {
			l.add(SeverityError, "invalid-enum", p+".kind", "kind %q; want audit, self-assessment or inherited", c.Kind)
		}
		if t, ok := l.date(p+".validUntil", c.ValidUntil); ok && t.Before(l.opts.Now) {
			l.add(SeverityError, "certification-expired", p+".validUntil", "%s expired on %s", c.Name, c.ValidUntil)
		}
		l.url(p+".url", c.URL)
	}
}

func (l *linter) location(path string, loc spec.Location) {
	if len(loc.Country) != 2 {
		l.add(SeverityError, "invalid", path+".country", "%q is not an ISO 3166-1 alpha-2 code or EU", loc.Country)
	}
}

func (l *linter) meta(path string, m *spec.DocMeta) {
	l.required(path+".title", m.Title)
	l.visibility(path+".visibility", m.Visibility)
	l.prose(path+".description", m.Description)
	if _, ok := l.date(path+".lastUpdated", m.LastUpdated); !ok && m.LastUpdated == "" {
		l.add(SeverityWarning, "last-updated", path+".lastUpdated", "set the date readers see as last updated")
	}
	interval := l.set.Review.IntervalDays
	if interval == 0 {
		interval = 365
	}
	if t, ok := l.date(path+".reviewedAt", m.ReviewedAt); ok {
		if age := int(l.opts.Now.Sub(t).Hours() / 24); age > interval {
			l.add(SeverityWarning, "review-stale", path+".reviewedAt", "last reviewed %d days ago; the review interval is %d", age, interval)
		}
	} else if m.ReviewedAt == "" {
		l.add(SeverityWarning, "review-missing", path+".reviewedAt", "no recorded review")
	}
}

func (l *linter) sections(path string, ss []spec.Section) {
	for i := range ss {
		s := &ss[i]
		p := fmt.Sprintf("%s.sections[%d]", path, i)
		l.id(path+".sections", p, s.ID)
		l.required(p+".title", s.Title)
		l.visibility(p+".visibility", s.Visibility)
		l.prose(p+".intro", s.Intro)
		l.prose(p+".outro", s.Outro)
		if s.Include != "" {
			if !slices.Contains(spec.Includes, s.Include) {
				l.add(SeverityError, "invalid-enum", p+".include", "include %q; want one of %v", s.Include, spec.Includes)
			} else if !l.hasFact(s.Include) {
				l.add(SeverityError, "include-missing-fact", p+".include", "includes %s, but facts.%s is not set", s.Include, s.Include)
			}
		}
		if s.Intro == "" && s.Include == "" && len(s.Practices) == 0 && s.Outro == "" {
			l.add(SeverityWarning, "section-empty", p, "section %q has no content", s.Title)
		}
		l.practices(p, s.Practices)
	}
}

func (l *linter) hasFact(in spec.Include) bool {
	f := &l.set.Facts
	switch in {
	case spec.IncludeHosting:
		return f.Hosting != nil
	case spec.IncludeEncryption:
		return f.Encryption != nil
	case spec.IncludeBackups:
		return f.Backups != nil
	case spec.IncludeDataLifecycle:
		return f.DataLifecycle != nil
	case spec.IncludeAccessControl:
		return f.AccessControl != nil
	case spec.IncludeIncidentNotification:
		return f.IncidentNotification != nil
	case spec.IncludeLawEnforcement:
		return f.LawEnforcement != nil
	case spec.IncludeCertifications:
		return len(f.Certifications) > 0
	}
	return false
}

func (l *linter) practices(path string, ps []spec.Practice) {
	for i := range ps {
		p := &ps[i]
		pp := fmt.Sprintf("%s.practices[%d]", path, i)
		l.id("practice", pp, p.ID)
		l.claim(pp, practiceLabel(p), &p.Claim, p.Statement)
		l.prose(pp+".statement", p.Statement)
	}
}

func (l *linter) document(ref spec.DocRef) {
	l.meta(ref.Path, ref.Meta)
	switch d := ref.Doc.(type) {
	case *spec.SecurityOverview:
		l.prose(ref.Path+".intro", d.Intro)
		if len(d.Sections) == 0 {
			l.add(SeverityWarning, "sections-missing", ref.Path+".sections", "the overview has no sections")
		}
		l.sections(ref.Path, d.Sections)
	case *spec.SecurityResponse:
		l.securityResponse(ref.Path, d)
	case *spec.Subprocessors:
		l.subprocessors(ref.Path, d)
	case *spec.DataHandling:
		l.prose(ref.Path+".intro", d.Intro)
		l.sections(ref.Path, d.Sections)
	case *spec.IncidentResponse:
		l.prose(ref.Path+".intro", d.Intro)
		for i, s := range d.Process {
			l.prose(fmt.Sprintf("%s.process[%d]", ref.Path, i), s)
		}
		if l.set.Facts.IncidentNotification == nil {
			l.add(SeverityWarning, "notification-missing", "facts.incidentNotification", "the incident-response document needs a notification commitment")
		}
		if d.History != nil {
			l.claim(ref.Path+".history", practiceLabel(d.History), &d.History.Claim, d.History.Statement)
			l.prose(ref.Path+".history.statement", d.History.Statement)
		}
		l.sections(ref.Path, d.Sections)
	case *spec.Availability:
		l.availability(ref.Path, d)
	case *spec.CustomDocument:
		l.required(ref.Path+".slug", d.Slug)
		l.prose(ref.Path+".intro", d.Intro)
		l.sections(ref.Path, d.Sections)
	}
}

func (l *linter) securityResponse(path string, d *spec.SecurityResponse) {
	l.prose(path+".intro", d.Intro)
	if len(d.Channels) == 0 {
		l.add(SeverityError, "channel-missing", path+".channels", "say how to report a vulnerability")
	}
	for i := range d.Channels {
		c := &d.Channels[i]
		p := fmt.Sprintf("%s.channels[%d]", path, i)
		l.id("channel", p, c.ID)
		l.claim(p, c.ID, &c.Claim, noStatement)
		l.required(p+".purpose", c.Purpose)
		switch c.Kind {
		case spec.ChannelEmail:
			if !strings.Contains(c.Address, "@") {
				l.add(SeverityError, "required", p+".address", "an email channel needs an address")
			}
		case spec.ChannelBugBounty, spec.ChannelWebForm, spec.ChannelOther:
			if c.URL == "" {
				l.add(SeverityError, "required", p+".url", "a %s channel needs a URL", c.Kind)
			}
		default:
			l.add(SeverityError, "invalid-enum", p+".kind", "kind %q; want email, bug-bounty, web-form or other", c.Kind)
		}
		l.url(p+".url", c.URL)
		if c.ResponseTarget == "" {
			l.add(SeverityInfo, "response-target", p+".responseTarget", "say how soon reporters hear back")
		}
		l.prose(p+".note", c.Note)
	}
	if len(d.Process) == 0 {
		l.add(SeverityWarning, "process-missing", path+".process", "say what happens after a report arrives")
	}
	for i, s := range d.Process {
		l.prose(fmt.Sprintf("%s.process[%d]", path, i), s)
	}
	if d.SafeHarbor == "" {
		l.add(SeverityInfo, "safe-harbor", path+".safeHarbor", "a safe-harbor statement tells researchers good-faith testing is welcome")
	}
	l.prose(path+".safeHarbor", d.SafeHarbor)
	if d.EncryptionKey != nil {
		l.url(path+".encryptionKey.url", d.EncryptionKey.URL)
	}
	for i, a := range d.Acknowledgements {
		l.required(fmt.Sprintf("%s.acknowledgements[%d].name", path, i), a.Name)
		l.url(fmt.Sprintf("%s.acknowledgements[%d].url", path, i), a.URL)
	}
	if t, ok := l.date(path+".securityTxtExpires", d.SecurityTxtExpires); ok {
		if t.Before(l.opts.Now) {
			l.add(SeverityError, "security-txt-expired", path+".securityTxtExpires", "security.txt expired on %s", d.SecurityTxtExpires)
		} else if t.After(l.opts.Now.AddDate(1, 0, 0)) {
			l.add(SeverityWarning, "security-txt-expires", path+".securityTxtExpires", "RFC 9116 recommends Expires less than a year away")
		}
	} else if d.SecurityTxtExpires == "" {
		l.add(SeverityInfo, "security-txt-expires", path+".securityTxtExpires", "set it to generate security.txt")
	}
	l.sections(path, d.Sections)
}

func (l *linter) subprocessors(path string, d *spec.Subprocessors) {
	l.prose(path+".intro", d.Intro)
	l.url(path+".dpaUrl", d.DPAURL)
	l.url(path+".changeNotificationUrl", d.ChangeNotificationURL)
	if d.ChangeNotificationURL == "" {
		l.add(SeverityInfo, "change-notification", path+".changeNotificationUrl", "tell customers how to hear about changes to the list")
	}
	if len(d.Subprocessors) == 0 {
		l.add(SeverityWarning, "subprocessors-missing", path+".subprocessors", "the list is empty")
	}
	for i := range d.Subprocessors {
		s := &d.Subprocessors[i]
		p := fmt.Sprintf("%s.subprocessors[%d]", path, i)
		l.id("subprocessor", p, s.ID)
		l.claim(p, s.Name, &s.Claim, noStatement)
		l.required(p+".name", s.Name)
		l.required(p+".purpose", s.Purpose)
		l.url(p+".url", s.URL)
		if len(s.Locations) == 0 {
			l.add(SeverityWarning, "subprocessor-location", p+".locations", "say where %s processes data", s.Name)
		}
		if s.Headquarters != nil {
			l.location(p+".headquarters", *s.Headquarters)
		}
		for j, loc := range s.Locations {
			l.location(fmt.Sprintf("%s.locations[%d]", p, j), loc)
		}
		if len(s.DataCategories) == 0 {
			l.add(SeverityInfo, "subprocessor-data", p+".dataCategories", "say what data %s receives", s.Name)
		}
		l.date(p+".since", s.Since)
	}
}

func (l *linter) availability(path string, d *spec.Availability) {
	l.prose(path+".intro", d.Intro)
	switch {
	case d.Commitment == nil && strings.TrimSpace(d.NoCommitment) == "":
		l.add(SeverityError, "availability-unstated", path, "set a commitment, or noCommitment to say that none is made")
	case d.Commitment != nil && d.NoCommitment != "":
		l.add(SeverityError, "availability-conflict", path, "set a commitment or noCommitment, not both")
	}
	if c := d.Commitment; c != nil {
		l.claim(path+".commitment", "", &c.Claim, noStatement)
		if c.TargetPercent <= 0 || c.TargetPercent > 100 {
			l.add(SeverityError, "invalid", path+".commitment.targetPercent", "%v is not a percentage", c.TargetPercent)
		}
		l.required(path+".commitment.period", c.Period)
		if c.Measurement == "" {
			l.add(SeverityWarning, "availability-measurement", path+".commitment.measurement", "say how uptime is measured")
		}
	}
	l.prose(path+".noCommitment", d.NoCommitment)
	l.url(path+".statusPageUrl", d.StatusPageURL)
	l.url(path+".uptimeHistoryUrl", d.UptimeHistoryURL)
	l.sections(path, d.Sections)
}

func practiceLabel(p *spec.Practice) string {
	if p.Title != "" {
		return p.ID + ": " + p.Title
	}
	return p.ID
}
