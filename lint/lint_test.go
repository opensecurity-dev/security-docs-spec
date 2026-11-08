package lint_test

import (
	"slices"
	"testing"
	"time"

	"github.com/opensecurity-dev/security-docs-spec/lint"
	"github.com/opensecurity-dev/security-docs-spec/spec"
)

var now = time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)

func load(t *testing.T) *spec.DocumentSet {
	t.Helper()
	set, err := spec.Load("../examples/example-notes/security-docs.json")
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func rules(r lint.Report, sev lint.Severity) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Severity == sev {
			out = append(out, f.Rule)
		}
	}
	return out
}

func TestExampleIsClean(t *testing.T) {
	r := lint.Run(load(t), lint.Options{Now: now})
	if r.Max().Rank() >= lint.SeverityWarning.Rank() {
		t.Fatalf("example has findings: %v", r.Findings)
	}
}

func TestScaffoldReportsWorkToDo(t *testing.T) {
	r := lint.Run(spec.Scaffold("Example Co", "Example Notes"), lint.Options{Now: now})
	errs := rules(r, lint.SeverityError)
	for _, want := range []string{"required", "availability-unstated"} {
		if !slices.Contains(errs, want) {
			t.Errorf("scaffold errors %v lack %q", errs, want)
		}
	}
	if !slices.Contains(rules(r, lint.SeverityWarning), "status-todo") {
		t.Error("scaffold has no status-todo warnings")
	}
}

func TestRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*spec.DocumentSet)
		sev    lint.Severity
		rule   string
		opts   lint.Options
	}{
		{"planned needs gap", func(s *spec.DocumentSet) {
			s.Documents.SecurityOverview.Sections[2].Practices[0].Status = spec.StatusPlanned
		}, lint.SeverityError, "gap-required", lint.Options{}},
		{"not applicable needs justification", func(s *spec.DocumentSet) {
			s.Documents.SecurityOverview.Sections[2].Practices[0].Status = spec.StatusNotApplicable
		}, lint.SeverityError, "justification-required", lint.Options{}},
		{"unknown status", func(s *spec.DocumentSet) {
			s.Facts.Backups.Status = "done"
		}, lint.SeverityError, "invalid-enum", lint.Options{}},
		{"unknown placeholder", func(s *spec.DocumentSet) {
			s.Documents.SecurityOverview.Intro = "Welcome to {{product.nmae}}."
		}, lint.SeverityError, "unknown-placeholder", lint.Options{}},
		{"todo marker", func(s *spec.DocumentSet) {
			s.Documents.SecurityOverview.Intro = "TBD"
		}, lint.SeverityWarning, "todo-marker", lint.Options{}},
		{"backups expire before purge", func(s *spec.DocumentSet) {
			s.Facts.DataLifecycle.BackupExpiryDays = 10
		}, lint.SeverityError, "lifecycle-inconsistent", lint.Options{}},
		{"backup retention outlives stated expiry", func(s *spec.DocumentSet) {
			s.Facts.DataLifecycle.BackupExpiryDays = 45
		}, lint.SeverityWarning, "lifecycle-inconsistent", lint.Options{}},
		{"stale review", func(s *spec.DocumentSet) {
			s.Documents.Subprocessors.ReviewedAt = "2025-01-01"
		}, lint.SeverityWarning, "review-stale", lint.Options{}},
		{"bad date", func(s *spec.DocumentSet) {
			s.Documents.Subprocessors.LastUpdated = "Nov 1"
		}, lint.SeverityError, "invalid-date", lint.Options{}},
		{"expired certification", func(s *spec.DocumentSet) {
			s.Facts.Certifications[0].ValidUntil = "2026-01-01"
		}, lint.SeverityError, "certification-expired", lint.Options{}},
		{"no availability statement", func(s *spec.DocumentSet) {
			s.Documents.Availability.NoCommitment = ""
		}, lint.SeverityError, "availability-unstated", lint.Options{}},
		{"both availability statements", func(s *spec.DocumentSet) {
			s.Documents.Availability.Commitment = &spec.AvailabilityCommitment{TargetPercent: 99.9, Period: "monthly", Claim: spec.Claim{Status: spec.StatusImplemented}}
		}, lint.SeverityError, "availability-conflict", lint.Options{}},
		{"include without fact", func(s *spec.DocumentSet) {
			s.Facts.LawEnforcement = nil
		}, lint.SeverityError, "include-missing-fact", lint.Options{}},
		{"duplicate practice id", func(s *spec.DocumentSet) {
			s.Documents.SecurityOverview.Sections[4].Practices[1].ID = "patching"
		}, lint.SeverityError, "duplicate-id", lint.Options{}},
		{"hosting provider missing from subprocessors", func(s *spec.DocumentSet) {
			s.Facts.Hosting.Providers = append(s.Facts.Hosting.Providers, "Other Cloud")
		}, lint.SeverityWarning, "provider-not-subprocessor", lint.Options{}},
		{"unverified public claim, strict", func(s *spec.DocumentSet) {
			s.Facts.Backups.Verification = ""
		}, lint.SeverityWarning, "unverified-claim", lint.Options{Strict: true}},
		{"verified without evidence", func(s *spec.DocumentSet) {
			s.Facts.Backups.Verification = spec.VerificationVerified
		}, lint.SeverityWarning, "evidence-missing", lint.Options{}},
		{"email channel without address", func(s *spec.DocumentSet) {
			s.Documents.SecurityResponse.Channels[0].Address = ""
		}, lint.SeverityError, "required", lint.Options{}},
		{"expired security.txt", func(s *spec.DocumentSet) {
			s.Documents.SecurityResponse.SecurityTxtExpires = "2026-10-01"
		}, lint.SeverityError, "security-txt-expired", lint.Options{}},
		{"bad NIST control ID", func(s *spec.DocumentSet) {
			s.Facts.Backups.ControlRefs = []spec.ControlRef{{Framework: spec.FrameworkNIST80053R5, Control: "cp9"}}
		}, lint.SeverityError, "control-id", lint.Options{}},
		{"bad KSI ID", func(s *spec.DocumentSet) {
			s.Facts.Backups.ControlRefs = []spec.ControlRef{{Framework: spec.FrameworkFedRAMPKSI, Control: "IAM-JIT"}}
		}, lint.SeverityError, "control-id", lint.Options{}},
		{"wrong schema version", func(s *spec.DocumentSet) {
			s.SchemaVersion = "9"
		}, lint.SeverityError, "schema-version", lint.Options{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := load(t)
			tt.mutate(set)
			opts := tt.opts
			opts.Now = now
			if got := rules(lint.Run(set, opts), tt.sev); !slices.Contains(got, tt.rule) {
				t.Fatalf("want %s %q, got %v", tt.sev, tt.rule, got)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	if s, err := lint.ParseSeverity("none"); err != nil || s != "" {
		t.Fatalf("none: %q, %v", s, err)
	}
	if _, err := lint.ParseSeverity("fatal"); err == nil {
		t.Fatal("fatal accepted")
	}
}
