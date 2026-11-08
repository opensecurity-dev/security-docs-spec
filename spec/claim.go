package spec

// Status is how far a claim is implemented. The words follow OSCAL's
// implementation-status values, plus "todo" for a claim nobody has assessed.
type Status string

const (
	StatusImplemented   Status = "implemented"
	StatusPartial       Status = "partial"
	StatusPlanned       Status = "planned"
	StatusAlternative   Status = "alternative"
	StatusNotApplicable Status = "not-applicable"
	StatusTodo          Status = "todo"
)

// Statuses lists every valid Status.
var Statuses = []Status{StatusImplemented, StatusPartial, StatusPlanned, StatusAlternative, StatusNotApplicable, StatusTodo}

// Visibility is the widest audience a claim may be shown to.
type Visibility string

const (
	// VisibilityPublic content is published on the website.
	VisibilityPublic Visibility = "public"
	// VisibilityNDA content is shared with customers under a non-disclosure agreement.
	VisibilityNDA Visibility = "nda"
	// VisibilityInternal content is never rendered for an outside audience.
	VisibilityInternal Visibility = "internal"
)

// Visibilities lists every valid Visibility, narrowest audience last.
var Visibilities = []Visibility{VisibilityPublic, VisibilityNDA, VisibilityInternal}

// Verification is how much a claim has been checked.
type Verification string

const (
	// VerificationUnverified: entered or discovered, not yet checked by a person.
	VerificationUnverified Verification = "unverified"
	// VerificationReviewed: a person read it and agrees it is true.
	VerificationReviewed Verification = "reviewed"
	// VerificationVerified: backed by evidence that was checked.
	VerificationVerified Verification = "verified"
)

// Verifications lists every valid Verification.
var Verifications = []Verification{VerificationUnverified, VerificationReviewed, VerificationVerified}

// Claim is the metadata every assertion in a document carries: how far it is
// implemented, who may see it, and where it came from. It is embedded in
// practices and fact groups, so its fields appear inline in JSON.
type Claim struct {
	// Status is required; an empty status is reported by lint.
	Status Status `json:"status,omitempty" jsonschema:"enum=implemented,enum=partial,enum=planned,enum=alternative,enum=not-applicable,enum=todo"`
	// Visibility defaults to public.
	Visibility Visibility `json:"visibility,omitempty" jsonschema:"enum=public,enum=nda,enum=internal"`
	// Verification defaults to unverified.
	Verification Verification `json:"verification,omitempty" jsonschema:"enum=unverified,enum=reviewed,enum=verified"`
	// Gap says what is missing. Required when status is partial or planned.
	Gap string `json:"gap,omitempty"`
	// TrackingRef points at the work item that closes the gap.
	TrackingRef string `json:"trackingRef,omitempty"`
	// Justification says why the claim does not apply. Required when status is not-applicable.
	Justification string `json:"justification,omitempty"`
	// Source records where the claim came from.
	Source *Source `json:"source,omitempty"`
	// Evidence backs the claim.
	Evidence []EvidenceRef `json:"evidence,omitempty"`
	// ControlRefs map the claim to framework controls, such as NIST SP 800-53 SC-8.
	ControlRefs []ControlRef `json:"controlRefs,omitempty"`
	// Notes are internal and never rendered.
	Notes string `json:"notes,omitempty"`
}

// EffectiveVisibility returns the claim's visibility, defaulting to public.
func (c Claim) EffectiveVisibility() Visibility {
	if c.Visibility == "" {
		return VisibilityPublic
	}
	return c.Visibility
}

// EffectiveVerification returns the claim's verification, defaulting to unverified.
func (c Claim) EffectiveVerification() Verification {
	if c.Verification == "" {
		return VerificationUnverified
	}
	return c.Verification
}

// SourceKind says what produced a claim.
type SourceKind string

const (
	SourceManual      SourceKind = "manual"
	SourceAnalyzer    SourceKind = "analyzer"
	SourceAttestation SourceKind = "attestation"
	SourceEvidence    SourceKind = "evidence"
	SourceInherited   SourceKind = "inherited"
)

// Source records where a claim came from.
type Source struct {
	Kind SourceKind `json:"kind" jsonschema:"enum=manual,enum=analyzer,enum=attestation,enum=evidence,enum=inherited"`
	// Ref identifies the producer: an analyzer name, an attestation ID, a provider.
	Ref string `json:"ref,omitempty"`
	// CollectedAt is a date (YYYY-MM-DD) or RFC 3339 time.
	CollectedAt string `json:"collectedAt,omitempty"`
}

// EvidenceRef points at evidence for a claim.
type EvidenceRef struct {
	// Ref is an identifier or URL. Internal references are never rendered.
	Ref         string `json:"ref"`
	Description string `json:"description,omitempty"`
	// Public marks evidence that may be linked from published output, such as an SSL Labs report.
	Public bool `json:"public,omitempty"`
}

// Framework names for ControlRef. Lint checks the control ID format of these.
// Other frameworks may be named, but only by ID: a document set never carries
// a framework's control text.
const (
	// FrameworkNIST80053R5 is NIST SP 800-53 Rev 5; controls like "SC-8" or "AC-2(1)".
	FrameworkNIST80053R5 = "nist-sp-800-53-r5"
	// FrameworkFedRAMPKSI is a FedRAMP Key Security Indicator; controls like "KSI-IAM-JIT".
	FrameworkFedRAMPKSI = "fedramp-ksi"
	// FrameworkFedRAMPRule is a FedRAMP rule ID; controls like "CDS-CSO-PUB".
	FrameworkFedRAMPRule = "fedramp-rule"
)

// ControlRef maps a claim to a control in a framework.
type ControlRef struct {
	// Framework, such as "nist-sp-800-53-r5", "fedramp-ksi" or "fedramp-rule".
	Framework string `json:"framework"`
	// Control ID, such as "SC-8", "KSI-IAM-JIT" or "CDS-CSO-PUB".
	Control string `json:"control"`
}
