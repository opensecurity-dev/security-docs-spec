package spec

// DocMeta is the front matter every document has.
type DocMeta struct {
	Title string `json:"title"`
	// Slug names the rendered file, such as "security-overview". Defaults per document type.
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
	// LastUpdated is the date (YYYY-MM-DD) shown to readers.
	LastUpdated string `json:"lastUpdated,omitempty"`
	// ReviewedAt is the date (YYYY-MM-DD) a person last reviewed the whole document.
	ReviewedAt string `json:"reviewedAt,omitempty"`
	// Owner is the role responsible for the document. Never rendered.
	Owner string `json:"owner,omitempty"`
	// Visibility of the whole document; defaults to public.
	Visibility Visibility `json:"visibility,omitempty" jsonschema:"enum=public,enum=nda,enum=internal"`
}

// EffectiveVisibility returns the document's visibility, defaulting to public.
func (m DocMeta) EffectiveVisibility() Visibility {
	if m.Visibility == "" {
		return VisibilityPublic
	}
	return m.Visibility
}

// Include names a fact group a section renders.
type Include string

const (
	IncludeHosting              Include = "hosting"
	IncludeEncryption           Include = "encryption"
	IncludeBackups              Include = "backups"
	IncludeDataLifecycle        Include = "dataLifecycle"
	IncludeAccessControl        Include = "accessControl"
	IncludeIncidentNotification Include = "incidentNotification"
	IncludeLawEnforcement       Include = "lawEnforcement"
	IncludeCertifications       Include = "certifications"
)

// Includes lists every valid Include.
var Includes = []Include{IncludeHosting, IncludeEncryption, IncludeBackups, IncludeDataLifecycle,
	IncludeAccessControl, IncludeIncidentNotification, IncludeLawEnforcement, IncludeCertifications}

// Section is a heading with prose, practices and optionally a fact group.
// The rendered order is: intro, the included facts, practices, outro.
type Section struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Intro is Markdown shown before everything else in the section.
	Intro string `json:"intro,omitempty"`
	// Include renders a fact group from the document set's facts.
	Include   Include    `json:"include,omitempty" jsonschema:"enum=hosting,enum=encryption,enum=backups,enum=dataLifecycle,enum=accessControl,enum=incidentNotification,enum=lawEnforcement,enum=certifications"`
	Practices []Practice `json:"practices,omitempty"`
	// Outro is Markdown shown after everything else in the section.
	Outro      string     `json:"outro,omitempty"`
	Visibility Visibility `json:"visibility,omitempty" jsonschema:"enum=public,enum=nda,enum=internal"`
}

// Practice is one security practice stated as a claim.
type Practice struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
	// Statement is Markdown: what is done, in a sentence or two.
	Statement string `json:"statement,omitempty"`
	Claim
}

// SecurityOverview is the main security page of a service.
type SecurityOverview struct {
	DocMeta
	Intro    string    `json:"intro,omitempty"`
	Sections []Section `json:"sections,omitempty"`
}

// ChannelKind is how a security report is sent.
type ChannelKind string

const (
	ChannelEmail     ChannelKind = "email"
	ChannelBugBounty ChannelKind = "bug-bounty"
	ChannelWebForm   ChannelKind = "web-form"
	ChannelOther     ChannelKind = "other"
)

// ReportingChannel is one way to report a security problem.
type ReportingChannel struct {
	ID   string      `json:"id"`
	Kind ChannelKind `json:"kind" jsonschema:"enum=email,enum=bug-bounty,enum=web-form,enum=other"`
	// Purpose, such as "Report security vulnerabilities".
	Purpose string `json:"purpose"`
	// Address is an email address for email channels.
	Address string `json:"address,omitempty"`
	// URL is the program or form URL.
	URL string `json:"url,omitempty"`
	// ResponseTarget, such as "72 hours" or "two hours".
	ResponseTarget string `json:"responseTarget,omitempty"`
	// Note is Markdown shown after the channel.
	Note string `json:"note,omitempty"`
	Claim
}

// Acknowledgement credits a researcher.
type Acknowledgement struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
	Year int    `json:"year,omitempty"`
}

// EncryptionKey is a public key for encrypted reports.
type EncryptionKey struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// SecurityResponse is the vulnerability reporting and disclosure policy. It
// also feeds security.txt (RFC 9116).
type SecurityResponse struct {
	DocMeta
	Intro    string             `json:"intro,omitempty"`
	Channels []ReportingChannel `json:"channels,omitempty"`
	// Process is the ordered steps after a report arrives (Markdown each).
	Process []string `json:"process,omitempty"`
	// InScope and OutOfScope list targets and finding types.
	InScope    []string `json:"inScope,omitempty"`
	OutOfScope []string `json:"outOfScope,omitempty"`
	// SafeHarbor is the statement protecting good-faith research.
	SafeHarbor string `json:"safeHarbor,omitempty"`
	// DisclosureDays is the coordinated-disclosure window, if one is committed to.
	DisclosureDays   int               `json:"disclosureDays,omitempty"`
	EncryptionKey    *EncryptionKey    `json:"encryptionKey,omitempty"`
	Acknowledgements []Acknowledgement `json:"acknowledgements,omitempty"`
	// Sections are any extra headings.
	Sections []Section `json:"sections,omitempty"`
	// SecurityTxtExpires is the RFC 9116 Expires value (RFC 3339) for the generated security.txt.
	SecurityTxtExpires string `json:"securityTxtExpires,omitempty"`
}

// Subprocessor is a third party that processes customer personal data.
type Subprocessor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// URL links to the provider's privacy, GDPR or DPA page.
	URL     string `json:"url,omitempty"`
	Purpose string `json:"purpose"`
	// Locations where it processes or hosts data.
	Locations []Location `json:"locations,omitempty"`
	// Headquarters is where the contracting company is based, which can
	// differ from where it hosts data.
	Headquarters *Location `json:"headquarters,omitempty"`
	// DataCategories, such as "account identity", "billing", "customer content".
	DataCategories []string `json:"dataCategories,omitempty"`
	// TransferMechanism for personal data leaving the EU or UK, such as "SCCs" or "EU-US DPF".
	TransferMechanism string `json:"transferMechanism,omitempty"`
	// Since is the date (YYYY-MM-DD) it was added.
	Since string `json:"since,omitempty"`
	Claim
}

// Subprocessors is the list of third parties that process personal data.
type Subprocessors struct {
	DocMeta
	Intro string `json:"intro,omitempty"`
	// DPAURL links to the data processing addendum.
	DPAURL string `json:"dpaUrl,omitempty"`
	// ChangeNotificationURL is where customers subscribe to changes.
	ChangeNotificationURL string         `json:"changeNotificationUrl,omitempty"`
	Subprocessors         []Subprocessor `json:"subprocessors,omitempty"`
}

// DataHandling covers deletion, retention, location and transfers: the
// security-related parts of a privacy policy.
type DataHandling struct {
	DocMeta
	Intro    string    `json:"intro,omitempty"`
	Sections []Section `json:"sections,omitempty"`
}

// IncidentResponse summarizes how incidents are handled and reported.
type IncidentResponse struct {
	DocMeta
	Intro string `json:"intro,omitempty"`
	// Process is the ordered phases of the response (Markdown each).
	Process []string `json:"process,omitempty"`
	// Drills describes recovery and response exercises.
	Drills string `json:"drills,omitempty"`
	// History is a claim about past incidents, such as "no data breach to date".
	History  *Practice `json:"history,omitempty"`
	Sections []Section `json:"sections,omitempty"`
}

// ServiceCredit is one SLA credit rule.
type ServiceCredit struct {
	// Condition, such as "an outage exceeds 5 minutes in a day".
	Condition string `json:"condition"`
	// Credit, such as "10x the hourly rate for one hour".
	Credit string `json:"credit"`
}

// AvailabilityCommitment is an uptime target, with or without credits.
type AvailabilityCommitment struct {
	// TargetPercent, such as 99.9.
	TargetPercent float64 `json:"targetPercent"`
	// Period, such as "monthly".
	Period string `json:"period"`
	// AppliesTo names plans or customers the commitment covers; empty means all.
	AppliesTo   []string        `json:"appliesTo,omitempty"`
	Credits     []ServiceCredit `json:"credits,omitempty"`
	Measurement string          `json:"measurement,omitempty"`
	Exclusions  []string        `json:"exclusions,omitempty"`
	Claim
}

// Availability states uptime targets, or that none is made.
type Availability struct {
	DocMeta
	Intro      string                  `json:"intro,omitempty"`
	Commitment *AvailabilityCommitment `json:"commitment,omitempty"`
	// NoCommitment is the statement used when no target is made. Exactly one
	// of Commitment and NoCommitment is set.
	NoCommitment     string    `json:"noCommitment,omitempty"`
	StatusPageURL    string    `json:"statusPageUrl,omitempty"`
	UptimeHistoryURL string    `json:"uptimeHistoryUrl,omitempty"`
	Sections         []Section `json:"sections,omitempty"`
}

// CustomDocument is any other document built from sections, such as a
// longevity promise or an AI data-use statement.
type CustomDocument struct {
	DocMeta
	Intro    string    `json:"intro,omitempty"`
	Sections []Section `json:"sections,omitempty"`
}
