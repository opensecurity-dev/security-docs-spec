package spec

// Facts are the typed values that several documents state. Keeping them in
// one place means the security overview, the data-handling summary and the
// incident-response summary cannot disagree about, say, backup retention.
// Documents pull a fact group into a section with Section.Include.
type Facts struct {
	Hosting              *Hosting              `json:"hosting,omitempty"`
	Encryption           *Encryption           `json:"encryption,omitempty"`
	Backups              *Backups              `json:"backups,omitempty"`
	DataLifecycle        *DataLifecycle        `json:"dataLifecycle,omitempty"`
	AccessControl        *AccessControl        `json:"accessControl,omitempty"`
	IncidentNotification *IncidentNotification `json:"incidentNotification,omitempty"`
	LawEnforcement       *LawEnforcement       `json:"lawEnforcement,omitempty"`
	Certifications       []Certification       `json:"certifications,omitempty"`
}

// Hosting is where the product runs and where its data is stored.
type Hosting struct {
	Claim
	// Locations, such as {"country": "US", "region": "Oregon"}.
	Locations []Location `json:"locations,omitempty"`
	// Providers names the infrastructure providers; each should also be a subprocessor.
	Providers []string `json:"providers,omitempty"`
	// Description is optional prose, such as how the network is segmented.
	Description string `json:"description,omitempty"`
}

// Location is a country and an optional region within it.
type Location struct {
	// Country is an ISO 3166-1 alpha-2 code, or "EU".
	Country string `json:"country"`
	Region  string `json:"region,omitempty"`
}

// Encryption covers data in transit, at rest and in use.
type Encryption struct {
	Claim
	InTransit       *EncryptionInTransit  `json:"inTransit,omitempty"`
	AtRest          []DataStoreEncryption `json:"atRest,omitempty"`
	PasswordHashing *PasswordHashing      `json:"passwordHashing,omitempty"`
	// ApplicationLevel describes field-level or "at-work" encryption, if any.
	ApplicationLevel string `json:"applicationLevel,omitempty"`
}

// EncryptionInTransit describes encryption between clients and the service.
type EncryptionInTransit struct {
	// MinTLSVersion, such as "1.2".
	MinTLSVersion string `json:"minTlsVersion,omitempty"`
	HSTS          bool   `json:"hsts,omitempty"`
	// Internal describes traffic inside the private network, including any
	// that is not encrypted.
	Internal string `json:"internal,omitempty"`
	// ReportURL is a public scan of the TLS setup, such as SSL Labs.
	ReportURL string `json:"reportUrl,omitempty"`
}

// DataStoreEncryption says whether one data store is encrypted at rest.
type DataStoreEncryption struct {
	// Store is a role, such as "application database", "file storage", "backups".
	Store     string `json:"store"`
	Encrypted bool   `json:"encrypted"`
	// Method, such as "AES-256 (provider-managed keys)" or "GPG".
	Method string `json:"method,omitempty"`
	Note   string `json:"note,omitempty"`
}

// PasswordHashing describes how passwords are stored.
type PasswordHashing struct {
	// Algorithm, such as "bcrypt" or "argon2id".
	Algorithm  string `json:"algorithm"`
	Parameters string `json:"parameters,omitempty"`
	// NotApplicable explains a product with no passwords, such as passkey or SSO-only sign-in.
	NotApplicable string `json:"notApplicable,omitempty"`
}

// Backups describes database and file backups.
type Backups struct {
	Claim
	// Frequency, such as "hourly", "daily", "continuous (point-in-time restore)".
	Frequency     string `json:"frequency,omitempty"`
	RetentionDays int    `json:"retentionDays,omitempty"`
	Encrypted     bool   `json:"encrypted,omitempty"`
	Offsite       bool   `json:"offsite,omitempty"`
	// RestoreTesting, such as "quarterly restore drills".
	RestoreTesting string `json:"restoreTesting,omitempty"`
}

// DataLifecycle is what happens to customer data when it is deleted or the
// account is cancelled.
type DataLifecycle struct {
	Claim
	// TrashRetentionDays is how long trashed content stays recoverable; 0 means no trash.
	TrashRetentionDays int `json:"trashRetentionDays,omitempty"`
	// PurgeAfterCancellationDays is when cancelled accounts' data leaves live systems.
	PurgeAfterCancellationDays int `json:"purgeAfterCancellationDays,omitempty"`
	// BackupExpiryDays is when the last backup holding deleted data expires,
	// counted from deletion. It is at least PurgeAfterCancellationDays.
	BackupExpiryDays int `json:"backupExpiryDays,omitempty"`
	// Export describes how customers take their data out.
	Export string `json:"export,omitempty"`
	// Retention is optional prose about other retention periods.
	Retention string `json:"retention,omitempty"`
}

// AccessControl is how staff get to production systems and customer data.
type AccessControl struct {
	Claim
	// MFARequired for staff access to production and administrative consoles.
	MFARequired bool `json:"mfaRequired,omitempty"`
	// LeastPrivilege describes how access is limited.
	LeastPrivilege string `json:"leastPrivilege,omitempty"`
	// CustomerDataAccess describes when staff may read customer data and how it is audited.
	CustomerDataAccess string `json:"customerDataAccess,omitempty"`
	// Personnel describes agreements, background checks and training.
	Personnel string `json:"personnel,omitempty"`
	// Endpoints describes how staff devices are secured.
	Endpoints string `json:"endpoints,omitempty"`
}

// IncidentNotification is the commitment to tell customers about an incident.
type IncidentNotification struct {
	Claim
	// NotifyWithinHours after confirming an incident that affects the customer's data.
	NotifyWithinHours int `json:"notifyWithinHours,omitempty"`
	// Timing is used when no hour figure is committed, such as "without undue delay".
	Timing string `json:"timing,omitempty"`
	// Recipient, such as "the account owner".
	Recipient string `json:"recipient,omitempty"`
	// Channel, such as "email".
	Channel string `json:"channel,omitempty"`
}

// LawEnforcement is how requests for customer data from governments are handled.
type LawEnforcement struct {
	Claim
	RequiresLegalProcess bool `json:"requiresLegalProcess,omitempty"`
	NotifiesCustomers    bool `json:"notifiesCustomers,omitempty"`
	// TransparencyURL links to a transparency report, if any.
	TransparencyURL string `json:"transparencyUrl,omitempty"`
	Description     string `json:"description,omitempty"`
}

// CertificationKind distinguishes an independent audit from a self-assessment.
type CertificationKind string

const (
	CertificationAudit          CertificationKind = "audit"
	CertificationSelfAssessment CertificationKind = "self-assessment"
	CertificationInherited      CertificationKind = "inherited"
)

// Certification is an audit, self-assessment or a provider's attestation the
// product relies on. A self-attested document must not read as an audit, so
// the kind is required.
type Certification struct {
	Claim
	// Name of the certification or report. Only the name is recorded; the
	// framework's own text never belongs in a document set.
	Name string            `json:"name"`
	Kind CertificationKind `json:"kind" jsonschema:"enum=audit,enum=self-assessment,enum=inherited"`
	// Issuer is the auditor or assessor, such as a QSA firm.
	Issuer string `json:"issuer,omitempty"`
	// Period is the audit period, such as "2025-07-01/2026-06-30".
	Period string `json:"period,omitempty"`
	// Scope, such as "the payment page" or, for inherited, "AWS data centers".
	Scope string `json:"scope,omitempty"`
	// ValidUntil is a date (YYYY-MM-DD).
	ValidUntil string `json:"validUntil,omitempty"`
	// AvailableUnderNDA says the report is shared with customers under an NDA.
	AvailableUnderNDA bool   `json:"availableUnderNda,omitempty"`
	URL               string `json:"url,omitempty"`
}
