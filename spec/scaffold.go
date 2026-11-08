package spec

// Scaffold returns a starter DocumentSet with every document and the
// practices a SaaS security page usually covers, each with status "todo".
// Lint on a scaffold lists everything left to assess. Remove what does not
// apply, or mark it not-applicable with a justification.
func Scaffold(org, product string) *DocumentSet {
	todo := Claim{Status: StatusTodo}
	p := func(id, title string) Practice { return Practice{ID: id, Title: title, Claim: todo} }
	return &DocumentSet{
		SchemaVersion: SchemaVersion,
		Organization:  Organization{Name: org},
		Product:       Product{Name: product},
		Contacts:      Contacts{Security: &Contact{}, Support: &Contact{}, Privacy: &Contact{}},
		Review:        ReviewPolicy{IntervalDays: 365},
		Facts: Facts{
			Hosting:              &Hosting{Claim: todo},
			Encryption:           &Encryption{Claim: todo},
			Backups:              &Backups{Claim: todo},
			DataLifecycle:        &DataLifecycle{Claim: todo},
			AccessControl:        &AccessControl{Claim: todo},
			IncidentNotification: &IncidentNotification{Claim: todo},
			LawEnforcement:       &LawEnforcement{Claim: todo},
		},
		Documents: Documents{
			SecurityOverview: &SecurityOverview{
				DocMeta: DocMeta{Title: "Security overview", Description: "How we keep {{product.name}} and your data secure."},
				Sections: []Section{
					{ID: "hosting", Title: "Where your data lives", Include: IncludeHosting},
					{ID: "encryption", Title: "Your data is encrypted", Include: IncludeEncryption},
					{ID: "backups", Title: "Backups and redundancy", Include: IncludeBackups, Practices: []Practice{
						p("redundancy", "Redundancy"),
					}},
					{ID: "access", Title: "Who can access your data", Include: IncludeAccessControl, Practices: []Practice{
						p("access-logging", "Access is logged"),
					}},
					{ID: "infrastructure", Title: "Infrastructure and software", Practices: []Practice{
						p("patching", "Security updates"),
						p("network", "Network protection"),
						p("secure-development", "Secure development"),
						p("dependencies", "Dependency scanning"),
					}},
					{ID: "monitoring", Title: "Monitoring", Practices: []Practice{
						p("security-monitoring", "Security monitoring"),
						p("abuse-protection", "Abuse protection"),
					}},
					{ID: "physical", Title: "Physical security", Practices: []Practice{
						p("physical", "Data centers"),
					}},
					{ID: "billing", Title: "Billing information", Practices: []Practice{
						p("payments", "Payment processing"),
					}},
					{ID: "testing", Title: "Security testing", Practices: []Practice{
						p("vulnerability-reports", "Vulnerability reports"),
						p("penetration-testing", "Penetration testing"),
					}},
					{ID: "incidents", Title: "If something goes wrong", Include: IncludeIncidentNotification},
					{ID: "legal", Title: "Requests for your data", Include: IncludeLawEnforcement},
					{ID: "contact", Title: "Reporting a concern", Intro: "See our [security response page]({{doc.security-response}}) to report a vulnerability or an incident."},
				},
			},
			SecurityResponse: &SecurityResponse{
				DocMeta: DocMeta{Title: "Security response", Description: "How to report a security problem in {{product.name}}."},
				Channels: []ReportingChannel{
					{ID: "email", Kind: ChannelEmail, Purpose: "Report a security vulnerability", Claim: todo},
				},
			},
			Subprocessors: &Subprocessors{
				DocMeta: DocMeta{Title: "Subprocessors", Description: "The third parties that process personal data for {{product.name}}."},
			},
			DataHandling: &DataHandling{
				DocMeta: DocMeta{Title: "Data handling", Description: "Where your data is stored, how long we keep it, and how it is deleted."},
				Sections: []Section{
					{ID: "deletion", Title: "Deleting your data", Include: IncludeDataLifecycle},
					{ID: "backups", Title: "Backups", Include: IncludeBackups},
					{ID: "location", Title: "Location of your data", Include: IncludeHosting, Practices: []Practice{
						p("transfers", "International transfers"),
					}},
				},
			},
			IncidentResponse: &IncidentResponse{
				DocMeta: DocMeta{Title: "Incident response", Description: "How we handle security incidents and tell you about them."},
				History: &Practice{ID: "history", Title: "Breach history", Claim: todo},
			},
			Availability: &Availability{
				DocMeta: DocMeta{Title: "Availability", Description: "Uptime commitments for {{product.name}}."},
			},
		},
	}
}
