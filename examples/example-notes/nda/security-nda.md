---
title: "Example Notes Security"
subtitle: "Example Co"
---

# Security overview

*Last updated: 2026-11-01*

Your notes are yours, and keeping them safe is our first job. This page says what we do, and where we are not there yet.

## Where your data lives

Example Notes runs in a private network on Amazon Web Services. Every request passes through Cloudflare, so the servers' addresses are never public.

- Customer data is stored in Oregon, United States.
- Infrastructure providers: Amazon Web Services, Cloudflare.

## Your data is encrypted

All data sent between you and Example Notes is encrypted with HTTPS, using TLS 1.2 or later. HTTP Strict Transport Security (HSTS) tells browsers never to connect without encryption. You can [check our TLS configuration](https://www.ssllabs.com/ssltest/analyze.html?d=notes.example.com).

Between Cloudflare and our servers, traffic is encrypted and the certificate is verified. Inside our private network, the application connects to its database over TLS.

| Data | Encrypted at rest | How |
|---|---|---|
| Application database | Yes | AES-256, keys managed by the cloud provider |
| Uploaded files | Yes | AES-256, keys managed by the cloud provider |
| Backups | Yes | AES-256 |

Passwords are never stored; we store a salted hash made with argon2id (64 MiB memory, 3 iterations).

Evidence: [SSL Labs report](https://www.ssllabs.com/ssltest/analyze.html?d=notes.example.com).

## Backups and redundancy

- Backups are taken continuously, with point-in-time restore, plus a nightly export of each database.
- Backups are kept for 30 days.
- Backups are encrypted and stored in a separate location from the live systems.
- Restores are tested: every quarter we restore a backup into a separate environment and check it.

**Redundancy.** The database runs with a standby in a second data center that takes over automatically if the primary fails.

## Who can access your data

- Staff access to production systems requires multi-factor authentication.
- Only the people who operate Example Notes can reach production systems, and only through an audited gateway.
- We look at your data only when you ask us to, to keep the service running, or when the law requires it.
- Everyone with access signs a confidentiality agreement.

> **In progress:** Access to production is reviewed when people join or leave, but not yet on a fixed schedule.

**Access is logged.** Every administrative session and every sign-in is recorded in a security event log.

## Infrastructure and software

**Security updates.** Operating system security updates install automatically. Application dependencies are checked for known vulnerabilities on every change.

**Network protection.** Our servers accept web traffic only from Cloudflare, and administrative access only from approved addresses.

**Secure development.** Every change is reviewed and tested before it is released, and the same release runs in a staging environment before production.

**Process isolation.** The application runs as an unprivileged user in a restricted sandbox.

## Monitoring

**Security monitoring.** Security events from the application are collected in one place.

> **In progress:** Alerts on suspicious activity are being set up; today the events are reviewed by hand.

**Abuse protection.** Sign-in and sign-up are rate limited to slow down password guessing.

## Physical security

**Data centers.** We run no servers of our own. Our cloud provider's data centers are guarded, access-controlled and independently audited.

Evidence: [AWS data center controls](https://aws.amazon.com/compliance/data-center/controls/).

## Billing information

**Payment processing.** Card details go straight to our payment processor; they never touch our servers.

## Security testing

**Vulnerability reports.** We welcome reports from security researchers. See our [security response page](security-response.md).

**Penetration testing.**

> **Planned:** We have not yet had an independent penetration test. The first is planned before we offer team plans.

## Audits and certifications

| Certification | Type | Scope | Valid until | Report |
|---|---|---|---|---|
| [SOC 2 Type II](https://aws.amazon.com/compliance/soc-faqs/) | Held by our provider | Amazon Web Services data centers |  | On request, under NDA |
| PCI DSS SAQ A | Self-assessment (not audited) | The payment page, which is hosted by our payment processor |  |  |

> PCI DSS SAQ A — **Planned:** The first self-assessment is scheduled for next quarter.

Example Co itself has not completed an independent audit, and this page is a self-assessment.

## If something goes wrong

If a security incident affects your data, we will notify the account owner within 72 hours of confirming it by email, and work with you until it is resolved.

## Requests for your data

- We do not hand over customer data to law enforcement or other government bodies without valid legal process, such as a court order.
- Unless the law prevents it, we tell affected customers when we receive such a request.

## Reporting a concern

See our [security response page](security-response.md) to report a vulnerability or an incident.

---

The history of changes to this document is [public](https://github.com/example/policies/commits/main).

# Security response

*Last updated: 2026-11-01*

If you have found a security problem in Example Notes, we want to hear about it.

## Reporting security problems

**Report a security vulnerability:** [security@example.com](mailto:security@example.com). We respond within 3 business days.

**For anything that is not urgent or sensitive:** [https://notes.example.com/support](https://notes.example.com/support).

## What happens after you report

1. We acknowledge your report.
2. We confirm the problem and assess its severity, and keep you informed.
3. We fix it. We do not disclose an issue until it is fixed.
4. We publish a note about the fix and, if you wish, credit you.

We aim to fix and disclose confirmed issues within 90 days of the report, and coordinate the disclosure date with you.

## Scope

In scope:

- notes.example.com and its subdomains
- The Example Notes desktop and mobile apps

Out of scope:

- Denial of service
- Social engineering of our staff or customers
- Reports from automated scanners without a demonstrated impact

## Safe harbor

We will not take legal action against research done in good faith that follows this policy, avoids harm to customers and their data, and gives us time to fix the problem before it is disclosed.

## Thanks

These researchers have helped us find, fix and disclose security issues safely:

- [A. Researcher](https://researcher.example.org) (2026)

---

The history of changes to this document is [public](https://github.com/example/policies/commits/main).

# Subprocessors

*Last updated: 2026-11-01*

We use a small number of third parties to run Example Notes. Each is bound by a data processing agreement.

| Subprocessor | Purpose | Location | Data |
|---|---|---|---|
| [Amazon Web Services](https://aws.amazon.com/compliance/gdpr-center/) | Cloud hosting | US | all customer data |
| [Cloudflare](https://www.cloudflare.com/trust-hub/gdpr/) | Network protection and content delivery | US | request metadata, IP addresses |
| [Stripe](https://stripe.com/legal/dpa) | Payment processing | US | billing details |
| Example Mail | Transactional email (planned) | EU, based in DE | email address |

To hear about changes to this list, [subscribe here](https://example.com/policy-updates).

---

The history of changes to this document is [public](https://github.com/example/policies/commits/main).

# Data handling

*Last updated: 2026-11-01*

## Deleting your data

- Content you delete stays in the trash for 30 days, where you can restore it.
- When you cancel your account, your content is deleted from our live systems within 30 days.
- Copies in backups expire, and all of your data is gone, within 60 days.
- You can export all of your notes as Markdown at any time from your account settings.

We keep billing records for as long as tax law requires.

## Backups

- Backups are taken continuously, with point-in-time restore, plus a nightly export of each database.
- Backups are kept for 30 days.
- Backups are encrypted and stored in a separate location from the live systems.
- Restores are tested: every quarter we restore a backup into a separate environment and check it.

## Location of your data

Example Notes runs in a private network on Amazon Web Services. Every request passes through Cloudflare, so the servers' addresses are never public.

- Customer data is stored in Oregon, United States.
- Infrastructure providers: Amazon Web Services, Cloudflare.

**International transfers.** If you are outside the United States, your data is transferred to and stored in the United States under Standard Contractual Clauses.

---

The history of changes to this document is [public](https://github.com/example/policies/commits/main).

# Incident response

*Last updated: 2026-11-01*

## Notification

If a security incident affects your data, we will notify the account owner within 72 hours of confirming it by email, and work with you until it is resolved.

## How we respond

1. **Detect.** Security events and alerts reach the on-call engineer.
2. **Contain.** We stop the incident from spreading, revoking credentials and isolating systems as needed.
3. **Notify.** We tell affected customers, as described above.
4. **Recover and learn.** We restore service, and write up what happened and what we changed.

## Drills

We rehearse restoring from backup every quarter.

## Our record

**Breach history.** To our knowledge, Example Notes has never had a data breach.

---

The history of changes to this document is [public](https://github.com/example/policies/commits/main).

# Availability

*Last updated: 2026-11-01*

We do not offer a service-level agreement. We work to keep Example Notes available and publish its status.

Current status is at [https://status.example.com](https://status.example.com).

---

The history of changes to this document is [public](https://github.com/example/policies/commits/main).
