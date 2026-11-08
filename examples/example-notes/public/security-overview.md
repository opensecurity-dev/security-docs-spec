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
