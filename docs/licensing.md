# Sources and Licensing

This specification is meant to be freely reusable, including commercially.
It therefore builds only on sources whose terms allow that, and names other
frameworks by identifier only.

## Five separate rights

Before adopting any external document, check each right on its own:

1. **Reading** it.
2. **Completing** it for your own organization.
3. **Publishing** your completed version.
4. **Redistributing the template itself**, including inside software.
5. **Offering it as a service:** generating, prefilling or publishing it
   for other organizations.

A vendor may be free to publish its own completed questionnaire while a
tool or service that produces that questionnaire for others needs a
license. This specification is meant to be used by commercial tools and
services, so it embeds only material for which the fourth and fifth rights
are free.

## Sources this specification builds on

| Source | Terms | Used for |
|---|---|---|
| NIST SP 800-53 Rev 5 and the NIST OSCAL content | US government work, public domain in the US, plus a CC0 1.0 waiver worldwide ([usnistgov/oscal-content](https://github.com/usnistgov/oscal-content/blob/main/LICENSE.md)) | Control references, control IDs, OSCAL as a publication format |
| FedRAMP Consolidated Rules for 2026, Key Security Indicators and JSON schemas ([FedRAMP/rules](https://github.com/FedRAMP/rules), [FedRAMP/schemas](https://github.com/FedRAMP/schemas)) | US government work (17 U.S.C. §105). The repositories carry no license file. The FedRAMP name and logo belong to GSA | Rule and KSI IDs, document alignment, export formats |
| RFC 9116 (security.txt) | IETF Trust Legal Provisions; field names and format are implemented, not copied | `secdocs security-txt` |

Using FedRAMP's rules or formats does not imply a FedRAMP certification.
Documents produced with this tool are self-attested unless they say
otherwise.

## Frameworks named by ID only

These frameworks restrict reproduction, modification or commercial reuse.
A document set may cite their identifiers in `controlRefs` (for example a
control or requirement number). Their control text, question text, titles
and layouts must not appear in this repository, in examples or in
contributions:

- CSA Cloud Controls Matrix and CAIQ
- EDUCAUSE HECVAT
- AICPA Trust Services Criteria (SOC 2)
- ISO/IEC 27001 and 27002
- PCI DSS and its self-assessment questionnaires
- Shared Assessments SIG

Third-party audit reports and certificates (for example a provider's SOC 2
or SOC 3 report) are published only with the rights to do so. A document set
records the report's name, kind and availability, not its contents.

A publisher that has completed a restricted questionnaire itself can link
to it from its document set, like any other document it holds. The link is
the publisher's own content. A tool that generates the questionnaire is a
different matter: that is the fifth right, and it needs the owner's license.

## Other organizations' security pages

Public security pages are good references for structure: which topics they
cover, how they state gaps, how they organize contacts. Their prose is not
copied. The example in this repository is fictional and original.
