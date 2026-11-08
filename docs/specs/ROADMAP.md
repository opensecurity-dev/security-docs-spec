# ROADMAP — Security Docs Spec

Specs: [PRD](PRD.md), [TRD](TRD.md), [PLAN](PLAN.md). Items carry stable IDs
and are reviewed and executed by phase. Phase status is derived from its
items.

## Phase 1 — IR, Lint & Output

**Theme:** A typed IR for the common security page set, a linter that is the to-do list, and output that cannot leak.

- [x] `RMI-SECURITYDOCSSPEC-001` Go types for the document set, claims and typed facts, with a generated, embedded JSON Schema linted by `schemakit`
- [x] `RMI-SECURITYDOCSSPEC-002` Linter: rule IDs, severities and JSON paths; status, gap, justification, date, review, placeholder and cross-fact consistency rules
- [x] `RMI-SECURITYDOCSSPEC-003` Audience filter and Markdown renderer per document, with draft mode, gap handling, front matter and a combined file for Pandoc
- [x] `RMI-SECURITYDOCSSPEC-004` `secdocs` CLI: `init`, `lint`, `render`, `export`, `security-txt`, `schema`
- [x] `RMI-SECURITYDOCSSPEC-005` Fictional example with golden output, leak tests and RFC 9116 security.txt
- [x] `RMI-SECURITYDOCSSPEC-006` Machine-readable JSON from the same filtered view as the Markdown, refusing unassessed claims; NIST, KSI and FedRAMP rule ID formats in control references

## Phase 2 — Trust Center Essentials

**Theme:** What an organization needs to show it is secure, honestly, using only open material.

- [ ] `RMI-SECURITYDOCSSPEC-025` Attestation statement: who attests, the date, the scope and the set version, with fixed wording that the documents are self-attested and not an audit or certification
- [ ] `RMI-SECURITYDOCSSPEC-013` Trust-center index document: grouped links with descriptions and alternate formats, including documents the publisher holds itself
- [ ] `RMI-SECURITYDOCSSPEC-012` An original, openly licensed security questionnaire with its own IDs, each question mapped to NIST controls and KSIs, answered from the IR
- [ ] `RMI-SECURITYDOCSSPEC-014` Audit and assessment entries: issuer, basis, period, scope and carve-outs, availability, and the right to publish a third-party report
- [ ] `RMI-SECURITYDOCSSPEC-026` Publisher's guide: from `secdocs init` to a published trust center, what self-attested means, and how to state gaps

## Phase 3 — FedRAMP & NIST Alignment

**Theme:** Publish what FedRAMP's 2026 rules ask for, in the formats they name.

- [ ] `RMI-SECURITYDOCSSPEC-007` Service offering block for CDS-CSO-PUB: service and deployment model, business category, service list with security categories, secure configuration guidance, trust center and documentation links, next ongoing report date
- [ ] `RMI-SECURITYDOCSSPEC-008` Export to FedRAMP CR26 JSON documents (Certification Package Overview first, then Incident Report and Significant Change Notification), validated against FedRAMP's schemas
- [ ] `RMI-SECURITYDOCSSPEC-009` KSI coverage document: per indicator, status, explanation, cycle, verification, automation and validation, with IDs and names from FedRAMP's rules data
- [ ] `RMI-SECURITYDOCSSPEC-010` NIST SP 800-53 Rev 5 control references checked against the catalog, with control titles rendered from it
- [ ] `RMI-SECURITYDOCSSPEC-011` OSCAL as a published format: practices with control references exported as an OSCAL component definition
- [ ] `RMI-SECURITYDOCSSPEC-015` Change notices: dated revision notes and a feed of policy updates, aligned with FedRAMP's significant change notifications

## Phase 4 — Populating From Systems

**Theme:** Tools propose facts, people approve them, lint shows the rest.

- [ ] `RMI-SECURITYDOCSSPEC-016` Fact patches: merge a partial set into a base set, keeping provenance, refusing to overwrite reviewed or verified claims
- [ ] `RMI-SECURITYDOCSSPEC-017` Analyzer contract: a Go interface that produces fact patches with `source.kind: analyzer`
- [ ] `RMI-SECURITYDOCSSPEC-018` Reference analyzers on public signals: TLS version and HSTS, security headers, security.txt
- [ ] `RMI-SECURITYDOCSSPEC-019` `secdocs diff`: claim-level changes between two versions of a set, for review
- [ ] `RMI-SECURITYDOCSSPEC-020` Lint configuration: per-rule severity overrides and a publish profile

## Phase 5 — Many Products, Many Outputs

**Theme:** One organization, several products, several formats.

- [ ] `RMI-SECURITYDOCSSPEC-021` Organization base set with per-product overlays
- [ ] `RMI-SECURITYDOCSSPEC-022` Wording overrides for generated sentences
- [ ] `RMI-SECURITYDOCSSPEC-023` HTML output with anchors and JSON-LD
- [ ] `RMI-SECURITYDOCSSPEC-024` Pandoc recipe: reference DOCX, PDF settings and a Makefile target

External dependencies: the NIST SP 800-53 catalog ([`nist-sp-800-53-go`](https://github.com/opensecurity-dev/nist-sp-800-53-go)) for `RMI-SECURITYDOCSSPEC-010` and `RMI-SECURITYDOCSSPEC-011`, and the FedRAMP CR26 schema types ([`fedramp-schemas-go`](https://github.com/opensecurity-dev/fedramp-schemas-go)) for `RMI-SECURITYDOCSSPEC-008`.
