# TRD — Security Docs Spec

Technical design for [PRD.md](PRD.md). Process is in [PLAN.md](PLAN.md);
work items are in [ROADMAP.md](ROADMAP.md).

## 1. Packages

```text
spec/            Go types (the IR), parsing, audience filter, placeholders, scaffold
schema/          generated JSON Schema, embedded; `go generate ./schema`
lint/            rules over a DocumentSet; findings with rule, severity, JSON path
render/          Markdown per document, combined file, JSON export, security.txt
cmd/secdocs/     Cobra CLI, thin over the packages
examples/        a fictional, complete set and its golden output
```

Library first: everything the CLI does is a function call another Go
program (an analyzer, a compliance engine, a site build) can make.

## 2. The IR

A `DocumentSet` is one product's documentation:

| Field | Purpose |
|---|---|
| `schemaVersion` | IR version (`0.1`) |
| `organization`, `product`, `contacts` | Names, URLs and role addresses used by every document |
| `publication` | Where the output is served, for absolute links in security.txt |
| `review.intervalDays` | How old a document's `reviewedAt` may be |
| `facts` | Typed fact groups, each a claim |
| `documents` | The documents; a missing one is not produced |

### 2.1 Claims

Every practice, fact group, channel, subprocessor, certification and
availability commitment embeds `Claim`:

| Field | Rule |
|---|---|
| `status` | OSCAL implementation-status words plus `todo`; empty is reported |
| `visibility` | `public` (default), `nda`, `internal` |
| `verification` | `unverified` (default), `reviewed`, `verified` |
| `gap`, `trackingRef` | Required gap for `partial` and `planned` |
| `justification` | Required for `not-applicable` |
| `source` | `manual`, `analyzer`, `attestation`, `evidence`, `inherited`, with a reference and date |
| `evidence` | References; only those marked `public` are ever rendered |
| `controlRefs` | Framework and control ID: `nist-sp-800-53-r5` / `SC-8`, `fedramp-ksi` / `KSI-MLA-LET`, `fedramp-rule` / `CDS-CSO-PUB`. Lint checks the ID format of these three. Restricted frameworks may be named by ID only |
| `notes` | Internal; never rendered outside the internal audience |

### 2.2 Facts and includes

A section's `include` renders a fact group as fixed sentences. The security
overview and the data-handling document both include `backups` and
`dataLifecycle`, so they cannot disagree. Lint checks cross-fact
consistency, e.g. backups that outlive the stated deletion window.

### 2.3 Placeholders

Prose may use `{{org.name}}`, `{{product.name}}`, `{{contact.security}}`,
`{{doc.<slug>}}` and a few more. It is a fixed substitution, not a template
language, so prose cannot reach fields that are not listed. Unknown keys
are lint errors.

## 3. Lint

Findings carry a rule ID, a severity and a JSON path. Severities:

- **error:** invalid or contradictory (bad enum or date, a planned claim
  with no gap, an include with no fact, an expired certification or
  security.txt, a duplicate ID or slug, an unknown placeholder).
- **warning:** work left before publishing (`todo` or missing status,
  missing `lastUpdated`, missing or stale `reviewedAt`, TODO markers in
  prose, missing backup retention or deletion window, a hosting provider
  absent from the subprocessor list).
- **info:** advice (no response target, no safe-harbor statement, no
  change-notification URL). `--strict` raises unverified public claims
  from info to warning.

`--fail-on` sets the exit threshold; `warning` is the publication gate.

## 4. Rendering

1. `ForAudience` deep-copies the set and removes documents, sections,
   practices, channels, subprocessors, certifications and fact groups the
   audience may not see, plus notes, sources, owners and non-public
   evidence. The renderer only ever sees this copy.
2. Claims render by status: implemented and alternative as stated; partial
   and planned with an "In progress" or "Planned" note carrying the gap
   (`--hide-gaps` keeps the label, drops the text); not-applicable and todo
   only in `--draft`, with visible markers and a DRAFT banner.
3. Each document is a Markdown file with an H1 title or, with
   `--front-matter`, YAML front matter for Pandoc. `--single` joins them
   into one file for a single DOCX or PDF.
4. `export` (and `render --json`) writes the same filtered view as JSON,
   so the human-readable and machine-readable copies cannot disagree, as
   FedRAMP's CDS-CSO-PUB asks. It refuses a set with unassessed claims,
   because the Markdown leaves those out, unless `--draft`.
5. `security-txt` writes RFC 9116 from the public security-response
   document, preferring dedicated security channels.

The renderer is Go code, not templates, so whitespace and tables are
deterministic and golden-tested. Wording overrides are a roadmap item.

## 5. Schema

`schema.Generate` reflects `spec.DocumentSet` with
`github.com/invopop/jsonschema`, reading field comments from `spec/` as
descriptions. The schema is committed and embedded; a test fails when it is
stale, and `schemakit lint --property-case camelCase` passes on it.
Parsing rejects unknown fields, so a misspelled key is an error, not a
silently missing claim.

## 6. Populating the IR

The IR is the meeting point for producers:

- **People** edit JSON directly, starting from `secdocs init`.
- **Analyzers** write fact groups with `source.kind: analyzer` and
  `verification: unverified`; a person raises verification after review.
- **Compliance engines** can map control statuses to practices through
  `controlRefs`.

Inputs that name hosts, accounts or internal paths stay in the producer's
private repository; only the reviewed, rendered output is published.

## 7. FedRAMP and NIST

FedRAMP's Consolidated Rules for 2026 (CR26) replace Word and Excel
templates with JSON documents and make OSCAL optional. FedRAMP now speaks
of certification classes A–D rather than Low, Moderate and High.

| CR26 | This IR |
|---|---|
| CDS-CSO-PUB: public information in human-readable and JSON form | `render` and `export` from one view; service offering block (roadmap) |
| Certification Package Overview (FRC-CSO-PKG) schema | Export target (roadmap) |
| Incident Report (IEC) | `incidentResponse`, `incidentNotification` |
| Significant Change Notification (SCN) | Change notices (roadmap) |
| Vulnerability Detection and Response, Evaluation and Reporting (VDR, VER) | `securityResponse` |
| Key Security Indicators | `controlRefs` with `fedramp-ksi`; KSI coverage document (roadmap) |

NIST SP 800-53 Rev 5 is the control vocabulary; OSCAL is one output, not
the internal model.

## 8. Open decisions

| Decision | Options |
|---|---|
| Open questionnaire | Its own question set mapped to NIST and KSIs (planned); restricted questionnaires are out of scope here |
| Product variants | One set per product, or an organization base set with per-product overlays |
| Wording overrides | Go templates per fact group, or a phrasebook of sentences |
| Revision history | Rely on git, or carry dated revisions in the IR |
