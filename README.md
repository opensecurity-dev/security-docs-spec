# Security Docs Spec

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Coverage][coverage-svg]][coverage-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/opensecurity-dev/security-docs-spec/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/opensecurity-dev/security-docs-spec/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/opensecurity-dev/security-docs-spec/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/opensecurity-dev/security-docs-spec/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/opensecurity-dev/security-docs-spec/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/opensecurity-dev/security-docs-spec/actions/workflows/go-sast-codeql.yaml
 [coverage-svg]: https://img.shields.io/badge/coverage-81.6%25-green
 [coverage-url]: https://github.com/opensecurity-dev/security-docs-spec
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/opensecurity-dev/security-docs-spec
 [docs-godoc-url]: https://pkg.go.dev/github.com/opensecurity-dev/security-docs-spec
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/opensecurity-dev/security-docs-spec/blob/main/LICENSE

An open format for the self-attested security documents a cloud service
publishes, and `secdocs`, a Go CLI that lints and renders it. It aligns
with NIST SP 800-53 and FedRAMP's Consolidated Rules for 2026, and builds
only on sources that allow free reuse ([licensing](docs/licensing.md)).

One JSON file per product is the intermediate representation. People and
tools fill it in, and `secdocs lint` says what is still to be done. Then
`secdocs render` and `secdocs export` publish the same content as Markdown
and JSON. A static site or Pandoc turns the Markdown into web pages, DOCX
or PDF.

## Why

- **A fact is stated once.** Backup retention, the deletion window and the
  incident-notification window are typed values. The security overview and
  the data-handling page include them, so the two cannot disagree.
- **Every claim says how true it is.** Each claim has a status (implemented,
  partial, planned, alternative, not-applicable or todo) and a verification
  level (unverified, reviewed or verified). Partial and planned claims must
  state their gap. Gaps are published as gaps.
- **Lint is the to-do list.** Unassessed claims, missing dates, stale
  reviews and contradictions are reported by JSON path.
- **Rendering cannot leak.** Each claim is `public`, `nda` or `internal`.
  Content above the audience is removed before rendering.
- **Human- and machine-readable from one view.** The JSON export and the
  Markdown come from the same filtered set. FedRAMP's certification data
  sharing rule asks for both, kept consistent.
- **Control references** to NIST SP 800-53, FedRAMP KSIs and FedRAMP
  rules are checked for format. Other frameworks may be named by ID only.

## Install

```bash
go install github.com/opensecurity-dev/security-docs-spec/cmd/secdocs@latest
```

## Use

```bash
# Start a set where every claim is "todo"
secdocs init --org "Example Co" --product "Example Notes" -o security-docs.json

# What is left to do? Exits 1 at --fail-on (default: error)
secdocs lint security-docs.json
secdocs lint --fail-on warning security-docs.json   # the gate before publishing

# Markdown and JSON for the website
secdocs render security-docs.json --json -o public

# One file for customers under NDA, converted with Pandoc
secdocs render security-docs.json --audience nda --front-matter --single security.md -o nda
pandoc nda/security.md -o security.docx

# Review a draft, with unassessed claims marked
secdocs render security-docs.json --draft -o draft

# RFC 9116 security.txt
secdocs security-txt security-docs.json > .well-known/security.txt

# The JSON Schema
secdocs schema
```

See [examples/example-notes](examples/example-notes) for a complete
fictional set and its rendered output.

## The document set

| Document | Slug | Contents |
|---|---|---|
| Security overview | `security-overview` | Sections of practices, plus fact groups |
| Security response | `security-response` | Reporting channels, process, scope, safe harbor, acknowledgements |
| Subprocessors | `subprocessors` | Name, purpose, locations, headquarters, data categories |
| Data handling | `data-handling` | Deletion, retention, backups, location, transfers |
| Incident response | `incident-response` | Notification commitment, process, drills, history |
| Availability | `availability` | An uptime commitment, or a statement that none is made |
| Custom | any | Sections, for anything else |

Fact groups, written once and included by any section: `hosting`,
`encryption`, `backups`, `dataLifecycle`, `accessControl`,
`incidentNotification`, `lawEnforcement`, `certifications`.

Prose may use placeholders: `{{org.name}}`, `{{product.name}}`,
`{{contact.security}}`, `{{doc.security-response}}` and so on. An unknown
key is a lint error.

## As a library

```go
set, err := spec.Load("security-docs.json")
report := lint.Run(set, lint.Options{})
files, err := render.Render(set, render.Options{Audience: spec.VisibilityPublic})
```

Analyzers can build or patch a `spec.DocumentSet` and record where each
fact came from in `source`.

## Development

```bash
go generate ./schema          # after changing types in spec/
go test ./render -update      # after an intended change to rendered output
go test ./... && golangci-lint run
```

Specs: [PRD](docs/specs/PRD.md), [TRD](docs/specs/TRD.md),
[PLAN](docs/specs/PLAN.md), [ROADMAP](docs/specs/ROADMAP.md).

## License

The code and specification are released under the [MIT License](LICENSE).
They build only on sources that allow free reuse, including commercially.
Frameworks with restrictive terms are referenced by identifier only; see
[docs/licensing.md](docs/licensing.md).
