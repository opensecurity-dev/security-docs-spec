# PRD — Security Docs Spec

## Summary

An open, commercially reusable format for the self-attested security
documents a cloud service publishes, and a Go engine that lints and renders
it. One JSON file per product is the intermediate representation (IR).
People and tools fill it in, `secdocs lint` says what is left to do, and
`secdocs render` and `secdocs export` publish the same content as Markdown
and JSON. The specification aligns with NIST SP 800-53 and FedRAMP's
Consolidated Rules for 2026, and builds only on sources that allow free
reuse ([licensing](../licensing.md)).

## Problem

- **Security pages are written by hand and drift.** The same fact (backup
  retention, the deletion window, the notification window) is repeated
  across pages, and the copies disagree over time.
- **Unknowns hide in prose.** A page cannot say which claims were checked,
  which are plans and which nobody has looked at.
- **Gaps are left out rather than stated.** Strong security pages state
  the negatives plainly; hand-written ones tend to omit them.
- **Machine-readable publication is becoming a requirement.** FedRAMP's
  certification data sharing rule (CDS-CSO-PUB) requires providers to
  share public information in both human-readable and JSON form, kept
  consistent by automation.
- **The common questionnaires are licensed.** CAIQ, HECVAT, SOC 2 criteria,
  ISO 27001 and PCI materials cannot be embedded in an open tool. An open
  format must rest on NIST and FedRAMP instead.

## Users

- **Engineers and operators** who know the system and fill in the facts.
- **Analyzers and agents** that inspect a system and propose facts.
- **Reviewers** (security lead, counsel) who approve wording.
- **Customers, agencies and their GRC tools**, which read the Markdown or
  the JSON.

## Goals

1. **A Go-first IR** with a generated, embedded JSON Schema.
2. **Typed facts, stated once,** included by any document.
3. **Every claim carries** status (OSCAL implementation-status words plus
   `todo`), visibility (public, NDA, internal), verification, source,
   evidence and control references (NIST SP 800-53, FedRAMP KSIs and rules).
4. **A linter that is the to-do list,** including control-ID formats.
5. **Human-readable and machine-readable output from one filtered view,**
   so they cannot disagree, and nothing above the audience is published.
6. **FedRAMP alignment:** the CDS public-information fields, KSI coverage,
   and export to FedRAMP's JSON documents and to OSCAL.

## Non-goals

- **A compliance platform.** No workflow, approvals or evidence storage.
- **A FedRAMP certification or any claim of one.**
- **Restricted frameworks' content.** They are referenced by ID only.
- **OSCAL as the internal model.** OSCAL is one published format; the IR
  stays small.
- **DOCX/PDF generation in Go.** Pandoc and similar tools do that.

## Success criteria

- A product's whole security page set renders from one JSON file, and the
  same fact reads the same everywhere.
- `secdocs lint --fail-on warning` passes only when nothing is unassessed,
  undated or unreviewed.
- Public output, Markdown and JSON, never contains NDA or internal content
  (tested).
- The schema is generated, current and lint-clean; the repository contains
  no restricted framework text.
