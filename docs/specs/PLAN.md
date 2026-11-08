# PLAN — Security Docs Spec

## Approach

1. **IR, lint and output** (Phase 1, done). A typed IR for the common
   security page set, a linter, Markdown and JSON from one filtered view,
   security.txt, and a fictional example with golden output.
2. **Trust center essentials** (Phase 2). An attestation statement, a
   trust-center index, an original open questionnaire mapped to NIST and
   KSIs, audit entries that record publication rights, and a publisher's
   guide. This is what an organization needs to present itself as secure,
   honestly, with no licensed material.
3. **FedRAMP and NIST alignment** (Phase 3). The CDS public-information
   fields, export to FedRAMP's CR26 JSON documents, KSI coverage, NIST
   control references checked against the catalog, OSCAL as a published
   format, and change notices.
4. **Populating from systems** (Phase 4). Fact patches with provenance, an
   analyzer contract, reference analyzers, and a diff for review.
5. **Many products, many outputs** (Phase 5). Organization base sets with
   product overlays, wording overrides, HTML, Pandoc recipes.

## Principles

- **Go structs are the source of truth;** schemas are generated.
- **A fact is stated once** and included where it is needed.
- **Unknown stays unknown:** an unassessed claim is `todo`, is never
  published and blocks the JSON export.
- **Gaps are published as gaps.**
- **Filtering happens before rendering,** so output cannot leak.
- **Only freely reusable sources;** restricted frameworks by ID only.
- **Public engine, private inputs:** this repository holds the format, the
  engine and fictional examples.

## Dependencies

- **NIST SP 800-53 Rev 5 catalog**
  ([`nist-sp-800-53-go`](https://github.com/opensecurity-dev/nist-sp-800-53-go))
  for control validation and titles.
- **FedRAMP CR26 schema types**
  ([`fedramp-schemas-go`](https://github.com/opensecurity-dev/fedramp-schemas-go))
  for the FedRAMP JSON export.
- **FedRAMP/rules** for KSI and rule IDs and names.

## Risks

| Risk | Mitigation |
|---|---|
| Restricted text enters through a contribution | [Licensing policy](../licensing.md); review; IDs-only rule |
| Use of FedRAMP formats is read as certification | Self-attested wording; certification `kind` is required and rendered |
| FedRAMP CR26 changes during 2026–2027 | Pin to dated schema sets and rules versions; regenerate |
| Generated sentences read stiffly | Free intro and outro prose per section; wording overrides later |
| Producers put private detail into public fields | Visibility per claim; notes never rendered; leak tests on output |
