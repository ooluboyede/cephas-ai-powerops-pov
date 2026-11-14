# Gate 0.4.1 — Independent PoV extraction

## Objective

Create a separately deployable PoV application, isolated from the enterprise PowerOps runtime and repository.

## Extraction source

The initial dashboard was copied from `demo/revenue-assurance/index.html` on branch `revenue-assurance/phase-0-foundation` in `ooluboyede/cephas-ai-powerops`. This is an extraction of the demonstration artifact only; no enterprise backend or database is copied.

## Included

- Responsive Revenue Assurance dashboard
- Twelve synthetic findings and demo-only interactions
- Overview, findings, investigation, reconciliation, reports, data quality and governance views
- Synthetic demo reset and export affordances already present in the source artifact

## Explicitly excluded

- Enterprise backend, APIs and production database
- Customer or IBEDC data
- Enterprise credentials, secrets, signing keys or licence authority
- Production authentication, authorisation, tenant registry or audit service
- Live billing, vending, payment, AMI/MDMS, SCADA, GIS, ERP or bank integrations
- Any operational command or financial posting capability

## Gate 0.4.1 acceptance

- [x] Dedicated private repository exists.
- [x] PoV UI extracted without changing the enterprise PR #20 source.
- [x] Independent package metadata and test command.
- [x] Independent CI workflow.
- [x] Separation boundary documented.
- [ ] CI executed successfully on the new repository's initial commit.
- [ ] Browser-level smoke tests and accessibility checks.
- [ ] Separate PoV application hosting/deployment configured.

## Known inherited limitations

The extracted HTML is functionally a static demo. Reviewer/approver separation is simulated, reconciliation values and fixture data need to become a true deterministic calculation workflow, evidence strings need source-record drilldown, scope/period selection is absent, CSV export needs spreadsheet-formula neutralisation, and dynamic HTML rendering needs hardening before untrusted imported text is ever introduced.

## Gate decision

**Repository extraction implemented; Gate 0.4.1 validation remains pending.** Do not call the PoV production-ready. Do not merge the enterprise PR or connect this repository to the enterprise database as a shortcut.
