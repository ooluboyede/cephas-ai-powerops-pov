# CEPHAS PowerOps PoV — Product scope and module register

## Product definition

This repository is the standalone proof-of-value application for **CEPHAS PowerOps**. It is intended to demonstrate the broader PowerOps product to IBEDC first and subsequently to other electricity distribution companies (DisCos).

Revenue Assurance is a module/workstream inside PowerOps. It is not the product identity, repository purpose, or complete PoV scope.

## Demonstration principles

- Deliver a fully working, interactive PoV experience using synthetic data.
- Begin with synthetic data and fixtures; customer data validation is a later, separately approved activity.
- Keep the PoV independently deployable and isolated from the enterprise PowerOps application, databases, credentials and runtime.
- Make module boundaries and implementation status explicit.
- Treat analytics and recommendations as advisory. No SCADA/ADMS/DMS control, switching, dispatch, meter commands, financial postings, billing adjustments or refunds.
- Never present synthetic results as IBEDC results or as measured customer value.

## Module register

| Workstream | Status in this repository | Notes |
|---|---|---|
| Revenue Assurance | **Implemented initial slice; validation pending** | Extracted browser dashboard and Gate 0.4.2 deterministic synthetic billing/payment reconciliation. |
| Other PowerOps capabilities | **Not yet implemented / scope to be gated** | Must be added as PowerOps modules, not used to redefine the repository as a single-module product. |

This register deliberately does not claim that additional modules are implemented. Each module requires an agreed scope, user journey, synthetic data model, safety boundary, tests and gate acceptance criteria before implementation status changes.

## Current technical baseline

- Standalone static browser PoV.
- Synthetic Revenue Assurance fixtures and deterministic reconciliation engine.
- Node-based unit tests.
- Independent CI workflow; successful GitHub Actions execution is pending.
- Browser end-to-end, accessibility, deployment and independent security validation remain pending.

## Separation from enterprise PowerOps

The PoV must remain a separate application and data boundary. It must not use the enterprise PowerOps database, production credentials, licence authority, secrets, migrations or runtime services. Validated concepts may later be ported into the enterprise product through separately reviewed changes; do not promote PoV code or demo controls directly into production.

## Release language

Use **“PowerOps PoV”** for the repository and demonstration product. Use **“Revenue Assurance module”** when describing the current implemented functional slice. Distinguish implemented, in progress, planned and validated work in every status report.
