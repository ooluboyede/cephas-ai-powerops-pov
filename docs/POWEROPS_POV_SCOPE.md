# CEPHAS PowerOps PoV — Product scope and module register

## Product definition
Standalone proof-of-value application for CEPHAS PowerOps, targeting IBEDC first and then other DisCos. It demonstrates the wider utility operations platform, not a Revenue Assurance-only application.

## Demonstration principles
- Fully interactive PoV using synthetic data first.
- Customer-data validation only after explicit customer approval and isolated handling arrangements.
- Separate repository, application, database and runtime from the enterprise PowerOps product.
- Advisory intelligence only; no direct operational control or autonomous financial/customer action.
- Report implemented, planned and validated capabilities separately.

## Module register

| Module | Status | Current boundary |
|---|---|---|
| PowerOps command centre | Implemented foundation; validation pending | Synthetic cross-utility overview, module register, operational attention queue and feeder snapshot |
| Network operations | Planned | Feeder, transformer and network performance intelligence |
| Outage & fault intelligence | Planned | Outage visibility, fault clustering and restoration support; no switching commands |
| Asset health & maintenance | Planned | Asset registry, condition indicators and maintenance prioritisation |
| Metering & energy intelligence | Planned | Meter data quality, consumption patterns and energy balance |
| Customer operations | Planned | Service requests, complaints and service-level monitoring |
| Field workforce | Planned | Work orders, crew coordination and field evidence |
| Revenue Assurance | Initial module slice implemented; validation pending | Synthetic findings, investigation workspace and deterministic payment reconciliation |
| Forecasting & planning | Planned | Load forecasting, demand scenarios and operational planning |

## Validation status
Unit tests can be run locally with `npm test`. Successful hosted CI, browser end-to-end, accessibility, independent security review and deployment are pending until evidenced.

## Separation and safety
The PoV must not import enterprise credentials, database migrations, licence signing keys, production services or runtime. Do not connect to SCADA/ADMS/DMS or send operational commands. Findings and recommendations require authorised human review. Synthetic values must never be represented as IBEDC measurements or customer outcomes.
