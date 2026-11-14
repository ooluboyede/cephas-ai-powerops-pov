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
| Network operations | Implemented foundation; validation pending | Synthetic feeder/transformer fixtures, versioned feature engineering, exploratory kNN novelty scoring, explainable alert queue and simulated human triage |
| Outage & fault intelligence | Planned | Outage visibility, fault clustering and restoration support; no switching commands |
| Asset health & maintenance | Planned | Asset registry, condition indicators and maintenance prioritisation |
| Metering & energy intelligence | Planned | Meter data quality, consumption patterns and energy balance |
| Customer operations | Planned | Service requests, complaints and service-level monitoring |
| Field workforce | Planned | Work orders, crew coordination and field evidence |
| Revenue Assurance | Initial module slice implemented; validation pending | Synthetic findings, investigation workspace and deterministic payment reconciliation |
| Forecasting & planning | Planned | Load forecasting, demand scenarios and operational planning |

## Gate history
- Gate 0.5.1 adds the first interactive Network Operations workspace. All readings are synthetic and advisory-only.
- Gate 0.5.2 adds a reusable feature-engineering pipeline, exploratory kNN novelty scoring, explainable synthetic network alerts, a small synthetic benchmark and session-only human triage. Model performance is not field-validated.
- Gate 0.5.3 adds dataset/model SHA-256 manifests, feature-schema binding, evaluation metrics, PSI drift calculation and a fail-closed model promotion policy. The current four-case synthetic model remains blocked from promotion.

## Validation status
Unit tests can be run locally with `npm test`. Successful hosted CI, browser end-to-end, accessibility, independent security review and deployment are pending until evidenced.

## Separation and safety
The PoV must not import enterprise credentials, database migrations, licence signing keys, production services or runtime. Do not connect to SCADA/ADMS/DMS or send operational commands. Findings and recommendations require authorised human review. Synthetic values must never be represented as IBEDC measurements or customer outcomes.
