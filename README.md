# CEPHAS PowerOps PoV

**Product:** CEPHAS PowerOps — standalone proof-of-value application  
**Initial utility target:** IBEDC, followed by other DisCos  
**Data approach:** Synthetic demonstration data first; customer-data validation only after explicit customer approval  
**Deployment boundary:** Separate application and repository from the CEPHAS PowerOps enterprise platform

## Product identity and scope
This repository is the overall **PowerOps PoV**, not a Revenue Assurance-only product. Revenue Assurance is one module/workstream within PowerOps and remains distinct from the separate Revenue Assurance PoV product/repository. New utility modules must preserve the overall PowerOps identity and their own evidence, synthetic fixtures, tests and acceptance gates.

## Current implementation
The browser application opens on the PowerOps command centre. Network Operations has synthetic feeder/transformer intelligence, feature engineering, exploratory ML alerts and human-review triage. Gate 0.5.3 adds dataset/model governance, SHA-256 lineage, drift checks and fail-closed promotion eligibility. Gate 0.5.4 adds deterministic train/validation/test splits, train-only standardisation, a reproducible logistic-regression baseline, held-out evaluation, model binary SHA-256 and Ed25519 publisher verification before deserialization. Gate 0.5.5 adds a governed in-memory model registry reference. Gate 0.5.6 adds a PostgreSQL registry adapter, server-configured authenticated RBAC, forced tenant/business-unit RLS, transactional approvals/releases/rollback and append-only hash-chained audit events. Revenue Assurance remains a separate initial functional module slice with deterministic synthetic reconciliation.

All model outputs remain research/demo only, not field-validated performance or calibrated probabilities. Other PowerOps capabilities remain planned until implemented and validated.

## Run locally
Open `index.html` in a modern browser. Alternatively run `python -m http.server 4173` and open `http://localhost:4173`.

## Test
Node.js 20+ is required. Run:
```bash
npm test
```

## Safety and data boundary
- Synthetic records only; no IBEDC telemetry or customer data.
- Customer data requires written approval, isolated storage and a retention/deletion plan.
- Findings are advisory investigation leads, not proof of theft, fraud or customer liability.
- No SCADA/ADMS/DMS commands, switching, dispatch, meter commands, billing adjustments, refunds or journal postings.
- No private signing keys or customer credentials belong in this repository.
- Ed25519 authenticity does not prove model quality or operational safety.

## Gate status
Gate 0.4.1 establishes the independent repository. Gate 0.4.2 implements deterministic synthetic Revenue Assurance reconciliation. Gate 0.5.0 establishes the PowerOps command centre. Gate 0.5.1 adds Network Operations. Gate 0.5.2 adds network alert intelligence, feature engineering and exploratory ML. Gate 0.5.3 adds model governance and reliability controls. Gate 0.5.4 adds reproducible training and model-artifact security. Gate 0.5.5 adds model registry, release approval and rollback reference controls. No gate certifies the overall PoV as production-ready.
