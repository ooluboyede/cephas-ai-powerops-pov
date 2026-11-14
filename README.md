# CEPHAS PowerOps Revenue Assurance PoV

**Status:** Evaluation-only, synthetic-data demonstration  
**Initial target:** IBEDC (then other DisCos)  
**Deployment boundary:** Separate application and repository from the CEPHAS PowerOps enterprise platform.

## What this repository contains

The initial extraction is the existing interactive Revenue Assurance dashboard from the enterprise repository's PoV workstream. It is a static browser application with synthetic fixtures and demo-only interactions.

## Run locally

Open `index.html` in a modern browser. No backend, customer credentials, database, licence authority, or live utility connector is required.

For a local static server:

```bash
python -m http.server 4173
```

Then open `http://localhost:4173`.

## Data and safety boundary

- All seeded records and displayed outcomes are synthetic.
- No IBEDC data, customer records, production secrets, or customer credentials are included.
- Findings are investigation leads, not proof of theft, fraud, or customer liability.
- Exposure, approved recovery, and cash received are separate measures.
- The current browser interactions are demonstrations, not authenticated production controls.
- The activity list is a simulated demo log, not a tamper-evident audit service.
- No SCADA/ADMS/DMS commands, switching, dispatch, meter commands, billing adjustments, refunds, or journal postings are performed.
- Do not connect this app to the enterprise PowerOps database or PR #21 backend.

## Repository separation

This repository is independently built and tested. It must not import enterprise application code, credentials, licence signing keys, database migrations, or runtime services. Any future customer-data evaluation requires written customer approval, a separately isolated data store, a documented retention/deletion plan, and security review.

## Gate status

Gate 0.4.1 establishes repository separation and an independent baseline CI pipeline. It does **not** certify the PoV as production-ready or complete the remaining workflow gaps. See `docs/GATE_0_4_1_EXTRACTION.md` and the follow-on gates.
