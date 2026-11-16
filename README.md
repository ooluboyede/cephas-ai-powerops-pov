# CEPHAS PowerOps PoV

**Product:** CEPHAS PowerOps — standalone proof-of-value application  
**Initial utility target:** IBEDC, followed by other DisCos  
**Data approach:** Synthetic demonstration data first; customer-data validation only after explicit customer approval  
**Deployment boundary:** Separate application and repository from the CEPHAS PowerOps enterprise platform

## Product identity and scope

This repository is the standalone **PowerOps PoV**, not a Revenue Assurance-only product. It is the demonstration environment for the broader PowerOps platform. Revenue Assurance is the first implemented functional workstream in this repository and is one module within PowerOps.

The PoV should evolve as a coherent PowerOps experience with modular capabilities. New modules must be added under the PowerOps product identity, with their own scope, evidence, synthetic fixtures, tests and acceptance gates. Do not rename the overall product or repository to Revenue Assurance.

## Current implementation

The browser application opens on the PowerOps command centre, with synthetic cross-utility KPIs, an operational attention queue, feeder snapshot and a module register. Gate 0.5.1 adds a dedicated Network Operations workspace with synthetic feeder and transformer performance indicators, evidence inspection and human-review recommendations. Gate 0.5.2 adds a versioned feature-engineering pipeline, exploratory k-nearest-neighbour novelty scoring, explainable network alerts, a small synthetic benchmark and simulated human triage. These ML results are not calibrated probabilities or field-validated performance. Revenue Assurance remains a separate initial functional module slice, with its own findings, investigation, reconciliation, reports, data quality and governance views.

This is an honest implementation boundary: the repository is the PowerOps PoV, while Network Operations and Revenue Assurance are the currently implemented functional module slices at different levels of completeness. Other PowerOps capabilities must be recorded as planned until implemented and validated.

## Run locally

Open `index.html` in a modern browser. No backend, customer credentials, database, licence authority, or live utility connector is required.

For a local static server:

```bash
python -m http.server 4173
```

Then open `http://localhost:4173`.

## Data and operational safety boundary

- All seeded records and displayed outcomes are synthetic.
- No IBEDC data, customer records, production secrets, or customer credentials are included.
- Findings are investigation leads, not proof of theft, fraud, or customer liability.
- Exposure, approved recovery, and cash received are separate measures.
- The current browser interactions are demonstrations, not authenticated production controls.
- The activity list is a simulated demo log, not a tamper-evident audit service.
- No SCADA/ADMS/DMS commands, switching, dispatch, meter commands, billing adjustments, refunds, or journal postings are performed.
- Do not connect this PoV to the enterprise PowerOps database or backend as a shortcut.

## Repository separation

This repository is independently built and tested. It must not import enterprise application code, credentials, licence signing keys, database migrations, or runtime services. Any future customer-data evaluation requires written customer approval, a separately isolated data store, a documented retention/deletion plan, and security review.

## Gate status

Gate 0.4.1 establishes repository separation and an independent baseline CI pipeline. Gate 0.4.2 implements deterministic synthetic reconciliation for the Revenue Assurance module. Gate 0.5.0 adds the overall PowerOps command-centre foundation and module register. Gate 0.5.1 adds the Network Operations workspace and synthetic feeder/transformer intelligence. Gate 0.5.2 adds the Network Alert Intelligence, Feature Engineering and ML Foundation. Other listed utility modules remain planned, not implemented. No gate certifies the complete PowerOps PoV as production-ready. See `docs/POWEROPS_POV_SCOPE.md` and the gate records.
