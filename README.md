# CEPHAS PowerOps PoV

**Product:** CEPHAS PowerOps — standalone proof-of-value application  
**Initial utility target:** IBEDC, followed by other DisCos  
**Data approach:** Synthetic demonstration data first; customer-data validation only after explicit customer approval  
**Deployment boundary:** Separate application and repository from the CEPHAS PowerOps enterprise platform

## Product identity and scope

This repository is the standalone **PowerOps PoV**, not a Revenue Assurance-only product. It is the demonstration environment for the broader PowerOps platform. Revenue Assurance is the first implemented functional workstream in this repository and is one module within PowerOps.

The PoV should evolve as a coherent PowerOps experience with modular capabilities. New modules must be added under the PowerOps product identity, with their own scope, evidence, synthetic fixtures, tests and acceptance gates. Do not rename the overall product or repository to Revenue Assurance.

## Current implementation

The browser application now opens on the PowerOps command centre, with synthetic cross-utility KPIs, an operational attention queue, feeder snapshot and a module register. Revenue Assurance remains the initial functional module slice, with findings, investigation, reconciliation, reports, data quality and governance views. Gate 0.4.2 adds deterministic synthetic reconciliation; Gate 0.5.0 establishes the wider PowerOps command-centre foundation.

This is an honest implementation boundary: the repository is the PowerOps PoV, while Revenue Assurance is currently the functional module implemented here. Other PowerOps capabilities must be recorded as planned until implemented and validated.

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

Gate 0.4.1 establishes repository separation and an independent baseline CI pipeline. Gate 0.4.2 implements deterministic synthetic reconciliation for the initial Revenue Assurance module. Gate 0.5.0 adds the overall PowerOps command-centre foundation and module register. The other listed utility modules remain planned, not implemented. No gate certifies the complete PowerOps PoV as production-ready. See `docs/POWEROPS_POV_SCOPE.md` and the gate records.
