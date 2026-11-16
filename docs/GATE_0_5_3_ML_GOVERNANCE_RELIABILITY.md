# Gate 0.5.3 — CEPHAS ML Model Governance and Intelligence Reliability

## Scope
This gate adds model and dataset governance to the overall CEPHAS PowerOps PoV. It does not change the separate Revenue Assurance PoV or its repository.

## Implementation
- SHA-256 dataset manifests with explicit source classification, record count, dataset identity, retention metadata and customer-approval reference requirement.
- SHA-256 model manifests binding model version, algorithm, feature version/schema, dataset fingerprint, hyperparameters, training-code revision and creation timestamp.
- Model-manifest integrity verification that detects metadata tampering.
- Reusable confusion-matrix evaluation metrics: precision, recall and false-positive rate.
- Population Stability Index (PSI) utility for feature-distribution drift monitoring.
- Fail-closed promotion policy: minimum 100 labelled evaluation cases, precision >= 0.90, recall >= 0.90, PSI <= 0.20, approved feature schema and valid artifact manifest.
- Registry-record fingerprinting for traceable blocked/eligible decisions.
- Unit tests for lineage, integrity, evaluation, drift and promotion gates.

## Current model release decision
The Gate 0.5.2 model remains **research/demo only and blocked from promotion**. Its existing four-case synthetic benchmark is below the 100-case minimum. No model is certified, deployed or validated against IBEDC/customer data by this gate. Passing the configurable software acceptance test only makes a manifest eligible for independent release review; it does not authorize deployment.

## Data governance
Synthetic data must be labelled synthetic and must not claim customer approval. Customer-approved data requires a non-empty approval reference. This library records lineage metadata and fingerprints; it does not itself provide secure data storage, encryption at rest, access control, deletion enforcement or regulatory compliance.

## Drift limitations
PSI is a statistical monitoring signal, not a root-cause diagnosis. The calling evaluation pipeline must select meaningful reference/current windows and feature-specific bins. Thresholds are initial policy defaults requiring model-risk review before production use.

## Safety and status
The PowerOps PoV remains advisory-only. No SCADA/ADMS/DMS control, switching, dispatch or field action is introduced. Authentication, signed model binaries, secure artifact storage, approval workflows, persistent append-only registry, customer-data validation and production monitoring remain future hardening work.
