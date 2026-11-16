# Gate 0.5.4 — CEPHAS ML Training Pipeline and Model Artifact Security

## Purpose
Introduce a reproducible, leakage-aware training baseline and cryptographic model-artifact verification for the overall CEPHAS PowerOps PoV. Revenue Assurance remains a separate module/workstream and is not changed by this gate.

## Implemented in this gate
- Deterministic seeded train/validation/test partitioning with stable record IDs, duplicate rejection, full-coverage and disjointness checks.
- Training-only standardisation; validation and test partitions do not contribute to fitted means/scales or gradient updates.
- Dependency-free standardized logistic-regression baseline with fixed seed, bounded hyperparameters and explicit dataset SHA-256 lineage.
- Separate validation and held-out test confusion-matrix metrics. Metrics are synthetic demonstration results, not field performance claims.
- Canonical serialized model bytes and SHA-256 of the actual serialized bytes (distinct from the Gate 0.5.3 manifest metadata digest).
- Ed25519 publisher signatures over exact model bytes.
- Fail-closed loader verifies expected binary SHA-256, trusted Ed25519 public key and signature before calling the supplied deserializer. Tampered bytes, missing signatures and untrusted publishers are rejected before parsing.
- Automated tests cover deterministic splits/training, partition disjointness, train-only fitting, artifact hash, valid signatures, tampering, invalid signatures, wrong publisher keys and invalid input.

## Security and operational boundaries
- Private signing keys are never stored in this repository. Production signing must occur in a controlled release environment or HSM/KMS; public verification keys must be pinned through a separately governed trust configuration.
- The tests generate ephemeral Ed25519 keys; these are test-only and not CEPHAS publisher credentials.
- The loader accepts a trusted deserializer callback. Production integration must keep that callback fixed and reviewed; never accept a deserializer or public key supplied by an untrusted artifact.
- Signature verification authenticates the exact bytes and publisher key; it does not establish model quality, safety, regulatory compliance or customer approval.
- Customer data is not used. Customer-approved source classification still requires a genuine approval reference and controlled ingestion process.
- The baseline algorithm and synthetic data are research/demo only. No model is certified for operational use.
- No SCADA/ADMS/DMS commands, switching, dispatch, meter commands, billing adjustments, refunds or journal postings are introduced.

## Validation status
Tests are authored for Node.js 20+ and run through `npm test`. They must be executed locally and through GitHub Actions on the resulting commit before this gate can be called validated. Browser E2E, accessibility, independent security review and any customer-data validation remain separate acceptance requirements.
