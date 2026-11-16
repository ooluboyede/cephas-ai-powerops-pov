# CEPHAS PowerOps PoV — Product Scope and Safety Boundary

This repository is the overall CEPHAS PowerOps proof-of-value application for IBEDC first, then other DisCos. It is not the separate PowerOps Revenue Assurance PoV product. Revenue Assurance is one module/workstream within this overall PoV.

## Implemented workstreams
- PowerOps command-centre foundation.
- Network Operations synthetic workspace and advisory review queue.
- Network Alert Intelligence, feature engineering and exploratory ML scoring.
- Dataset/model governance, drift checks and fail-closed release eligibility.
- Gate 0.5.4 reproducible ML training baseline, dataset partitioning, binary SHA-256 and Ed25519 verification-before-deserialization.
- Gate 0.5.5 in-memory model registry reference.
- Gate 0.5.6 PostgreSQL registry adapter, server-configured identity and RBAC, forced tenant/business-unit RLS, transactional independent approvals/releases/rollback, scoped advisory locks and append-only hash-chained audit events (integration and production hardening still pending).
- Revenue Assurance deterministic synthetic reconciliation module slice.

## Planned until separately implemented and validated
Outage and fault intelligence expansion, asset health and maintenance, metering and energy intelligence, customer operations, field workforce, forecasting and planning, production identity-provider integration, KMS/HSM secret custody, independent immutable audit anchoring/WORM service, real PostgreSQL migration/RLS and backup/restore validation, HSM/KMS-backed signing and customer-hosted deployment hardening.

## Data and safety
Synthetic data only by default. Customer data requires explicit written approval, isolation, documented purpose, retention/deletion controls and security review. All intelligence is advisory. This PoV must not issue SCADA/ADMS/DMS commands, switching, dispatch, protection, meter commands, billing adjustments, refunds or journal postings. No gate in this repository alone certifies production readiness.
