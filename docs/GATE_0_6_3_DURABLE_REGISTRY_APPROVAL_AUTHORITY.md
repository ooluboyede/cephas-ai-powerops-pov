# Gate 0.6.3 — Durable Registry and Approval Authority

## Objective
Replace in-memory model-registry state with PostgreSQL-backed, transaction-safe state. Preserve customer-hosted deployment and advisory-only operation.

## Required trust boundaries
1. The caller must not choose effective approver identity or role. Resolve a verified principal from the Gate 0.6.0 authentication boundary.
2. Role membership must be checked against durable tenant- and business-unit-scoped authorization records. A request-supplied role is never authority.
3. Candidate registration, approvals, release activation and rollback must commit atomically with their audit event.
4. Unique constraints must prevent duplicate approval per candidate/role and one principal filling multiple required roles.
5. Release activation must lock the registry scope and compare the expected active release to prevent concurrent release races.
6. Event records must be append-only for application roles. Hash-chain updates must be serialized per registry scope. Hash chaining is tamper-evident, not WORM; independent external anchoring remains F-05.
7. Candidate, approval, release and event rows carry tenant and business-unit scope. Database-enforced isolation remains the final boundary.
8. Credentials, migrations, backup/restore and restore-time role reconstruction remain subject to Gate 0.5.9–0.5.12 controls.

## Schema introduced
The migration creates scoped registry, candidate, approval, release and event tables, foreign keys and uniqueness constraints. It deliberately does not grant application privileges or claim RLS integration until the adapter is wired to the established SESSION_USER-derived identity boundary and tested against the protected-object privilege matrix.

## Required implementation sequence
- Add a PostgreSQL repository adapter with explicit transaction boundaries and parameterized SQL.
- Bind tenant/business-unit scope from the trusted database principal resolver, never request JSON.
- Implement approval authorization from durable principal-role assignments.
- Implement serializable or explicitly locked release/rollback transitions.
- Persist event sequence and previous hash under a per-registry transaction lock.
- Add negative tests for forged actor IDs, role escalation, cross-scope access, duplicate approvals, concurrent release attempts, rollback races, transaction rollback and append-only enforcement.
- Add fresh-cluster migration/restore smoke and privilege-matrix coverage.
- Run exact-head CI and request independent security review.

## Explicit exclusions
No production IdP, KMS/HSM custody, external WORM anchor, customer-approved ML thresholds, live IBEDC telemetry, automatic model deployment or SCADA/ADMS/DMS control is introduced here. This schema alone does not close any finding or establish production certification.
