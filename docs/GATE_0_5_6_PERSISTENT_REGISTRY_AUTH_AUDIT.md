# Gate 0.5.6 — Persistent ML Registry, Authenticated RBAC and Tamper-Evident Audit

## Objective
Replace Gate 0.5.5's in-memory registry reference with a PostgreSQL-backed registry boundary. Persist candidates, approvals, release pointers and audit events; derive identity and scope from a server-verified token; enforce tenant and business-unit isolation in PostgreSQL Row-Level Security (RLS).

## Implemented in this gate
- `src/ml-registry-security.js`: HMAC-SHA-256 signed, expiring bearer tokens. The token contains a subject and expiry; tenant, business-unit and roles are resolved from server-side principal configuration. Client-provided role and scope claims are not trusted.
- `src/ml-registry-postgres.js`: parameterized PostgreSQL transactions for candidate registration, independent approvals, release activation, rollback, candidate listing and audit-chain verification.
- `migrations/0001_powerops_ml_registry_rls.sql`: tenant + business-unit scoped tables, composite keys, forced RLS, one-active-release constraint and append-only audit trigger.
- Per-scope transaction advisory locks serialize mutations, including first-event creation and concurrent release pointer changes.
- Candidate registration and approval retries are idempotent for matching immutable request content; conflicting reuse of IDs fails closed.
- Manifest integrity is checked before registration. Artifact receipt acceptance requires an injected trusted server-side verifier; the caller's `verified: true` claim is not accepted.
- Every state mutation and its audit event share one database transaction. Audit records contain a per-scope sequence and SHA-256 hash chain.

## Role / permission model

| Server-assigned role | Allowed actions |
|---|---|
| registry-reader | Read candidates and audit |
| model-trainer | Read and register candidates |
| model-risk | Record model-risk approval |
| security | Record security approval; read audit |
| operations-owner | Record operations-owner approval |
| release-manager | Activate approved releases; rollback; read audit |
| auditor | Read candidates and audit |

The token authority must be called only after an upstream identity provider or trusted customer-hosted authentication service has authenticated the user. Principal-to-role mappings are server configuration, never request-body fields. Tokens expire after 15 minutes by default and may be configured from 60 to 3,600 seconds.

## Database security requirements
1. Apply the migration using a dedicated migration owner.
2. Run the application with a separate PostgreSQL role that does not own these tables and does not have `BYPASSRLS` or superuser privileges.
3. Grant only required table privileges. Do not grant runtime `TRUNCATE`, DDL, policy-management or trigger-management privileges.
4. Keep the database connection private to the service. The RLS session variables are set from the server-verified identity within each transaction.
5. Back up the registry and audit tables; test restore and chain verification before customer onboarding.
6. Use TLS for database connections and secret-manager/KMS custody for token signing secrets. Do not commit signing secrets or production principal maps.

RLS uses both `tenant_id` and `business_unit_id` on every registry table. The application also includes both scope keys in its queries and transaction context. Missing scope settings fail closed under the policies.

## Audit assurance boundary
The audit chain is tamper-evident and the database trigger rejects row updates and deletes. This is **not** a formal WORM guarantee: a database superuser or privileged administrator could still alter database structures or data. Production WORM assurance requires independent hash anchoring/export to separately administered immutable object storage with retention lock, plus tested backup/restore and privileged-access monitoring.

## Integration contract / limitations
- The artifact verifier is injected by the trusted server and must verify the Gate 0.5.4 artifact's exact bytes, SHA-256, Ed25519 signature and trusted publisher key before returning a verification receipt. The promotion assessor is injected by the trusted server and must resolve the evaluation reference from trusted, tenant-scoped evaluation records and apply the Gate 0.5.3 promotion policy. Do not wire browser/client-provided receipts or eligibility decisions directly to these functions.
- This repository supplies a PostgreSQL-compatible adapter and migration; it does not yet include a production HTTP server, upstream identity-provider integration, secret-manager integration, a provisioned PostgreSQL instance or live customer deployment.
- Unit/contract tests use a fake PostgreSQL pool. A real PostgreSQL migration/RLS integration run, restart/recovery test against a provisioned database, backup/restore drill, independent security review and customer-hosted deployment validation remain acceptance items.
- The Gate 0.5.5 in-memory registry remains as a prior reference/test implementation; the new PostgreSQL adapter is the persistence path introduced by this gate.
- Synthetic data only. No IBEDC telemetry or customer data. No automatic deployment to live models and no SCADA/ADMS/DMS, switching, dispatch, meter, billing or financial commands.

## Acceptance checklist
- [x] PostgreSQL schema for candidates, releases and audit events.
- [x] Forced tenant + business-unit RLS policies.
- [x] Server-configured identity, role and scope resolution.
- [x] Server-side permission checks before database connection acquisition.
- [x] Transactional candidate/approval/release/rollback + audit event writes.
- [x] Scoped advisory locks and ID retry safeguards.
- [x] Audit update/delete trigger and chain verifier.
- [x] Unit/contract tests authored.
- [ ] GitHub Actions result for this gate.
- [x] Real PostgreSQL migration and RLS integration test added to CI (pending first successful run on this revision).
- [ ] Restart, backup/restore and concurrency test against PostgreSQL.
- [ ] Independent security review and production key custody review.
