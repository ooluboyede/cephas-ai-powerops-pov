# Gate 0.6.3.1 — Principal-Bound Durable Approval Authority

## Status

Design and implementation contract. This gate is stacked on Gate 0.6.3 / PR #17 and must not be merged independently. It is not a production-readiness claim.

## Why this gate is required

Gate 0.6.3 adds durable, tenant/business-unit-scoped approval and role-assignment tables. The current migration is not sufficient to make those records an authorization boundary:

1. The approval table currently grants INSERT to the shared powerops_runtime group.
2. Its trigger checks whether the principal_id supplied by the inserting statement has an active role assignment.
3. The existing db_principal_scopes identity map derives tenant and business unit from SESSION_USER, but does not derive the human approver identity.
4. Consequently, a runtime database login could submit another assigned person's principal_id directly. Application code comparing the authenticated token subject is necessary, but it does not prevent a compromised or misconfigured service from bypassing that check with direct SQL.
5. The role-assignment primary key prevents a clean second grant after revocation unless the original row is reactivated or mutated, which weakens grant history.

Therefore, Gate 0.6.3.1 must close the database identity gap before durable approvals become authoritative.

## Security objective

The database must independently establish all four approval dimensions:
- tenant ID;
- business-unit ID;
- principal ID;
- approver role.

A caller-supplied principal ID must never be sufficient to establish approver identity.

## Required architecture

### 1. Principal-bound approval database identities

Extend the protected powerops_security.db_principal_scopes mapping with a principal binding for approval-capable database logins. Keep the existing tenant/business-unit scoped runtime logins for ordinary registry operations.

Provision a dedicated non-shared login identity for each approval principal and tenant/business-unit scope. Its protected mapping row binds:

SESSION_USER -> tenant_id + business_unit_id + principal_id.

Add a powerops_security.current_principal_id() SECURITY DEFINER function with fixed search path, owned by powerops_scope_owner, reading only the protected mapping keyed by SESSION_USER. Runtime users cannot write or alter the mapping.

Approval operations must acquire a database connection whose authenticated login is bound to the same principal as the verified application token. The pool resolver must take the authenticated identity, not a caller-supplied principal argument. Before any approval write, the adapter compares the token subject with current_principal_id() and fails closed on mismatch.

### 2. Remove direct approval-table INSERT

Revoke INSERT on powerops_ml_model_approvals from the shared powerops_runtime role and from PUBLIC.

Expose one narrowly scoped database function for approval recording, owned by powerops_registry_owner, with a fixed search path. It must derive principal, tenant and business unit from the protected SESSION_USER mapping, not from parameters. Its inputs may include candidate ID, approval ID, role, decision and reason only.

The function must:
- derive the exact scope and principal from the authenticated database login;
- verify an active role assignment for that principal in that scope;
- verify candidate existence and candidate status;
- reject creator self-approval;
- reject duplicate role approval and duplicate principal approval;
- insert one immutable decision;
- return the persisted decision;
- execute atomically.

Grant EXECUTE only to the dedicated approval runtime capability. Ensure function ownership, grants, RLS behavior and trigger execution do not allow caller-controlled principal substitution.

### 3. Durable approval authority in the adapter

Update src/ml-registry-postgres.js so:
- recordApproval no longer mutates candidate_data.approvals as the source of truth;
- approval identity is the verified token subject matched against the principal-bound database login;
- approval rows are inserted through the database function and then read back from PostgreSQL;
- candidate JSON may contain a derived read projection for API compatibility, but it is never authoritative;
- idempotency compares the persisted approval ID and exact principal/role/decision/reason;
- activateRelease obtains required approvals from powerops_ml_model_approvals within the same transaction and exact scope;
- any rejected approval blocks release;
- all required roles must have approved, and each principal must be distinct;
- creator self-approval is checked against the database-derived principal;
- release and rollback remain transaction-safe and scope-serialized.

### 4. Grant history and revocation

Replace the one-row-per-principal-role assignment design with immutable grant records and an active-assignment resolution strategy. A revoked grant must remain historically queryable. A later re-grant must create a new grant record, not rewrite the old grantor/timestamp.

Approval rows must reference the exact grant record used at decision time. Revoking a role after an approval must not erase or rewrite the historical decision. A revocation must prevent future approvals.

### 5. Concurrency and integrity

Enforce at database level:
- unique approval ID per scope;
- at most one decision per candidate/role;
- at most one approval per principal/candidate;
- no self-approval;
- no approval without an active principal-bound assignment;
- atomic decision recording;
- one active release per scope;
- race-safe activation and rollback.

Use row locks and existing scope advisory locks consistently. Add an explicit partial unique index for one active release per tenant/business unit if compatible with the existing schema and migration path.

## Required acceptance tests

1. Shared tenant/BU runtime login cannot INSERT approval rows directly.
2. Shared runtime login cannot call an approval function that impersonates a principal.
3. Principal-A login cannot create an approval as principal B, even if B has an active role assignment.
4. Principal-A token paired with principal-B DB login fails closed.
5. Principal-A token and principal-A DB login succeeds only with an active scoped role.
6. Cross-tenant and cross-business-unit assignments are invisible and unusable.
7. Creator self-approval is rejected by the database path.
8. Revoked grant cannot create new approvals.
9. Re-grant creates a new grant record and preserves the old revoked grant.
10. Approval rows remain immutable and retain exact grant linkage.
11. Duplicate approval IDs, duplicate role approvals and duplicate principal approvals fail.
12. A rejected decision blocks release.
13. Release requires all three independent approvals from distinct principals.
14. Two concurrent release attempts cannot leave multiple active releases or inconsistent candidate state.
15. Rollback is atomic and preserves audit ordering.
16. Candidate JSON tampering cannot create, remove or alter authoritative approvals.
17. Fresh-cluster restore reconstructs principal mappings, grants, approvals, functions, owners, grants and RLS.

## Migration and rollout constraints

- Apply only after Gate 0.6.3 schema exists.
- Preserve the established SESSION_USER identity boundary and fail-closed RLS.
- Never add caller-controlled tenant, business-unit or principal GUCs as authority.
- Do not grant runtime roles membership in owner roles.
- Do not expose approval principal mapping writes to runtime roles.
- Provide a controlled migration path for existing shared runtime logins and test fixtures.
- Update backup/restore and role-provisioning documentation.
- Do not merge PR #17 or this stacked gate without explicit authorization.

## Explicitly out of scope

- Production OIDC/SAML integration, MFA and durable token revocation (F-02).
- HSM/KMS custody and publisher key governance.
- Independent WORM anchoring (F-05).
- Customer DR/RPO/RTO acceptance (F-06).
- Any live utility control, switching, dispatch, SCADA/ADMS/DMS action or automated model deployment.

## Exit criteria

Gate 0.6.3.1 is complete only when the database—not JSON fields or application-supplied principal IDs—authoritatively binds each approval to a real principal, scoped role grant and exact candidate; all acceptance tests pass on the exact PR head; fresh-cluster restore passes; and independent security review accepts the principal-identity boundary.
