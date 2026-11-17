# Gate 0.5.8 — Database Identity Trust Boundary and Least-Privilege RLS

## Purpose

Remediate independent-review finding F-01 from Gate 0.5.6. The former policies trusted caller-settable PostgreSQL custom settings (app.tenant_id and app.business_unit_id). Any holder of the shared runtime database credential able to execute SQL could change those settings. Application-side token checks did not make those settings an independent database identity boundary.

## Implemented in this gate

- Adds migration 0002_powerops_session_identity_rls.sql.
- Replaces custom-GUC RLS predicates with protected database functions that resolve scope from PostgreSQL SESSION_USER.
- Stores database-login-to-tenant/business-unit mappings in powerops_security.db_principal_scopes, owned by a non-login role.
- Revokes runtime access to the scope mapping table; runtime can execute only the two scope-resolution functions.
- Separates non-login scope-owner, registry-owner and runtime privilege roles.
- Gives runtime candidate/release SELECT, INSERT and UPDATE only; audit SELECT and INSERT only. No runtime DELETE, audit UPDATE/DELETE/TRUNCATE, ownership, DDL, or scope-map read.
- Changes the adapter to require a trusted server-side poolForIdentity(identity) resolver. It checks the actual database session's resolved scope before any registry operation and fails closed on mismatch.
- Adds an actual PostgreSQL negative test: a tenant-A database login deliberately sets both legacy GUCs to tenant-B and attempts cross-tenant reads/writes and role switching.

## Required deployment contract

A database login is provisioned for each tenant + business-unit scope. For each login:

1. Create a dedicated LOGIN role with NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS.
2. Grant membership in powerops_runtime only.
3. Insert its exact database role, tenant ID and business-unit ID into powerops_security.db_principal_scopes using the administrator-controlled provisioning process.
4. Store its credential in the deployment's secret manager and bind it to a server-side pool selected from the authenticated principal's scope.
5. Never grant a scoped login membership in another scoped login, powerops_scope_owner, or powerops_registry_owner.
6. Rotate/revoke credentials and disable the mapping row when a scope credential is deprovisioned.

The adapter does not accept one shared cross-scope pool. A pool resolver is trusted server configuration, not request input. The adapter verifies that the returned database login resolves to exactly the application-authenticated tenant and business unit.

This architecture trades some connection-pool complexity for a database-verifiable identity boundary. Deployments must budget for credential provisioning, pool lifecycle, rotation, and connection limits across scopes.

## Acceptance tests

The PostgreSQL integration test applies both migrations and provisions three isolated logins:
- tenant-a / unit-1
- tenant-a / unit-2
- tenant-b / unit-1

It verifies:
- each login sees only its mapped scope;
- changing both legacy custom GUCs cannot change the rows visible to tenant-a/unit-1;
- the same attack cannot insert a tenant-b row;
- tenant-a cannot SET ROLE to tenant-b's login;
- runtime cannot read the protected scope map;
- runtime has no candidate DELETE, audit UPDATE/DELETE/TRUNCATE privileges;
- scope remains correct after application pool recreation.

The integration test requires POWEROPS_PG_ADMIN_URL for a disposable PostgreSQL test database. GitHub Actions supplies PostgreSQL 16. The CI backup/restore stage also verifies that scope-map rows and both scope-resolution functions survive the logical restore. Its test restore uses --no-owner/--no-privileges, so it does not prove production role ownership or grants are restored; production recovery must separately provision/restore cluster roles, memberships, ownership and grants before runtime traffic is enabled.

## Security boundaries and limitations

- This gate addresses F-01 by binding database RLS scope to the authenticated PostgreSQL login, not to a mutable custom setting.
- A compromised tenant-scoped database credential is limited to that one tenant/business-unit scope, assuming no privileged role membership or credential reuse.
- A compromised database administrator/superuser remains outside this isolation boundary and can alter role mappings, policies, functions, or data. Protect and monitor administrative credentials.
- Production provisioning, secret-manager integration, per-scope pool lifecycle/rotation, OIDC integration, end-to-end artifact-verifier wiring, independent audit anchoring, and customer-environment disaster recovery remain separate acceptance work.
- Hash-chained audit data remains tamper-evident, not independently immutable WORM storage.
- Synthetic test data only. No IBEDC telemetry, customer records, live utility connection, or operational control is included.
- This gate is not production certification. Do not merge or certify until CI passes and an independent reviewer retests the exact resulting commit.

## Reviewer retest required

Ask the independent reviewer to repeat F-01 using the actual scoped runtime login, deliberately setting both legacy custom GUCs to another tenant/business unit, and verify that cross-scope reads and writes remain denied. Also inspect effective role membership, table/schema privileges, ownership, and restore behavior.
