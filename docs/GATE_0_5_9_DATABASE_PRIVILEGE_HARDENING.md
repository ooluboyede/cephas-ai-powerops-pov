# Gate 0.5.9 — Database Ownership, Role Inheritance and Privilege Hardening

## Scope

This gate implements the independent review's remaining F-04 acceptance matrix. Gate 0.5.8 F-01 is not reopened: tenant/business-unit RLS continues to resolve identity from PostgreSQL SESSION_USER and the protected scope mapping.

## Changes

- Adds migration 0003_powerops_privilege_hardening.sql.
- Uses powerops_security.db_principal_scopes as the authoritative inventory of scoped LOGIN roles.
- Normalizes each scoped role to LOGIN + INHERIT, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION and NOBYPASSRLS.
- Removes all scoped-role memberships except powerops_runtime, stripping legacy membership in other scoped logins, scope-owner, registry-owner and arbitrary legacy roles.
- Removes direct grants on registry tables and the protected scope map, and removes direct schema privileges that could bypass the runtime capability group.
- Re-grants only powerops_runtime and reasserts protected object ownership and the exact candidate/release/audit grants.
- Ensures powerops_runtime itself does not inherit another role's privileges.

## F-04 verification matrix

The PostgreSQL integration test now verifies:

1. Catalog ownership for candidate, release, audit and scope-map tables; protected schema ownership; and ownership of both identity functions and the audit trigger function.
2. Scoped-login membership inventory: each mapped login is a member of powerops_runtime only.
3. Runtime and owner roles are NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE and NOBYPASSRLS; owner roles have no inherited memberships.
4. Complete effective SELECT/INSERT/UPDATE/DELETE/TRUNCATE matrix for candidates, releases, audit events and scope map using has_table_privilege.
5. Actual denied DELETE and TRUNCATE statements against every protected object using the scoped login.
6. Schema CREATE privilege denial for powerops_security and public.
7. Upgrade from deliberately contaminated existing roles: pre-existing scoped logins start with CREATEDB/CREATEROLE, direct table grants, membership in another scoped login and a legacy role; owner-role memberships and direct scope-map grants are then added before applying migration 0003. The migration must normalize the effective role and privilege state.

## Restore acceptance

The CI restore stage now:
- Restores the logical backup without owner/privilege metadata.
- Reapplies the ownership/security migration.
- Deliberately contaminates a restored scoped login by removing its runtime membership and granting owner membership and excessive table/scope-map privileges.
- Reapplies migration 0003 as the provisioning/hardening step.
- Verifies table ownership, scoped-role membership, scope-map privilege denial and tenant isolation.
- Connects as the restored tenant-A runtime login, changes the legacy tenant GUC to tenant-B, confirms tenant-B rows remain invisible, and verifies a cross-tenant insert is rejected.

This is a CI PostgreSQL 16 recovery/provisioning simulation. It is not a customer-environment DR exercise and does not establish measured RPO/RTO.

## Deployment contract and limits

- Run migrations 0001, 0002 and 0003 in order using a protected database administrator/migration identity.
- Maintain the scope map as the authoritative list of provisioned scoped LOGIN roles.
- Use one distinct credential and server-side connection pool per tenant/business-unit.
- Never share scoped credentials or expose the pool resolver to request-controlled input.
- Protect administrator credentials: a database superuser can still alter roles, mappings, policies and data.
- Production secret-manager provisioning/rotation, upstream OIDC integration, end-to-end artifact-verifier wiring, independent audit anchoring and customer DR/RPO/RTO remain outstanding.
- Synthetic test data only; no IBEDC telemetry, customer data, live utility connection or operational control.
- F-04 must remain open until the exact CI-tested commit is independently retested and accepted. This gate is not production certification.
