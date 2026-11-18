# Gate 0.5.10 — Fresh-Cluster Role Provisioning and Recovery Acceptance

## Purpose

Close the specific F-04 evidence gap identified in the independent Gate 0.5.9 re-review: demonstrate that scoped PostgreSQL LOGIN roles can be recreated on a genuinely fresh PostgreSQL cluster after restoring the database backup. Gate 0.5.8 F-01 remains closed and is not reopened.

## Recovery sequence exercised in CI

1. Create a separate PostgreSQL 16 container, independent of the original CI service container.
2. Confirm that no `powerops_app_%` scoped login roles exist in the fresh cluster.
3. Restore the database-only custom-format backup with `--no-owner --no-privileges`. PostgreSQL cluster roles are therefore not supplied by the database dump.
4. Reapply migrations `0001`, `0002` and `0003` in order. Migration 0001 is idempotently reapplied against the restored schema; 0002 reconstructs protected owner/runtime roles, schema, identity functions, RLS policies and ownership.
5. Read the restored `powerops_security.db_principal_scopes` inventory and recreate each enabled scoped LOGIN using a unique ephemeral credential.
6. Grant only the `powerops_runtime` capability group, then complete migration 0003 hardening.
7. Authenticate separately as every recreated scoped login and verify its SESSION_USER, tenant and business-unit mapping.
8. Verify role attributes, membership restrictions, protected object ownership and effective runtime privileges.
9. Change the legacy tenant GUC and confirm the authenticated database identity remains authoritative. Attempt a cross-tenant write and require RLS rejection.

## Provisioning implementation

`scripts/provision-scoped-db-roles.cjs` is a provisioning primitive. It takes a credential-provider callback, validates role identifiers and credential strength, reads the authoritative scope map, creates or resets scoped LOGIN roles with restricted attributes, and grants the runtime capability group. The script does not print credentials. However, it currently interpolates the password into a PostgreSQL `CREATE ROLE` / `ALTER ROLE` utility statement. The application code alone cannot guarantee that server statement logging, SQL tracing, database proxies or observability tooling will redact that statement. This remains a credential-handling limitation requiring explicit deployment controls and independent validation; do not represent the provisioner as production-safe until this is resolved.

The fresh-cluster smoke test supplies random ephemeral credentials in memory and verifies that each recreated login can authenticate. The separate post-restore CI login check now creates a one-run random password, masks it in Actions output, and sets it through psql's `\\password` command using stdin rather than embedding a fixed password in workflow source or SQL text. Production deployments must supply credentials from an approved secret manager or controlled provisioning service; this gate does not implement production secret-manager integration, credential rotation policy, server-side log-redaction validation, or upstream identity-provider integration. Never store scoped database passwords in source control, logs, or the scope map.

## Acceptance boundary

This test proves fresh-cluster role reconstruction and login authentication in an isolated PostgreSQL 16 CI cluster. It does not prove customer-environment disaster recovery, measured RPO/RTO, production secret custody, or full-cluster backup of all customer infrastructure. F-06 therefore remains open.

The migration and smoke test operate only on synthetic PoV records. They do not connect to IBEDC or any live utility system and provide no operational control.

## Independent retest request

The reviewer should inspect and execute the exact Gate 0.5.10 head, confirm the fresh container begins with zero scoped login roles, inspect the provisioning callback boundary, verify that secrets are not printed, and confirm each recreated login authenticates and passes the identity/privilege assertions. F-04 remains open until the reviewer explicitly accepts this exact commit.

PR remains draft and unmerged pending independent acceptance and CEPHAS approval.


## Gate 0.5.11 — Complete fresh-cluster security acceptance

The fresh-cluster smoke test now repeats the full effective privilege matrix for every reconstructed scoped LOGIN across all four protected tables: model candidates, model releases, audit events, and the protected scope map. It verifies all five table privileges (SELECT, INSERT, UPDATE, DELETE, TRUNCATE) against the established runtime contract.

For every reconstructed login, the test executes real DELETE and TRUNCATE statements against each protected table and requires PostgreSQL SQLSTATE 42501. It verifies exactly one membership in `powerops_runtime` with `INHERIT TRUE`, `SET TRUE`, and `ADMIN FALSE`; verifies the runtime and owner capability roles remain NOLOGIN, NOINHERIT, non-privileged and without memberships; and checks ownership of the security schema, protected tables, scope map and security functions.

The test seeds synthetic records for each restored tenant/business-unit scope, then authenticates as every reconstructed login and checks that cross-scope candidate, release and audit reads return no rows. It attempts cross-scope writes to all three tenant-scoped registry tables and requires insufficient-privilege/RLS rejection. It also repeats custom-GUC spoofing checks after provisioning.

These assertions run inside the independent PostgreSQL 16 fresh-cluster CI job. F-04 remains open until an independent reviewer accepts the exact resulting PR head. CI success is evidence for this automated test suite only; it is not production certification or customer disaster-recovery validation.
