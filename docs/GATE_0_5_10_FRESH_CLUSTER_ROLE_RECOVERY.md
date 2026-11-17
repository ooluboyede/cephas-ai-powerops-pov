# Gate 0.5.10 — Fresh-Cluster Role Provisioning and Recovery Acceptance

## Purpose

Close the specific F-04 evidence gap identified in the independent Gate 0.5.9 re-review: demonstrate that scoped PostgreSQL LOGIN roles can be recreated on a genuinely fresh PostgreSQL cluster after restoring the database backup. Gate 0.5.8 F-01 remains closed and is not reopened.

## Recovery sequence exercised in CI

1. Create a separate PostgreSQL 16 container, independent of the original CI service container.
2. Confirm that no `powerops_app_%` scoped login roles exist in the fresh cluster.
3. Restore the database-only custom-format backup with `--no-owner --no-privileges`. PostgreSQL cluster roles are therefore not supplied by the database dump.
4. Reapply `0002_powerops_session_identity_rls.sql` to reconstruct protected owner/runtime roles, schema, identity functions, RLS policies and ownership.
5. Read the restored `powerops_security.db_principal_scopes` inventory and recreate each enabled scoped LOGIN using a unique ephemeral credential.
6. Grant only the `powerops_runtime` capability group, then apply `0003_powerops_privilege_hardening.sql`.
7. Authenticate separately as every recreated scoped login and verify its SESSION_USER, tenant and business-unit mapping.
8. Verify role attributes, membership restrictions, protected object ownership and effective runtime privileges.
9. Change the legacy tenant GUC and confirm the authenticated database identity remains authoritative. Attempt a cross-tenant write and require RLS rejection.

## Provisioning implementation

`scripts/provision-scoped-db-roles.cjs` is a provisioning primitive. It takes a credential-provider callback, validates role identifiers and credential strength, reads the authoritative scope map, creates or resets scoped LOGIN roles with restricted attributes, and grants the runtime capability group. It never logs passwords.

The CI smoke test supplies random ephemeral credentials in memory and verifies that each recreated login can authenticate. Production deployments must supply the callback from an approved secret manager or controlled provisioning service; this gate does not implement a production secret-manager integration, credential rotation policy, or upstream identity-provider integration. Never store scoped database passwords in source control, logs, or the scope map.

## Acceptance boundary

This test proves fresh-cluster role reconstruction and login authentication in an isolated PostgreSQL 16 CI cluster. It does not prove customer-environment disaster recovery, measured RPO/RTO, production secret custody, or full-cluster backup of all customer infrastructure. F-06 therefore remains open.

The migration and smoke test operate only on synthetic PoV records. They do not connect to IBEDC or any live utility system and provide no operational control.

## Independent retest request

The reviewer should inspect and execute the exact Gate 0.5.10 head, confirm the fresh container begins with zero scoped login roles, inspect the provisioning callback boundary, verify that secrets are not printed, and confirm each recreated login authenticates and passes the identity/privilege assertions. F-04 remains open until the reviewer explicitly accepts this exact commit.

PR remains draft and unmerged pending independent acceptance and CEPHAS approval.
