# Gate 0.6.3.1 — Principal-Bound Durable Approval Implementation

## Objective

Make PostgreSQL independently bind each model approval to the authenticated human principal, tenant, business unit and exact role grant. Candidate JSON is a projection only; it is not approval authority.

## Database trust boundary

- Approval-capable logins are dedicated to one human principal and one tenant/business-unit scope.
- `powerops_security.db_principal_scopes` maps PostgreSQL `SESSION_USER` to tenant, business unit and (for approval logins) principal ID.
- `powerops_security.current_principal_id()` reads only this protected mapping. No caller-supplied principal parameter or custom GUC participates in identity.
- A dedicated `powerops_approval_runtime` group grants EXECUTE on the approval function. The login also inherits ordinary runtime capability for scoped candidate reads, audit writes and candidate projection updates.
- Shared `powerops_runtime` and PUBLIC cannot directly INSERT approvals.
- `powerops_ml_record_principal_approval` is SECURITY DEFINER, owned by the non-login registry owner, has a fixed `pg_catalog` search path, and derives scope/principal from `SESSION_USER`.
- The function validates active grant, candidate state and creator self-approval; it inserts the decision with the exact grant ID. Rejections mark the candidate rejected in the same transaction.

## Grant history

- Existing assignment rows are converted to UUID-backed grant records.
- A partial unique index permits only one active grant for a principal/role/scope at a time.
- Grant identity, scope, role, grantor and grant time are immutable.
- Revocation is one-way; a later re-grant creates a new grant ID.
- Each approval references the exact grant used when it was recorded. Historical approvals are not rewritten when a role is revoked.

## Registry adapter

- `poolForApprovalIdentity` must resolve a dedicated pool for the authenticated token identity.
- Before approval, the adapter compares database `SESSION_USER`, tenant, business unit and principal against the verified token subject.
- The adapter records approvals only through the database function.
- Approval projections and release eligibility are read from `powerops_ml_model_approvals`; candidate JSON cannot create, erase or modify an approval.
- Release checks require all three configured roles, distinct principals and no rejected decision. This remains a registry-service transition; production release authority and deployment controls require their own review.

## Operational requirements and residual risks

- Provision each dedicated login through a customer-controlled administrator workflow. Store and rotate credentials through the customer's secret manager; never place passwords in migrations, logs or source control.
- Connection pools must be isolated per exact database login. The database identity comparison fails closed if a token is paired with another principal's pool.
- Restore procedures must recreate scoped login roles, protected mapping rows and group memberships after migrations. A database dump alone does not include cluster-global role credentials.
- This gate does not provide OIDC/SAML, MFA, durable token revocation, HSM/KMS custody, external WORM anchoring or customer DR/RPO/RTO acceptance.
- Synthetic data only. Advisory-only; no live utility control, SCADA/ADMS/DMS actions or automated model deployment.

## Acceptance status

Implementation is under exact-head CI and independent review. Do not merge this stacked Draft PR or close F-02/F-05/F-06 based on this gate alone.
