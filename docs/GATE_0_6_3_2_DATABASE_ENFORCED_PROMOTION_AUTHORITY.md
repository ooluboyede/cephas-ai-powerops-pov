# Gate 0.6.3.2 — Database-Enforced Model Promotion and Evidence Authority

## Status

Architecture/design gate only. This document does not implement the controls, close F-03/F-05, certify production readiness, or authorize merge/deployment. It is based on the independent review of PR #19 at `c61652fa155ca72e6035c0d97cb338ea0583afd0`.

## Objective

Close the release-authority bypass identified in the independent review: a scoped ordinary runtime login must not be able to alter trusted candidate evidence or create, activate, deactivate, or rewrite model-release records through direct SQL. Every successful promotion must be enforced by PostgreSQL using immutable evidence and durable approval records, not merely by `activateRelease()` application logic.

The gate also addresses the related approval/audit consistency gap: a successful database approval must not be possible without its corresponding audit event being committed in the same transaction.

## Threat model and security invariant

Assume an attacker has obtained credentials for an ordinary scoped `powerops_runtime` login and can issue arbitrary SQL permitted to that role, bypassing the Node.js adapter.

The following invariant must hold:

> No ordinary runtime SQL session can manufacture or mutate trusted model evidence, create or activate a release directly, bypass the approval policy, or commit an approval without its database audit event.

The database must independently enforce tenant and business-unit scope using the existing protected `SESSION_USER` mapping. It must not accept caller-supplied tenant, business-unit, human principal, approval count, eligibility boolean, artifact-verification boolean, or release status as authority.

This gate does not defend against PostgreSQL superuser/DBA compromise, compromise of a deliberately privileged evidence-verifier identity, compromised publisher private keys, or compromise of the host/secret manager. Those remain explicit trust assumptions and operational controls.

## Source-confirmed baseline defect

At the reviewed PR #19 head:

- Migration 0002 grants `SELECT, INSERT, UPDATE` on both `powerops_ml_model_candidates` and `powerops_ml_model_releases` to `powerops_runtime`.
- The ordinary runtime integration-test privilege matrix expects candidate and release writes.
- The adapter's release path trusts mutable `candidate_data.eligibility.eligible` and `candidate_data.artifactVerification.verified`.
- The release table's active-release uniqueness constraint does not require three valid approvals.
- The application adapter checks approvals, but no equivalent database-side release function currently gates direct SQL writes.

The independent reviewer did not execute a live exploit. The implementation must therefore include controlled adversarial SQL reproduction, not describe the source finding as a reproduced exploit until that test passes.

## Required architecture

### 1. Separate mutable projection from trusted evidence

Introduce a normalized, immutable candidate-evidence record, scoped by tenant, business unit and candidate. It must bind at minimum:

- candidate ID;
- model version;
- exact manifest digest;
- exact artifact digest;
- evaluation dataset/reference digest and provenance identifier;
- promotion-assessment result and the policy/assessor version;
- artifact publisher key ID and verifier version;
- signed receipt digest and receipt reference;
- evidence-verifier identity and verification timestamp.

The record must be immutable after insertion. Corrections require a new candidate/evidence version or a separately governed superseding record; they must never overwrite the evidence used by an earlier release.

Candidate JSON may remain a read projection, but no field in mutable JSON may be authoritative for artifact verification, evaluation eligibility, approval state or release activation.

### 2. Establish a narrow evidence-registration authority

Ordinary `powerops_runtime` must not be able to insert or update trusted evidence records.

Define a dedicated, non-owner evidence capability and customer-provisioned scoped verifier login. A trusted server-side verifier must:

1. verify the publisher signature over the exact artifact bytes;
2. verify the artifact digest and manifest binding;
3. validate the evaluation evidence and policy version;
4. produce a bounded verification attestation;
5. call a narrowly scoped database registration function.

The database function must derive tenant/business-unit and verifier identity from protected database login mapping, not caller-supplied scope or verifier ID. It must bind the attestation to the exact candidate and immutable digests, reject duplicate/conflicting registration, and write candidate plus evidence records atomically.

Important trust qualification: unless a separately reviewed PostgreSQL cryptographic verification implementation is introduced, PostgreSQL is attesting that the dedicated verifier identity submitted the evidence; it is not itself proving Ed25519 signature validity. The trusted verifier service, its credentials, publisher-key governance and host remain in the trust boundary and must be documented. Do not claim that a database row alone cryptographically proves artifact authenticity.

### 3. Remove direct runtime mutation of promotion authority

Revoke from `PUBLIC` and ordinary `powerops_runtime`:

- candidate `UPDATE` that can alter trusted evidence or promotion state;
- release `INSERT`, `UPDATE`, `DELETE` and `TRUNCATE`;
- direct evidence-table mutation;
- any sequence/function privileges that recreate equivalent bypasses.

Retain only the minimum candidate read and any narrowly justified candidate-registration capability. If the existing adapter requires candidate projection updates after approval, replace those writes with database functions or derive the projection at read time.

The migration must inspect effective privileges, including inherited role membership and PUBLIC grants. Tests must execute real SQL as the scoped runtime login, not only inspect catalog flags.

### 4. Make PostgreSQL the promotion authority

Create a narrowly scoped `SECURITY DEFINER` promotion function with:

- fixed safe `search_path`;
- non-login owner;
- explicit revocation from PUBLIC;
- minimal EXECUTE grants;
- scope and actor derived from protected database identity;
- no caller-supplied approval count, approved-role list, eligibility boolean, evidence-verification boolean, tenant, business unit or human actor.

Within one transaction, the function must lock the candidate and scope's active-release state, then independently verify:

1. candidate exists in the authenticated scope and is in a promotable state;
2. exactly one valid immutable evidence record binds the candidate's current manifest and artifact digests;
3. evidence records an eligible assessment under an explicitly versioned policy;
4. artifact-verification attestation is bound to the exact artifact digest, publisher key ID and verifier version;
5. durable approvals include all required roles: `model-risk`, `security`, and `operations-owner`;
6. approvals are positive, immutable, linked to exact active-at-recording grant IDs, and from three distinct database-authenticated principals;
7. no rejection exists for the candidate;
8. creator self-approval and any duplicate/replay conditions are rejected;
9. no conflicting release ID or invalid state transition exists.

The function, not the adapter, must atomically write the release, mark the candidate released, deactivate the prior active release if policy permits, and append the corresponding audit event. A partial failure must roll back all state changes.

Rollback must also use a constrained database function and must not restore or activate arbitrary rows through direct runtime UPDATE.

### 5. Make approval and audit atomic

The current approval function inserts the durable approval, while the application appends the audit event afterwards. A direct SQL caller can therefore create an approval without the application audit event.

Move audit creation into the database approval function so approval and audit evidence commit or roll back together. The audit actor must come from the database-derived principal. The caller must not supply an authoritative actor ID.

Define a stable, versioned database-side hash serialization for new events. Preserve verifiability of historical events created with the existing application canonicalization scheme; do not silently reinterpret old hashes. Update the verifier and migration documentation to distinguish hash versions.

This closes transaction consistency only. It does not constitute independent WORM anchoring. External immutable anchoring remains a separate F-05 acceptance requirement.

## Required adversarial tests

Tests must run against PostgreSQL 16 using actual scoped login credentials and prove:

| Attack / condition | Required result |
| --- | --- |
| Ordinary runtime INSERT release | Permission denied |
| Ordinary runtime UPDATE/DELETE/TRUNCATE release | Permission denied |
| Ordinary runtime UPDATE trusted candidate evidence | Permission denied |
| Ordinary runtime inserts fabricated evidence | Permission denied |
| Direct SQL activation without approvals | Denied |
| Direct SQL activation with incomplete approvals | Denied |
| Rejected approval | Promotion denied |
| Same human principal attempts multiple required roles | Promotion denied |
| Candidate JSON eligibility changed to true | Cannot authorize promotion |
| Candidate JSON artifactVerification changed to true | Cannot authorize promotion |
| Evidence digest differs from candidate artifact/manifest | Promotion denied |
| Evidence registration from wrong scope/login | Denied |
| Duplicate/conflicting evidence | Denied or safely idempotent |
| Direct approval-function invocation | Approval and audit committed atomically |
| Audit insert failure during approval | Approval rolled back |
| Direct promotion-function invocation | Full policy independently enforced |
| Concurrent promotion attempts | At most one valid active release |
| Concurrent approval/revocation | Deterministic serialized outcome; no revoked-grant race |
| Rollback through direct SQL UPDATE | Permission denied |
| Rollback through constrained function | Scope and target policy enforced |
| Cross-tenant/business-unit evidence or release access | Denied by RLS |
| Fresh migration/restart/restore | Constraints, owners, grants and functions restored |

For the principal release-bypass finding, include a controlled reproduction script showing the pre-fix direct-write path (in an isolated disposable database) and the post-fix denial. Clearly label the former as a test fixture, not a production attack.

## Migration and compatibility requirements

- Add a new forward-only migration after 0005; do not rewrite historical migrations.
- Preserve historical approvals, grants, audit rows and release records.
- Backfill evidence only where source provenance is sufficient. If it is not, mark historical candidates as not promotable pending re-verification; do not manufacture attestations.
- Define explicit migration failure behavior for ambiguous or unverifiable historical data.
- Reapply the complete migration chain in CI and test PostgreSQL restart/restore.
- Review owner, SECURITY DEFINER, RLS/FORCE RLS, PUBLIC grants, inherited membership and function EXECUTE privileges.
- Keep PR #19 and this design branch unmerged until the stacked base and architecture are independently reviewed.

## Acceptance gates and dispositions

- **F-03:** remains OPEN until direct-write bypasses are denied, the DB promotion function is authoritative, trusted evidence is immutable/bound to exact digests, adversarial tests pass, and independent review accepts the result.
- **F-05:** approval/audit atomicity is a required part of this gate. Independent external WORM anchoring, retention and recovery remain OPEN and require a separate acceptance test.
- **F-01:** the principal-binding implementation remains only partially accepted for production; verifier and promotion actor credential lifecycle must be independently assessed.
- **F-02:** OIDC/SAML, MFA, durable token revocation and production signing-key custody remain separate.
- **F-04/F-06:** genuine fresh-cluster credential reconstruction and customer-approved DR/RPO/RTO remain separate gates.

## Non-negotiable product boundary

Synthetic data only. Advisory-only utility PoV. No live IBEDC telemetry, SCADA/ADMS/DMS control, switching, dispatch, meter commands, billing adjustments, refunds, journal postings, or automatic production model deployment. Model promotion in this gate is registry governance only; it must not imply deployment to operational utility systems.

## Independent review required before implementation acceptance

Request an independent architecture/security review of this design before treating its trust boundaries as final. The reviewer must specifically challenge:

- whether a dedicated evidence-verifier login is a sufficient database trust boundary;
- whether evidence can be forged by a compromised verifier credential and how that is contained;
- how exact artifact bytes, manifest, evaluation dataset and policy version are bound;
- whether a PostgreSQL function can enforce every promotion invariant under direct SQL;
- whether audit hashing can be versioned without invalidating historical verification;
- whether the migration safely preserves legacy records;
- concurrency, deadlock and revocation races;
- effective privilege closure including PUBLIC and inherited roles.

No merge, production certification or closure of F-03/F-05 is implied by this design document.
