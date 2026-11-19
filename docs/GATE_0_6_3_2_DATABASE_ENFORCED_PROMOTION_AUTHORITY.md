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


---

## Independent review response and design amendment — 19 November 2026

### Review disposition

The independent architecture reviewer returned **ACCEPT WITH CONDITIONS** against design commit `536fefbcc8f09fae0f9f09a673d4ff2aafbaa9b0`. This amendment addresses findings F-01 through F-08 before implementation is authorized.

This is a design clarification only. It does not claim implementation, test execution, implementation acceptance, F-03/F-05 closure, production readiness or merge authorization. The PR remains Draft.

### F-01 — Verifier attestation protocol and compromise containment

#### Canonical attestation envelope

The verifier must construct a versioned, canonical attestation envelope. Version 1 uses:

- Canonical serialization: JSON Canonicalization Scheme (RFC 8785).
- Digest: SHA-256 over the exact canonical envelope bytes.
- Verifier signature: Ed25519 over the envelope digest, with a domain-separation prefix identifying this as a CEPHAS PowerOps evidence-verification receipt.
- Explicit `envelope_version`, `signature_algorithm`, `digest_algorithm`, and `verifier_key_id`.

The signed envelope must bind, without caller-controlled substitutions:

- immutable candidate UUID and model version;
- tenant and business-unit identifiers;
- exact artifact SHA-256 digest and byte length;
- exact manifest SHA-256 digest and canonicalization version;
- evaluation dataset snapshot digest, dataset identifier, provenance/lineage digest and preparation version;
- evaluation result digest and assessment record identifier;
- immutable promotion-policy identifier, version and digest;
- assessor identity and assessor implementation/version;
- publisher key ID and publisher-signature reference;
- verifier service identity, verifier software/build version and verification timestamp;
- result (eligible/ineligible), reason codes and applicable validation profile.

The verifier must hash the exact artifact bytes it reads. It must verify that the manifest references that same artifact digest and model version. The evaluation dataset must be an immutable snapshot or content-addressed object; a mutable URI or display name is not sufficient. Missing bytes, unavailable provenance, unsupported algorithms, unknown/revoked keys or ambiguous policy versions fail closed.

Artifact and dataset bytes must be retained in customer-controlled immutable or content-addressed storage for the applicable evidence-retention period. The verifier records the storage object digest and immutable version/reference. It must not attest to bytes it cannot retrieve and hash.

#### What PostgreSQL verifies

For this gate, PostgreSQL authenticates the verifier database login through the protected `SESSION_USER` mapping and accepts evidence only through a narrowly scoped registration function. The verifier service performs publisher-signature and evaluation verification and signs the canonical receipt. PostgreSQL stores the exact envelope bytes, digest, signature, algorithm and key ID as immutable evidence.

Unless a separately reviewed database-side Ed25519 verifier is implemented, PostgreSQL does **not** independently prove the Ed25519 signature. It trusts the authenticated verifier service to have performed the checks. The signed receipt supplies independently checkable provenance to downstream auditors; it does not remove the verifier from the trust boundary.

The verifier login receives no direct INSERT/UPDATE/DELETE/TRUNCATE rights on evidence, candidate or release tables. It receives only EXECUTE on the registration function. The function derives verifier identity and scope from the protected mapping, validates envelope structure/version and exact candidate/scope/digest bindings, and writes immutable evidence. It cannot create, approve, promote, deactivate or roll back releases.

#### Compromise response

Verifier signing keys must be held outside the application database in a customer-controlled secret manager or HSM/KMS where available. Define key activation, rotation, revocation, expiry, incident timestamp and key-compromise status in a protected verifier trust registry. Registration rejects unknown, expired or revoked verifier keys.

On suspected verifier host or credential compromise:

1. Disable the verifier login and revoke its function EXECUTE grant.
2. Revoke the affected verifier signing key and stop accepting receipts signed by it.
3. Identify all evidence registered by that verifier identity/key during the exposure window.
4. Mark affected evidence as quarantined/non-promotable through a separately authorized incident procedure; never rewrite the original evidence.
5. Re-run verification from retained exact artifact, manifest, dataset and policy snapshots using a clean verifier identity/key.
6. Record incident, quarantine, re-verification and supersession events in the audit chain and external incident log.
7. Reassess any release whose promotion relied on affected evidence; do not silently revoke or replace production state through this PoV.

Acceptance tests must prove a verifier login cannot write releases, alter existing evidence, change scope, or invoke approval/promotion/rollback authority. A compromised verifier remains capable of submitting a false attestation within its narrow evidence-registration authority; containment therefore depends on key custody, rapid revocation, evidence quarantine and independent re-verification. This residual trust assumption is explicit.

### F-02 — Exact evidence canonicalization and byte binding

The evidence record is immutable and references a canonical evidence envelope. Every digest is SHA-256 over the precisely identified bytes and canonicalization version. The implementation must persist:

- artifact digest, byte length, immutable object version and retrieval reference;
- manifest digest, canonicalization version and immutable manifest bytes/reference;
- candidate UUID and model version;
- dataset snapshot digest, provenance/lineage digest and immutable snapshot reference;
- evaluation-result digest and immutable assessment record;
- policy ID/version/digest;
- assessor identity and implementation version;
- publisher key ID and signature reference;
- verifier identity/version, verifier key ID, signed receipt bytes, receipt digest and signature;
- trusted registration timestamp and database-generated evidence ID.

The verifier must establish byte identity by hashing the exact bytes read from the immutable object version and compare that digest to the manifest and candidate binding. A mutable URI, mutable JSON projection, mutable dataset name or caller-supplied digest is never sufficient.

The database registration function rejects a receipt whose candidate, scope, artifact digest, manifest digest, dataset digest, policy digest, publisher key or verifier identity does not match the protected candidate/evidence context. It rejects a second conflicting evidence envelope for the same immutable candidate version. Re-verification creates a new evidence version with an explicit supersession relationship; it never overwrites the prior receipt.

If original bytes or immutable provenance are unavailable, evidence is incomplete and the candidate is non-promotable. The verifier must not reconstruct or infer missing historical bytes.

Acceptance test: substitution of artifact bytes, manifest, dataset snapshot, provenance, evaluation result or policy version must invalidate the binding and prevent registration or promotion.

### F-03 — Distinct human approvers and identity aliases

A database principal ID is not, by itself, proof of a distinct human being. The authoritative identity key for separation-of-duties checks is an immutable, issuer-qualified human subject identifier from the configured enterprise identity authority, represented as a canonical identity key (issuer + subject). Email address, display name, username and database login name are not human identity keys.

The protected principal mapping must bind each approval database login to:

- tenant and business unit;
- immutable internal principal UUID;
- canonical issuer-qualified human identity key;
- identity-provider issuer;
- approval role grant;
- mapping status and effective dates.

All aliases, multiple logins and renamed accounts belonging to the same human must resolve to the same canonical human identity key through a separately governed identity-administration process. A database uniqueness constraint and promotion-function check must reject the same canonical human identity key across the three required approval roles, even if the login names or internal principal UUIDs differ.

The identity provider and identity-governance process remain trusted: PostgreSQL cannot independently establish that two different issuer/subject pairs are two different natural persons. The customer must attest to the uniqueness and lifecycle governance of the canonical human identity mapping. Mapping changes are append-only, versioned events; they do not rewrite the identity attached to historical approvals.

The candidate creator is prohibited from approving **any** required role for that candidate. Approval records reference the exact immutable grant ID and canonical human identity key resolved at approval time. Revocation affects future approvals and promotions according to the serialization rule below; it never rewrites a historical approval.

Acceptance tests must include two database logins, two internal principal UUIDs and two aliases mapped to the same canonical human identity key. They must not satisfy two approval roles. The three required roles must be represented by three distinct canonical human identity keys.

### F-04 — Scope serialization, lock order and revocation semantics

Create a durable promotion-mutex row for every tenant/business-unit scope. Provision it with the scope; it must exist even when that scope has no active release. Promotion and rollback transactions acquire this row with `SELECT ... FOR UPDATE` as their first scope-changing lock. This avoids relying on the existence of an active-release row.

Use PostgreSQL READ COMMITTED isolation with the scope mutex as the serialization authority, plus row locks and uniqueness constraints as defense in depth. All promotion, rollback, approval-revocation and grant-revocation functions follow one deterministic lock order:

1. tenant/business-unit promotion-mutex row;
2. candidate row(s), ordered by immutable candidate UUID;
3. approval grant rows, ordered by grant UUID;
4. approval rows, ordered by approval UUID;
5. active/prior release rows, ordered by release UUID;
6. audit-chain head row for the scope.

No function may acquire these locks in a conflicting order. Where a function touches multiple scopes, it must acquire scope mutexes in lexicographic tenant/business-unit order before any lower-level row locks.

The promotion function rechecks grant validity and approval completeness **after** acquiring the scope mutex and relevant grant/approval locks. The linearization point for promotion authorization is the successful validation of all required approvals and active grants while those locks are held. Grant revocation uses the same scope mutex and lock order. Therefore:
- if revocation obtains the mutex first, the subsequent promotion sees the revoked grant and fails;
- if promotion obtains the mutex first and completes its transaction, that promotion linearizes before revocation;
- no promotion may commit using a grant revoked before its authorization linearization point.

The mutex is held until commit/rollback. A partial unique index on one active release per tenant/business-unit scope remains a final integrity safeguard, not the primary concurrency control. Duplicate requests use a caller-independent idempotency key bound to scope, candidate and operation; replays return the prior outcome without creating a second release or audit event.

Deadlock/serialization errors fail closed and may be retried only by a bounded, idempotent transaction retry policy. The retry must restart the complete transaction and repeat all authorization checks. Exhausted retries return a non-success result and do not leave partial state.

Rollback uses the same scope mutex and lock order. It does not directly reactivate a historical row. It creates a new release transition referencing the target artifact/release history after revalidating current evidence, current publisher/verifier key status, current policy and required rollback approvals. A target with revoked publisher/verifier trust or invalid evidence is not eligible for rollback.

Acceptance tests must run two competing promotions in a scope with no active release, competing promotions with an existing active release, concurrent revocation/promotion in both lock orders, duplicate retries, rollback races and bounded deadlock handling.

### F-05 — Effective privilege closure and SECURITY DEFINER contract

The implementation must provide an effective-privilege inventory for every protected table, sequence, schema, view, materialized view, partition, function and role. The inventory must include direct grants, inherited/transitive role memberships, PUBLIC grants, default privileges, ownership, RLS/FORCE RLS and function EXECUTE rights.

Required controls:

- Runtime, verifier, approver and promotion-function-owner roles are separate, non-overlapping capabilities; no general-purpose service login owns protected objects.
- The promotion function owner is a NOLOGIN role with only the minimum object rights required. It is not a member of superuser, BYPASSRLS or broad administrative roles.
- The evidence registration function has a separate NOLOGIN owner/capability and cannot mutate releases or approval records.
- `SECURITY DEFINER` functions use a fixed safe `search_path` (prefer `pg_catalog` plus fully schema-qualified application objects), schema-qualified object references, revoked PUBLIC EXECUTE and explicit EXECUTE grants only.
- Untrusted roles have no CREATE on trusted schemas and cannot replace objects, operators, casts or functions resolved by privileged code.
- Ordinary runtime has no direct INSERT/UPDATE/DELETE/TRUNCATE on trusted evidence or release tables, no sequence privileges that enable equivalent mutation, and no EXECUTE on privileged internal helper functions.
- Views, triggers, partitions, child tables, foreign-key side effects and callable functions must not provide an alternate mutation route.
- RLS and FORCE RLS remain enabled where applicable. Function ownership and any deliberate RLS bypass must be explicitly justified and tested; do not rely on table-owner bypass as an authorization mechanism.
- Protected identity continues to derive from original authenticated `SESSION_USER`, not caller-controlled GUC values or `current_user` inside a SECURITY DEFINER context.
- Future-object default privileges must preserve the same restrictions.

Acceptance tests must connect using real scoped runtime, verifier and approval login credentials and attempt direct DML, TRUNCATE, sequence use, function invocation, view/partition mutation, schema object creation, inherited-role escalation and PUBLIC paths. Catalog assertions alone are insufficient; actual SQL attempts must demonstrate denial.

### F-06 — Versioned audit serialization and concurrent append

New database-generated audit events use a stable versioned schema and canonical serialization. Version 1 uses RFC 8785 canonical JSON and SHA-256. Every event stores the schema version, canonicalization version, hash algorithm, event digest, previous event digest, scope sequence number and database-generated timestamp.

A durable audit-chain-head row exists per tenant/business-unit scope. Every approval, promotion and rollback function acquires the scope mutex first, then locks the corresponding audit-head row before reading the prior digest, allocating the next sequence and inserting the event. The head update and business-state mutation occur in the same transaction. This serializes concurrent appends and prevents two transactions from extending the same prior head.

Historical application-generated events retain their original bytes, digest and verification algorithm/version. The verifier supports both the historical format and the new database-generated format; migration must not rewrite old event hashes. A version transition is recorded as a new event referencing the last verified historical chain head.

Successful approval, promotion, release-state change and their corresponding audit event commit or roll back together. Failure to insert or advance the audit head aborts the entire business transaction.

Rejected or failed authorization attempts cannot be durably recorded in the same transaction that is intentionally rolled back. They must be sent to a separate protected security-event channel (for example, a separately committed security log or external SIEM) with request correlation, authenticated database login, scope where known, reason code and timestamp. Such failure telemetry must never be represented as a committed approval/promotion event.

Acceptance tests must force audit insertion/head-update failure and prove that approval, release and candidate changes roll back; run concurrent approvals/promotions and independently verify a gap-free, deterministic hash chain; and verify historical hashes using their original verifier.

This is transactional tamper-evident audit, not independent WORM. External immutable anchoring, retention and recovery remain separate F-05 requirements.

### F-07 — Legacy record classification and quarantine

The migration must classify existing records without manufacturing evidence:

| Legacy record | Migration treatment |
| --- | --- |
| Candidate with retrievable exact artifact, manifest, dataset snapshot, provenance and assessment inputs | Preserve as historical; mark pending fresh evidence verification; promotable only after new verifier attestation and current approval policy |
| Candidate with missing artifact bytes or incomplete manifest binding | Preserve; mark `legacy_unverifiable` and non-promotable |
| Candidate with mutable or unverifiable evaluation dataset/provenance | Preserve; mark `legacy_unverifiable` and non-promotable |
| Existing approval with unambiguous principal, role, grant and scope linkage | Preserve as historical approval evidence; do not automatically count it toward a new promotion unless it satisfies the new policy and current grant rules |
| Approval with ambiguous identity, alias or grant linkage | Preserve historically; quarantine from promotion eligibility |
| Existing release | Preserve as historical release state; do not assume it meets the new promotion policy or permit direct reactivation |
| Existing audit event | Preserve original payload, digest, algorithm and verification version without rewriting |

The migration may complete while explicitly quarantining ambiguous/non-promotable records, provided the quarantine is durable, visible and fail-closed. It must fail before changing protected authority if it cannot preserve historical rows or their original audit verification data. Produce a migration report with counts by classification and stable record identifiers; do not silently discard or auto-upgrade records.

Acceptance tests must cover each category, verify that no legacy candidate becomes promotable solely due to migration, and prove old audit hashes remain verifiable.

### F-08 — Rollback authority and reactivation policy

Rollback is a new governed release transition, not a direct status reversal or reactivation of an old release row.

A rollback request must identify the target historical artifact/release and reason. The database rollback function must:

- derive tenant/business-unit and actor from protected database identity;
- require the target to belong to the same authenticated scope;
- verify the target's immutable artifact, manifest, evaluation evidence and signed verifier receipt;
- reject target evidence whose publisher key, verifier key or trust status has been revoked or quarantined;
- assess the target under the currently effective promotion/rollback policy; the original historical approval is retained as history but is not, by itself, sufficient authorization;
- require fresh, distinct model-risk, security and operations-owner approvals for the rollback transition;
- prohibit candidate creator self-approval and enforce canonical human identity uniqueness;
- acquire the scope mutex and deterministic locks described in F-04;
- create a new release-transition record referencing both prior active release and target historical release/artifact;
- atomically update active-release state and append the rollback audit event;
- reject direct SQL changes that would achieve equivalent reactivation.

If the target fails current evidence, key-status or policy checks, rollback is denied. There is no emergency bypass in this PoV gate. Any future break-glass process requires a separately reviewed authority model, explicit dual control and independent audit.

Acceptance tests must include cross-scope target, revoked publisher key, revoked verifier key, quarantined evidence, stale policy, missing rollback approvals, creator self-approval, concurrent rollback/promotion and direct SQL reactivation attempts.

### Revised implementation entry criteria

The eight findings are considered **design-addressed only when** an independent reviewer confirms that these amendments resolve the stated design ambiguities. Implementation may then begin as a separate implementation gate with its own migration, actual PostgreSQL role/privilege tests, adversarial SQL reproduction, concurrency tests, restore tests and independent implementation review.

The reviewer’s ACCEPT WITH CONDITIONS is not converted into unconditional acceptance by this amendment. The reviewer must verify the amended design and explicitly confirm whether each F-01 through F-08 condition is satisfied or remains open.

### Gate status after this amendment

- Architecture review: ACCEPT WITH CONDITIONS, subject to independent confirmation of this amendment.
- Design amendment: proposed in this commit; not yet independently re-reviewed.
- Implementation: not started / not authorized pending independent confirmation.
- F-03: OPEN.
- F-05: OPEN; external WORM anchoring remains a separate requirement.
- PR #20: must remain Draft/open/unmerged.
- Production certification and operational utility integration: not authorized.
