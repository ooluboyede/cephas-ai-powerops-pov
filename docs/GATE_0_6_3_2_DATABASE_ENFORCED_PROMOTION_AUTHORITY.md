# Gate 0.6.3.2 — Database-Enforced Model Promotion and Evidence Authority

## Status

Architecture/design gate only. This document does not implement the controls, close F-03/F-05, certify production readiness, or authorize merge/deployment. It is based on the independent review of PR #19 at `c61652fa155ca72e6035c0d97cb338ea0583afd0`.

**Current normative amendment:** `docs/GATE_0_6_3_2_CONSOLIDATED_NORMATIVE_AMENDMENT.md` is the single authoritative consolidation for D-07.1, D-08.1, D-09.1 and D-10.1/D-10.2 and supersedes prior conflicting wording on those subjects. The earlier separate remediation addendum is retired. The original design and historical review baselines remain preserved; see the consolidated amendment for exact precedence, rollback-request v2, audit registry v2 and implementation authorization status.

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


---

## Independent reassessment response — N-01 through N-06

### Baseline preservation and status

This amendment is a new commit descended from reviewed baseline `8442032703642e780ffdfd7fd348849640f35d04`. The baseline is preserved unchanged in Git history and remains the exact commit assessed in the preceding independent reassessment. This amendment does not rewrite, force-push over, or relabel that baseline.

The independent reassessment returned **ACCEPT WITH CONDITIONS — DESIGN DIRECTION ONLY** and withheld implementation authorization. The six findings below are incorporated as explicit design requirements. They are proposed clarifications, not evidence that any control has been implemented or tested.

### N-01 — High: Verifier credential is a privileged evidence authority

#### Selected trust model

For this gate, adopt **Model A — Trusted verifier authority**, with the trust boundary made explicit:

- The dedicated verifier service and its protected database login together constitute a high-impact evidence-registration authority.
- PostgreSQL authenticates the verifier login through the protected `SESSION_USER` mapping and restricts it to the evidence-registration function.
- PostgreSQL validates envelope structure, version, scope, candidate and digest bindings, key identifiers/status metadata available to the database, uniqueness and state transitions. Unless an independently reviewed database-side Ed25519 verifier is added, PostgreSQL does not independently validate the Ed25519 signature.
- The signed receipt is independently checkable by auditors and downstream verification tools, but its presence in a row is not proof that PostgreSQL verified the signature.
- Possession of the verifier database credential is itself sufficient to invoke the evidence-registration authority. A stolen verifier database credential can therefore register a fabricated or incorrectly attested envelope even if the attacker does not possess the verifier signing key. This residual risk is accepted as part of Model A and must not be described as prevented by the signature field.

#### Required credential and service protections

The verifier database credential must be held only by the verifier service, retrieved from customer-controlled secret storage at runtime, excluded from source code, images, logs, CI output and operator workstations, and rotated/revoked through a documented procedure. Network access to the database must be restricted to the verifier service identity and approved deployment path; use mutually authenticated transport where supported. The verifier login must have no direct table DML and no EXECUTE rights beyond the single evidence-registration entry point.

The verifier signing key remains separately protected in customer-controlled secret storage or HSM/KMS where available. Signing-key separation reduces the chance that one secret exposes both signing and registration capabilities, but it does not neutralize compromise of the database credential because Model A trusts that credential to register evidence.

#### Compromise semantics

A suspected or confirmed compromise of either the verifier service or its database credential is treated as **verifier-authority compromise**, not merely as signing-key compromise. The response must:

1. Disable the verifier login and revoke registration-function EXECUTE.
2. Revoke/disable the affected verifier signing key and stop accepting new receipts from it.
3. Establish the earliest plausible exposure start and containment time.
4. Quarantine every evidence record registered by the affected verifier identity during the exposure window, including records whose receipt signature appears valid, until independently re-verified.
5. Mark candidates/releases relying on that evidence as non-promotable or under incident review through a separately authorized incident procedure; preserve original rows and history.
6. Re-verify exact retained artifact, manifest, dataset, provenance and policy bytes using a clean verifier identity and newly authorized key.
7. Record containment, quarantine, re-verification and supersession as append-only audit/security events and retain the incident record outside the affected verifier authority.

If the exposure start cannot be bounded, quarantine all evidence registered by that verifier identity since its credential/key activation or last independently verified clean rotation.

#### Acceptance criteria

The implementation review must demonstrate that the verifier login cannot directly mutate evidence, candidates, approvals or releases and cannot invoke approval, promotion or rollback functions. The reviewer must also confirm the explicit residual: a compromised verifier database credential can submit false evidence through its permitted function, and all evidence within the exposure window is quarantined pending independent re-verification. Do not claim that a fabricated signature is rejected by PostgreSQL unless a separately reviewed cryptographic verifier is actually implemented and tested.

### N-02 — Medium: Receipt identity, replay prevention and validity

Every signed verifier receipt must contain a globally unique immutable `attestation_id` (UUID), candidate UUID and immutable candidate version, scope, artifact/manifest/dataset/policy digests, verifier identity and key ID, issue time, expiry time, and protocol version. The database assigns a trusted registration timestamp and immutable evidence-row ID. Receipt identity is unique across the deployment; the database also enforces uniqueness for the receipt digest and the candidate-version/evidence relationship.

A receipt is valid only when:

- its issue time is not materially in the future under the configured clock-skew allowance;
- its expiry is later than its issue time and within the configured maximum receipt lifetime;
- it is registered before expiry;
- the verifier identity and signing key are active and not revoked at registration;
- all candidate, scope and digest bindings match the immutable candidate version; and
- the receipt has not already been consumed by a different registration request.

The customer deployment must configure a maximum receipt lifetime and bounded clock-skew allowance. These values are versioned policy, not caller-controlled parameters. Use trusted server/database time for registration decisions; do not trust a caller-supplied registration timestamp.

A repeated submission of the same `attestation_id` and exact receipt digest returns the original registration result as an idempotent response and creates no new evidence row, audit event or eligibility transition. Reuse of an ID with different bytes/digest, or reuse against a different candidate/version/scope, is rejected and security-logged.

A receipt first presented after expiry or after its verifier key has been revoked is rejected. Revocation after registration places affected evidence into quarantine/non-promotable status pending independent re-verification; it does not silently rewrite or erase the original evidence. A superseded receipt remains permanently superseded and cannot become eligible again. Re-verification creates a new attestation ID and new evidence version with an explicit immutable supersession link. It does not revive an old receipt.

Acceptance tests must cover duplicate idempotent submission, ID collision with different bytes, cross-candidate replay, expired receipt, future issue time, revoked key before registration, key revocation after registration, supersession and attempted revival.

### N-03 — Medium: Transactional audit sequence and exact hash preimage

The audit-chain head for each tenant/business-unit scope must store both the current event digest and the next sequence number as ordinary transactional row values. Do not use PostgreSQL sequences (`nextval()` or equivalent non-transactional allocators) for the gap-free audit-chain sequence.

Within the same transaction as the business mutation:

1. Acquire the scope mutex according to F-04.
2. Lock the scope's audit-chain-head row with `SELECT ... FOR UPDATE`.
3. Read the current head digest and next sequence number.
4. Construct the canonical event envelope.
5. Compute the event digest.
6. Insert the event and update the head digest and next sequence number.
7. Commit the business mutation, audit event and head update together.

Version 1 hash preimage is the exact UTF-8 byte sequence produced by RFC 8785 canonicalization of an object containing, at minimum:

- `audit_schema_version`;
- `canonicalization_version`;
- `hash_algorithm`;
- tenant and business-unit scope identifiers;
- integer sequence number;
- previous event digest (explicit genesis value for the first event);
- event type and operation/request identifier;
- canonical event payload;
- database-generated event timestamp.

The digest is SHA-256 over those canonical bytes. Persist the canonicalization/hash version and the exact canonical event bytes (or an exactly reproducible immutable representation) needed for later verification. The database, not the caller, supplies sequence, previous digest and event timestamp.

The chain-head row update and event insert must be rolled back if any later operation in the transaction fails. This guarantees transactional sequence allocation; it does not by itself protect against a privileged DBA rewriting both the chain and head, and it is not WORM.

Acceptance test: deliberately raise an error after the chain-head row has been locked and the next sequence value tentatively incremented, and after the associated business mutation has been attempted. Confirm that the chain-head digest, next sequence number, event row and business mutation all remain exactly at their pre-transaction values. Then retry successfully and confirm the next committed event uses the unconsumed sequence number with the correct prior digest. Also test concurrent appends and independent full-chain verification.

### N-04 — Medium: All authority-changing lifecycle operations share the scope mutex

Extend the F-04 serialization contract to every operation capable of changing the canonical approver identity, approval authority or the validity of an approval. The scope mutex must be acquired before any lower-level row lock for:

- approval-grant creation, replacement, revocation and re-grant;
- principal-to-login binding creation, disablement and replacement;
- canonical issuer/subject mapping creation, correction, alias consolidation and deactivation;
- identity-provider issuer/subject migration or account-link changes;
- login disablement and credential retirement where they affect an approver binding;
- grant-expiry changes and any administrative override to an approval authority; and
- promotion, rollback and any operation that changes candidate/release authority.

All such functions follow the same lock order already defined in F-04: scope mutex, candidates in stable UUID order, grants in stable UUID order, approvals in stable UUID order, release rows in stable UUID order, then audit head. Multi-scope changes acquire scope mutexes in lexicographic tenant/business-unit order before lower-level locks. No identity/grant administration path may bypass this contract with direct table DML.

#### Expiry and authorization linearization

Grant validity is evaluated at the authorization linearization point: after the scope mutex and relevant grant/approval locks have been acquired, and immediately before the promotion/rollback function commits its governed state transition. The function must re-check active status and expiry using trusted database time at that point. Grant expiry is not extended by a transaction that began before expiry.

Set a strict transaction/statement timeout for these authority-changing functions. If the transaction cannot complete within the configured maximum duration, it aborts and releases its locks; it must not commit based on a stale pre-lock authorization check. The exact timeout is deployment configuration with a documented upper bound and must be shorter than the operational approval/credential validity window.

A grant or identity change that obtains the mutex first is visible to the subsequent promotion/rollback check. If promotion/rollback obtains the mutex first and commits after a successful final authorization check, it linearizes before the waiting grant/identity change. Every outcome is serialized and auditable.

Acceptance tests must cover grant create/revoke/re-grant, identity alias consolidation, login disablement, issuer/subject remapping, grant expiry during a queued promotion, both mutex acquisition orders and timeout/rollback behavior. Actual concurrent PostgreSQL sessions must be used.

### N-05 — Medium: Atomic migration, preflight and active-release preservation

The forward-only migration after 0005 must have an explicit migration state machine and must not expose a partially upgraded promotion authority.

#### Preflight

Before changing protected privileges or release authority, run read-only preflight checks under a migration lock. Verify:

- expected schema/migration version and absence of conflicting concurrent migration;
- all protected tables, constraints, indexes, owners, grants, RLS policies and function signatures match the expected baseline;
- every historical candidate, approval, grant, audit row and release can be enumerated and classified;
- historical audit payloads/digests and the current active-release state can be preserved and independently verified;
- required immutable artifact/evidence references are available or can be explicitly quarantined;
- no ambiguous duplicate active releases or inconsistent scope references exist without an explicit quarantine/repair decision; and
- sufficient storage, permissions and maintenance window are available.

If preflight cannot establish preservation of historical rows, audit verification data or active-release state, abort before changing protected authority.

#### Transaction boundary and non-transactional operations

Where PostgreSQL supports transactional execution, apply schema changes, data classification, privilege changes, function installation and authority cutover in one transaction. Use a transaction-scoped advisory migration lock to prevent concurrent execution. Do not use non-transactional DDL such as `CREATE INDEX CONCURRENTLY` inside the authority-cutover transaction.

If an operational step cannot be made transactional, isolate it in an explicitly documented preparatory phase that does not alter effective promotion authority. Make that phase idempotent and verifiable; record a durable migration checkpoint; and do not perform the protected authority cutover until every preparatory step has passed. Define a tested retry/compensation procedure for each such step. No intermediate state may grant ordinary runtime broader effective privileges than either the pre-migration or final approved model.

#### Legacy active-release handling

Preserve the exact historical active-release identity and state during migration. Do not silently deactivate, replace, reactivate or promote a release as a side effect of schema migration. If the existing active release lacks evidence required by the new policy, preserve it as historical/current legacy state but mark it explicitly as not eligible for a new promotion or governed rollback until fresh evidence and approvals satisfy the new policy. If preserving a coherent active-state representation is impossible, abort the migration and require an independently reviewed remediation plan; do not guess which release should remain active.

#### Completion and recovery

Before declaring success, verify in a final transaction that all migration steps are recorded, the full migration chain is applied, role/function/object privileges match the intended matrix, RLS/FORCE RLS and ownership are correct, protected functions are callable only by intended roles, no ordinary runtime bypass remains, legacy classifications reconcile to source counts, audit hashes verify, and the pre-migration active-release state has been preserved consistently.

A failed transactional migration must leave the database at the complete pre-migration state. A failed preparatory phase must be safely retryable without changing authority. Test both failure and retry paths against a disposable PostgreSQL 16 database, then perform fresh-cluster restore verification. Produce a durable migration report with before/after counts, classifications, active-release identifiers and verification outcomes.

Acceptance tests must inject failures at each migration phase, prove no partial authority cutover, prove retry idempotency, verify active-release preservation and confirm the final privilege/owner/RLS/function state.

### N-06 — Medium: Rollback approvals bind to one immutable transition request

A rollback is a distinct operation type and must not reuse approvals issued for promotion or for another rollback request.

Create an immutable rollback request with a globally unique `rollback_request_id` and a canonical request digest. The digest must bind:

- operation type = `rollback`;
- rollback request ID;
- tenant and business-unit scope;
- candidate and target historical release identifiers;
- exact target artifact and manifest digests;
- exact target evidence/attestation version and verifier receipt digest;
- prior active release identifier and digest at request creation;
- reason and requestor identity;
- effective rollback policy ID, version and digest; and
- request creation timestamp and request schema version.

Each of the three required approval records (`model-risk`, `security`, `operations-owner`) must reference the exact rollback request ID and request digest, scope, target release/artifact digest, prior active release, policy version and operation type. Approvals must be signed/recorded by the database-authenticated canonical human identity and exact active grant ID. They remain subject to distinct-human, creator-exclusion, grant-validity and revocation rules.

The rollback function must recompute the canonical request digest from immutable stored fields and require a complete, positive approval set for that exact digest. It must also confirm that the prior active release has not changed since the request was approved. If it has changed, the request is stale and must be cancelled/rejected; a new rollback request and fresh approvals are required.

Any change to scope, target release, artifact/manifest/evidence digest, prior active release, reason where policy-relevant, operation type or policy version creates a new rollback request ID and invalidates the old approval set for execution. An approval cannot be transferred between rollback requests, targets, scopes, promotion and rollback operations, or prior-active-release states. Replayed approval submissions are idempotent only for the exact same approval/request binding; mismatched replay is rejected and security-logged.

The same operation-binding principle applies to promotion approvals: each approval must reference the immutable promotion request/candidate version, scope, evidence digest and policy version it authorizes. A candidate-level approval detached from a specific operation/evidence version is insufficient.

Acceptance tests must attempt to reuse an approval across two rollback targets, two artifact digests, two scopes, two prior active releases, a promotion request and a different rollback request. Every mismatch must fail closed. Also test stale prior-active state, changed policy version, duplicate/replayed approval and successful execution with three distinct fresh approvals.

### Updated design entry criteria and implementation status

The six clarifications above are submitted for independent reassessment. They do not themselves authorize implementation. Implementation remains **NOT AUTHORIZED** until an independent reviewer assesses the exact amended commit, confirms whether N-01 through N-06 are resolved or remain open, and explicitly authorizes the design as an implementation contract.

The reviewer must also retain explicit dispositions for F-01 through F-08. No original finding is deemed closed merely because a clarification has been written. Implementation, once authorized, remains a separate gate requiring actual PostgreSQL implementation evidence, adversarial tests, fresh-cluster recovery and independent implementation review.

PR #20 must remain Draft, open and unmerged. No production certification, live utility telemetry integration, operational control or automatic production model deployment is authorized.


---

## Independent reassessment response — mandatory pre-implementation conditions C-01 through C-05

**Source disposition:** The independent reassessment of commit 428abadf5ed612408cfd82ac9c835d6769dcd95e was ACCEPT WITH CONDITIONS. Implementation authorization was withheld. This is a documentation-only response. It does not claim customer risk acceptance, implementation, or successful implementation testing.

The reviewed baseline 8442032703642e780ffdfd7fd348849640f35d04 and reassessed commit 428abadf5ed612408cfd82ac9c835d6769dcd95e remain immutable historical commits. This amendment is additive and must be reassessed at its own exact commit.

### C-01 / C-05 — Model A residual risk acceptance, customer governance and promotion-time quarantine

#### Explicit trust decision

This design retains Model A: the trusted verifier service, its protected database login and its narrowly scoped evidence-registration function collectively form a privileged evidence-registration authority. PostgreSQL authenticates the database login and restricts its function capability. PostgreSQL does not independently verify the Ed25519 receipt signature. A party able to use the verifier database credential can register fabricated evidence through the permitted registration function, even without possession of the verifier signing key.

This residual risk is accepted as a possible trust model for a controlled, synthetic-data, advisory-only PoV only after the customer has knowingly accepted it in writing. It is not cryptographically independent evidence verification and must not be described as such. The customer may reject Model A; in that case the verifier registration authority remains disabled until a separately designed and independently reviewed trust model is approved.

#### Mandatory customer-approved risk-acceptance record

Before the verifier registration authority can be enabled, the customer must approve a durable, versioned security-risk-acceptance record containing, at minimum:

- unique immutable risk-acceptance record ID and schema version;
- customer legal entity, deployment/environment ID, tenant and business-unit scope;
- explicit selection of Model A and an unambiguous statement that compromise of the verifier database credential can register fabricated evidence without the signing key;
- the residual risk, plausible impact, limitations of PostgreSQL verification, and the fact that a signed receipt does not remove the verifier from the trust boundary;
- verifier service identity, database login identity, registration-function identity, verifier key IDs and credential/key custody arrangements;
- named accountable customer roles and identified human principals for risk approval, verifier credential custody, signing-key custody, incident command, quarantine authorization, independent re-verification and escalation;
- incident notification channel and escalation path, including who can disable the verifier login and revoke registration-function execution;
- approval decision, approving authority, approval timestamp, effective date, review/expiry date and conditions; and
- immutable evidence of customer authorization, such as a customer-controlled signed approval artifact or equivalent independently auditable approval record.

The record must be approved by the customer's designated security/risk authority, not self-approved by the implementation team, verifier operator or repository owner. Role assignments must resolve to canonical issuer-qualified human identities under the customer identity-governance process. The record must be in force, in scope and unexpired.

The deployment must fail closed if this record is absent, invalid, expired, revoked, out of scope or missing any accountable role. The verifier login and registration-function capability must not be enabled before the database has verified the approved record. Renewal or material change to the verifier identity, credential/key custody, incident owner or accepted residual risk requires a new approval record before continued operation. The implementation must not create a default or synthetic customer acceptance record.

#### Database-enforced enablement precondition

The verifier registration function must, at its authorization linearization point, confirm that:

1. an active customer risk-acceptance record exists for the exact deployment and scope;
2. the record explicitly accepts Model A and identifies the verifier authority being enabled;
3. the approving customer authority and required accountable roles remain valid under protected customer identity/grant mappings;
4. the record has not expired, been revoked or been superseded; and
5. the verifier identity and key are active and mapped to the exact permitted scope.

The enable/disable state must be held in protected database state. Ordinary runtime, verifier and approver logins must not be able to create, amend, extend or bypass the customer risk-acceptance record or its enablement check. Changes must use a separately governed customer-administration function and produce an audit event. Loss of a valid acceptance record disables new evidence registration and fails closed.

#### Promotion-time trust and quarantine checks

The promotion function must re-evaluate evidence trust at the authorization linearization point, after acquiring the required scope mutex and relevant row locks and immediately before committing the release transition. It must not rely solely on trust status captured when evidence was registered.

For every evidence version bound to the immutable promotion request, the function must confirm:

- the verifier identity is currently enabled and trusted for the exact deployment and scope;
- the verifier key is currently active, not revoked, not expired and not superseded for new use;
- the receipt/attestation is the exact immutable version referenced by the request;
- the evidence version is not quarantined, superseded, revoked or otherwise non-promotable;
- the customer Model A risk-acceptance record is current and applicable; and
- the candidate's evidence binding has not changed since the request and approvals were created.

A revoked verifier identity or key must make all evidence versions dependent on it non-promotable, including evidence registered before revocation. A quarantine must invalidate eligibility for every dependent candidate and every not-yet-executed promotion request. These checks must be database-enforced, not application-only filters or mutable JSON flags.

#### Quarantine propagation and already-promoted transitions

Quarantine must preserve original evidence, approval, candidate and release-transition records. It must not rewrite historical evidence or silently deactivate, replace or reactivate an active release.

The incident procedure must create an immutable incident record identifying the verifier identity/key, exposure window, affected attestation IDs and evidence versions, dependent candidate versions, promotion requests, approval sets and release-transition IDs. If the exposure start is unknown, the affected set extends back to the last independently verified clean credential/key rotation or activation, as applicable.

Every release transition that relied on affected evidence must be explicitly listed in the incident record and assigned a customer-approved disposition. Dispositions may include independent re-verification and a newly governed transition, continued legacy/current-state treatment under a documented customer decision, or another customer-authorized response. A historical transition must never be silently rewritten as though it had not occurred. While the incident remains unresolved, affected evidence cannot authorize a new promotion or rollback; any further state change must follow a separately approved incident/governance procedure.

Independent re-verification must use retained exact artifact, manifest, dataset, provenance and policy bytes, a clean verifier identity and newly authorized key. It creates a new attestation/evidence version with an immutable supersession link. It does not revive the quarantined receipt. Quarantine, re-verification, supersession and each affected-transition disposition must be append-only audit/security events, with an incident record retained outside the affected verifier authority.

#### C-01 / C-05 acceptance criteria

Before enabling the verifier authority, an implementation acceptance test must prove that registration fails when the customer risk-acceptance record is missing, expired, revoked, out of scope or lacks an accountable required role, and succeeds only with a valid customer-approved record.

A PostgreSQL adversarial test must register evidence through the permitted verifier function, revoke the verifier identity/key, quarantine the evidence and attempt promotion using a request and approval set created before revocation. Promotion must fail. The test must also prove that all dependent candidate versions and unexecuted requests are non-promotable, and that an already-promoted transition is identified in the incident record without silently changing historical rows. Test unknown exposure start and quarantine back to the last independently verified clean rotation/activation.

No customer risk-acceptance record is asserted to exist by this design amendment. Customer approval is a deployment prerequisite and remains outstanding until supplied and verified in the customer-controlled environment.

### C-02 — Closed and versioned audit event serialization contract

The prior open-ended phrase describing fields “at minimum” is replaced by a closed serialization contract. Audit hash version 1 is normative.

#### Version-1 top-level event object

The canonical JSON object must contain exactly these fields and no others:

| Field | JSON type | Rule |
| --- | --- | --- |
| audit_schema_version | string | Exactly cephas.powerops.audit-event.v1 |
| canonicalization_version | string | Exactly RFC8785 |
| hash_algorithm | string | Exactly SHA-256 |
| event_id | string | Lowercase canonical UUID text |
| tenant_id | string | Canonical tenant UUID text |
| business_unit_id | string | Canonical business-unit UUID text |
| sequence_number | number | Integer from 1 through 9,007,199,254,740,991 inclusive |
| previous_event_digest | string | Exactly 64 lowercase hexadecimal characters; genesis is 64 ASCII zeroes |
| event_type | string | Non-empty registered event-type token, maximum 128 UTF-8 bytes |
| operation_id | string | Lowercase canonical UUID text identifying the governed operation/request |
| actor_principal_id | string or null | Canonical immutable principal UUID; null only for explicitly registered system events |
| actor_issuer | string or null | Canonical issuer URI; null if and only if actor_principal_id is null |
| actor_subject | string or null | Exact canonical subject from the issuer; null if and only if actor_principal_id is null |
| event_timestamp | string | UTC timestamp in fixed YYYY-MM-DDTHH:mm:ss.ffffffZ form, six fractional digits |
| event_payload_schema | string | Registered, immutable event-specific payload schema token |
| event_payload | object | Exact payload conforming to the registered schema named by event_payload_schema |

No top-level property may be omitted. No top-level property may be added in version 1. Nullable fields must be present with JSON null; omission is not equivalent to null. actor_principal_id, actor_issuer and actor_subject must be either all null for a specifically permitted system event or all non-null. Empty strings are not substitutes for null.

#### Event payload closure

Every event_type must map to one immutable event_payload_schema. Each payload schema must define exact property names, JSON types, bounds, nullability and required/optional semantics. Unknown properties are prohibited at every object level. Optional values, where a particular payload schema permits them, must be represented using an explicitly defined nullable field rather than omission. A payload schema must not permit arbitrary untyped extension maps or caller-supplied authoritative scope, actor, sequence, timestamp, previous digest or hash fields.

A new event type or a change to any payload schema that can change canonical bytes requires a new registered payload-schema version. A change to the top-level event schema, field type, null/omission rule, timestamp representation, canonicalization or digest construction requires a new audit schema/hash version. Version 1 must never be silently reinterpreted or extended.

#### Scalar and encoding rules

- UUIDs use lowercase canonical hyphenated text. Non-canonical UUID representations are rejected before serialization.
- Digests use lowercase hexadecimal SHA-256 text without a prefix.
- sequence_number is a JSON integer, never a string or floating-point value, and must remain within the stated interoperable integer bound.
- event_timestamp is generated by PostgreSQL from trusted database time, normalized to UTC and rendered with exactly six fractional digits. It must parse to a valid timestamp in the inclusive UTC range 2000-01-01T00:00:00.000000Z through 9999-12-31T23:59:59.999999Z. Local offsets, leap-second notation, variable precision and timezone-less values are rejected.
- All strings are Unicode scalar-value strings encoded as UTF-8; invalid Unicode and unpaired surrogate representations are rejected. RFC 8785 governs canonical JSON escaping and property ordering.
- JSON numbers other than the bounded sequence_number are prohibited in version-1 event payloads unless the event-specific payload schema explicitly defines a safe integer range and exact numeric semantics. Binary quantities and arbitrary-precision decimals must use schema-defined canonical strings, not implementation-dependent floating-point serialization.
- The exact canonical UTF-8 byte sequence used for hashing must be persisted immutably as canonical_event_bytes or an equivalent byte-for-byte immutable representation. A parsed JSON projection may also be stored, but it is not a substitute for the canonical bytes.

#### Hash construction and genesis

Let C be the exact UTF-8 byte sequence obtained by applying RFC 8785 to the complete version-1 event object. The event digest is:

SHA-256(UTF8("CEPHAS-POWEROPS-AUDIT-EVENT-V1") || 0x00 || C)

The domain-separation prefix and terminating zero byte are mandatory. The stored digest is 64 lowercase hexadecimal characters. The first event in a scope uses 64 ASCII zeroes as previous_event_digest; subsequent events use the exact digest of the immediately preceding committed event in that scope.

The chain-head row stores the last committed digest and next sequence number as ordinary transactional values. The business mutation, event insert, canonical bytes, digest and chain-head update occur in one transaction under the existing lock order. A failed transaction consumes neither a sequence number nor a digest position.

#### Independent verification and version transition

A verifier must validate the exact version token, exact field set, scalar constraints, event-specific payload schema, canonicalization version, canonical bytes, domain-separated hash and previous-digest chain. Unknown schema versions, unknown payload schemas, extra/missing fields, invalid nullability or non-canonical bytes fail verification; verifiers must not guess.

A version transition is explicit. A new event/hash version has a new version token and a separately specified canonical preimage and domain-separation prefix. Historical version-1 bytes and digests remain verifiable using this contract. External immutable/WORM anchoring, retention, independent copies and recovery remain separate controls; a successful database-chain verification does not close the WORM requirement.

#### C-02 acceptance criteria

Provide at least two independently implemented audit serializers/verifiers. For the same normative fixtures they must produce byte-identical canonical output and identical digests. Fixtures must cover explicit nulls, rejected omissions, Unicode and escaping, maximum permitted sequence number, genesis and non-genesis links, timestamp precision/range, unknown fields, unknown payload schema, and a schema/hash-version transition. Include negative fixtures proving that altered property sets, null semantics, timestamps, payload types or domain-separation bytes fail verification.

### C-03 — Enumerated migration state machine and crash/retry contract

The migration runner must persist a durable migration-control record for this gate, keyed by a stable migration ID and recording the migration-contract version, source schema version, target schema version, current state, state version, timestamps, preparatory-operation checkpoints, source/target reconciliation evidence and failure details. The record is not authoritative merely because the runner reports progress; each transition must be supported by database-observable evidence.

#### Normative states and transitions

| Current state | Permitted next state | Required durable evidence / action |
| --- | --- | --- |
| NOT_STARTED | PREFLIGHT_RUNNING | Acquire migration lock; create immutable migration ID and initial control record |
| PREFLIGHT_RUNNING | PREFLIGHT_PASSED | Read-only preflight report, source counts, active-release snapshot and audit verification results persisted |
| PREFLIGHT_RUNNING | FAILED_RECOVERY_REQUIRED | Preflight failure record; no protected authority change permitted |
| PREFLIGHT_PASSED | PREPARATORY_OPERATIONS_IN_PROGRESS | Persist ordered preparatory-operation manifest and expected checksums |
| PREPARATORY_OPERATIONS_IN_PROGRESS | PREPARATORY_OPERATIONS_IN_PROGRESS | Persist each operation's started/completed checkpoint and independently verified result |
| PREPARATORY_OPERATIONS_IN_PROGRESS | PREPARATORY_OPERATIONS_VERIFIED | Every required preparatory operation completed, idempotency/reconciliation checks passed, and effective authority remains unchanged |
| PREPARATORY_OPERATIONS_IN_PROGRESS | FAILED_RECOVERY_REQUIRED | Failure/compensation record; authority remains at the complete pre-cutover model |
| PREPARATORY_OPERATIONS_VERIFIED | CUTOVER_IN_PROGRESS | Begin one database transaction; record this state inside that transaction only |
| CUTOVER_IN_PROGRESS | CUTOVER_COMMITTED | In the same transaction, commit schema/data cutover, protected privileges/functions/RLS, migration ledger and cutover marker |
| CUTOVER_COMMITTED | POST_CUTOVER_VERIFICATION_IN_PROGRESS | Reacquire migration lock and verify committed cutover marker and expected target schema |
| POST_CUTOVER_VERIFICATION_IN_PROGRESS | POST_CUTOVER_VERIFICATION_PASSED | Durable final verification report proves target authority, preservation and reconciliation invariants |
| POST_CUTOVER_VERIFICATION_IN_PROGRESS | FAILED_RECOVERY_REQUIRED | Durable failure report; new promotion/evidence authority remains fail-closed pending controlled repair |
| FAILED_RECOVERY_REQUIRED | PREPARATORY_OPERATIONS_IN_PROGRESS | Only after authorized recovery decision and verified idempotent retry/compensation plan, where cutover has not committed |
| FAILED_RECOVERY_REQUIRED | POST_CUTOVER_VERIFICATION_IN_PROGRESS | Only after authorized forward-repair/reverification plan where cutover has committed |
| POST_CUTOVER_VERIFICATION_PASSED | none | Terminal success for this migration ID; rerun is a no-op after rechecking committed marker and final report |

No other transition is permitted. A transition must use compare-and-set on the expected current state and state version under the migration lock. State regression, skipped states and success without supporting evidence are prohibited.

#### Transactional cutover and crash determination

CUTOVER_IN_PROGRESS is written only inside the same transaction as the authority cutover. It must not be exposed as a separately committed state. If the process or database fails before commit, PostgreSQL rolls back the cutover transaction and the last durable state remains PREPARATORY_OPERATIONS_VERIFIED; the runner may safely retry the cutover after rechecking preconditions.

If the commit succeeds but the runner loses its connection before receiving confirmation, restart logic must inspect the durable migration ledger, committed cutover marker, target schema version, migration ID and transactionally written cutover evidence. If all agree, the runner treats cutover as committed and proceeds to post-cutover verification; it must not repeat non-idempotent operations or infer rollback from a missing client acknowledgement. If the marker and schema/authority state disagree, the runner enters FAILED_RECOVERY_REQUIRED and must not report success.

#### Preparatory operations and retry

Each non-transactional preparatory operation must have a stable operation ID, deterministic input digest, expected output/checksum, start checkpoint, completion checkpoint and independent verification result. Re-running an operation with the same ID and same input must be idempotent or detect that its expected output already exists. Reusing an operation ID with different inputs is rejected. Compensation, where possible, must itself be an explicit checkpointed operation; the runner must never assume an external side effect was undone because its process exited.

Preparatory work must not grant ordinary runtime, verifier or approver roles broader effective authority than the pre-migration model. It must not alter the active-release identity/state. Before every retry, reconcile actual external/database state with durable checkpoints. Ambiguous state requires FAILED_RECOVERY_REQUIRED, not blind retry.

#### Failure, success and active-release preservation

The migration runner must not report success, enable the new verifier/promotion authority or mark the gate operationally ready until CUTOVER_COMMITTED and POST_CUTOVER_VERIFICATION_PASSED are both durably confirmed.

If post-cutover verification fails, do not automatically reverse or partially roll back the committed authority cutover. Keep new evidence registration and promotion fail-closed, preserve active-release identity/state and historical rows, and require an authorized forward-repair or separately reviewed restore plan. The runner must not mark success.

Capture the exact active-release identity and state before preparatory work. Reconcile it after every preparatory restart, after cutover commit and after final verification. Any mismatch is a hard failure requiring recovery; no migration step may silently deactivate, replace, reactivate or promote a release.

#### C-03 acceptance criteria

In disposable PostgreSQL 16 environments, inject process termination and database interruption at every state transition boundary and after every non-transactional preparatory operation. Restart the runner and demonstrate correct state determination, safe retry/compensation, no duplicate side effects, no premature authority enablement and exact active-release preservation. Test the ambiguous lost-commit-acknowledgement case. Verify that the runner cannot declare success unless the committed cutover marker and final verification report both exist and reconcile.

### C-04 — Complete immutable promotion-request envelope and digest

Promotion and rollback use one operation-binding framework with distinct operation types, unique request IDs and non-transferable approval sets. Promotion requests are specified as completely as rollback requests.

#### Promotion request schema version 1

A promotion request is an immutable record containing exactly the following canonical fields:

| Field | Type / rule |
| --- | --- |
| request_schema_version | Exact string cephas.powerops.promotion-request.v1 |
| canonicalization_version | Exact string RFC8785 |
| digest_algorithm | Exact string SHA-256 |
| operation_type | Exact string promotion |
| promotion_request_id | Unique lowercase canonical UUID |
| tenant_id | Canonical tenant UUID |
| business_unit_id | Canonical business-unit UUID |
| candidate_id | Canonical candidate UUID |
| candidate_version | Immutable positive integer within the interoperable safe-integer bound |
| artifact_sha256 | 64 lowercase hexadecimal characters |
| manifest_sha256 | 64 lowercase hexadecimal characters |
| dataset_snapshot_sha256 | 64 lowercase hexadecimal characters |
| provenance_sha256 | 64 lowercase hexadecimal characters |
| assessment_sha256 | 64 lowercase hexadecimal characters |
| evidence_version_id | Immutable evidence-version UUID |
| attestation_id | Immutable verifier attestation UUID |
| receipt_sha256 | 64 lowercase hexadecimal characters |
| publisher_key_id | Immutable publisher-key identifier |
| verifier_identity_id | Immutable verifier identity identifier |
| verifier_key_id | Immutable verifier-key identifier |
| policy_id | Immutable promotion-policy identifier |
| policy_version | Immutable policy version token |
| policy_sha256 | 64 lowercase hexadecimal characters |
| prior_active_release | Required object defined below; never omitted |
| requestor_principal_id | Canonical immutable human principal UUID authenticated by the database |
| requestor_issuer | Canonical issuer URI from protected identity mapping |
| requestor_subject | Exact canonical subject from protected identity mapping |
| request_created_at | Database-generated UTC timestamp in fixed six-fractional-digit form |

prior_active_release is a closed object with exactly three fields: state, release_id and transition_sha256. If state is present, release_id is a canonical UUID and transition_sha256 is a 64-character lowercase SHA-256 digest of the immutable transition that made it active. If state is none, both release_id and transition_sha256 must be explicit JSON null. This explicitly represents the genesis/no-active-release case; omission or an empty string is invalid.

All fields are mandatory. No additional fields are allowed in schema version 1. No field may be omitted. Null is prohibited except for the two explicitly nullable prior_active_release members in the none case. All identifiers, digests, timestamp and integer constraints are validated before canonicalization. The requestor identity and timestamp are derived by the database, not accepted as authority from caller-supplied JSON.

#### Canonical bytes and digest

The database constructs the immutable request envelope from trusted candidate/evidence/policy/identity/release state. It serializes the complete object using RFC 8785 to UTF-8 canonical bytes P. The request digest is:

SHA-256(UTF8("CEPHAS-POWEROPS-PROMOTION-REQUEST-V1") || 0x00 || P)

Persist the exact canonical request bytes, schema/canonicalization/hash versions and 64-character lowercase digest. Recompute the digest from immutable stored fields when recording approvals and again inside the promotion function. Do not trust a caller-supplied digest or mutable JSON projection.

#### Approval and execution binding

Each required approval (model-risk, security, operations-owner) must reference the exact promotion_request_id and promotion_request_digest, operation type, tenant/business-unit scope, candidate ID/version, evidence version, artifact/manifest/dataset/assessment/receipt digests, policy ID/version/digest and prior-active-release state. Each approval must also bind to the exact database-authenticated canonical human principal and active grant ID at recording time. Three distinct principals and creator exclusion remain mandatory.

At execution, the promotion function must recompute the request digest and compare it to every approval's stored request ID/digest and bound fields. It must re-check that the prior active release is exactly the one in the request, including the explicit none state; that the candidate and evidence versions remain unchanged; that the verifier identity/key and evidence remain trusted and non-quarantined; that the policy remains effective; and that all grants remain valid at the authorization linearization point.

If the prior active release changes, or any candidate version, artifact, manifest, dataset, provenance, assessment, evidence/attestation version, verifier/publisher key, policy, scope or requestor-bound field changes, the request is stale and its approval set cannot authorize execution. Create a new promotion request ID and collect fresh approvals. An approval cannot be transferred between requests, candidates, evidence versions, scopes, prior-active states, policy versions, promotion and rollback operations. Exact duplicate approval submission may be idempotent only for the identical approval/request binding; conflicting replay is rejected and security-logged.

Rollback uses the same canonical request framework with operation_type=rollback, a distinct rollback request schema/version and a unique rollback request ID. Promotion and rollback schemas must not be conflated, and neither operation may consume the other's approval set.

#### C-04 acceptance criteria

PostgreSQL adversarial tests must attempt approval reuse after changing, one at a time, candidate version, artifact digest, manifest digest, dataset snapshot, provenance, assessment, evidence version, attestation/receipt, publisher key, verifier identity/key, policy ID/version/digest, scope, requestor, prior active release and the genesis/no-active-release state. Every mismatch must fail closed and require a new request and fresh approvals. Verify byte-identical RFC 8785 serialization and digest reproduction in two independent implementations, exact request immutability, stale-request rejection and cross-operation approval non-transfer.

### Cross-condition implementation and governance acceptance

The following conditions remain pre-implementation requirements and must not be deferred to ordinary post-implementation hardening:

1. The customer-approved Model A risk-acceptance record and accountable incident roles are mandatory before verifier authority enablement.
2. The closed audit-event v1 schema and domain-separated hash construction are part of the implementation contract.
3. The migration state machine and crash/retry contract are part of the implementation contract.
4. The immutable promotion-request v1 envelope and digest are part of the implementation contract.
5. PostgreSQL must enforce all enablement, quarantine, request-binding, state-transition and privilege boundaries; application-only checks are insufficient.

These amendments define requirements only. They do not prove PostgreSQL enforcement, independent serialization agreement, migration recovery, customer acceptance or incident readiness.

### Updated gate status

- C-01 — Model A residual risk: Design requirement specified; customer acceptance and implementation enforcement remain outstanding.
- C-02 — Audit serialization: Closed schema and digest contract specified; independent serializer/verifier and PostgreSQL implementation tests remain outstanding.
- C-03 — Migration recovery: States, transitions and crash/retry contract specified; implementation and failure-injection tests remain outstanding.
- C-04 — Promotion request binding: Complete immutable request schema and digest specified; implementation and adversarial approval-reuse tests remain outstanding.
- C-05 — Customer governance: Risk record, accountable roles and fail-closed enablement precondition specified; customer approval and implementation enforcement remain outstanding.

**Implementation authorization remains NOT GRANTED.** This amendment requests a new independent exact-commit reassessment. PR #20 must remain Draft, open and unmerged. Synthetic data and advisory-only utility PoV boundaries remain unchanged. No live IBEDC telemetry, SCADA/ADMS/DMS control, switching, dispatch, meter commands, billing adjustments, refunds, journal postings or automatic production model deployment is authorized.


---

## Independent reassessment amendment — D-01 through D-06
**Amendment date:** 19 November 2026  
**Parent design commit:** `de5e10dd23e643d4658fdbd9d25f64ffb95a1018`  
**Purpose:** Convert the six findings in the independent reassessment into normative, testable implementation-contract requirements. This section is additive. It does not alter or supersede the parent commit or earlier review baselines.

### Amendment status and interpretation

This is still a design-only amendment. It does not establish that any PostgreSQL migration, privilege report, concurrent-session test, serializer, rollback function, audit registry, external immutable anchor, customer risk acceptance or deployment control exists or has passed. Implementation authorization remains **NOT GRANTED** pending independent review of the exact amended commit.

The threat model continues to exclude compromise of PostgreSQL superuser/DBA, the database host, the operating-system administrator, and the customer secret manager. These exclusions are not accepted implicitly by Model A risk acceptance. They require separate customer risk treatment, administrative separation, monitored privileged access, independently retained audit evidence, tested backup/recovery and incident response. No database-only design in this gate claims to resist an administrator who can rewrite database storage, replace binaries or control the host.

---

### D-01 — Normative effective-privilege closure matrix

#### D-01.1 Closed inventory is a release artifact

The implementation must ship a versioned, machine-readable privilege contract named `powerops-privilege-matrix.v1`. It is part of the migration and acceptance evidence, not an informal checklist. It must enumerate every role, schema, table, partition, sequence, view, materialized view, type, domain, function, procedure, trigger function, extension-owned object, default-privilege rule and ownership relationship that can read or affect:

- tenant/business-unit identity and scope mapping;
- risk-acceptance records and accountable-role mappings;
- verifier identities, verifier keys, attestations and evidence;
- candidates, candidate projections and model artifacts/references;
- promotion and rollback requests and approvals;
- grants, principal mappings and revocation state;
- active-release state and release history;
- audit events, canonical bytes, chain heads and migration ledger;
- quarantine, incident, supersession and re-verification records.

The inventory must include object OIDs and qualified names for a specific database build, object owner, object kind, partition parent/child relationship, schema, direct ACL, effective ACL, inherited role path, PUBLIC privileges, grant option, RLS state, FORCE RLS state, policy definitions, function language, SECURITY DEFINER status, owner, fixed search_path, EXECUTE grants, and applicable ALTER DEFAULT PRIVILEGES entries. The report must identify the migration version, database version, cluster identity, extraction timestamp and matrix version.

An object that is not in the matrix is not implicitly safe. Any newly introduced object in a protected schema or any new callable function that can affect a protected invariant must cause the privilege-closure check to fail until the matrix is deliberately versioned and reviewed.

#### D-01.2 Required role classes and authority

The matrix must define, at minimum, these separate role classes. Names may be mapped to deployment-specific names, but their capabilities must not be combined:

| Role class | Permitted authority | Prohibited authority |
| --- | --- | --- |
| Database superuser / break-glass DBA | Emergency administration under customer-controlled dual control and monitored break-glass procedure | Routine application use; use as runtime/verifier/approver identity |
| Schema/object owner roles | Own only their explicitly assigned objects; NOLOGIN | Application login; ordinary runtime use; direct human approval |
| Migration executor | Execute approved forward-only migrations during controlled maintenance window | Runtime traffic; evidence registration; approval; promotion outside migration contract |
| `powerops_runtime` | Minimum scoped reads and explicitly listed non-authoritative projection operations | Writes to protected evidence, trust, risk, grant, request, approval, release, audit or migration authority |
| Evidence verifier login | EXECUTE only on the evidence-registration entry point and read only the minimum candidate inputs required | Direct table/sequence writes; approval, promotion, rollback, risk acceptance, quarantine disposition |
| Human approver login | Submit an approval through the approval function for its authenticated principal and active grant | Direct approval-table writes; grant/risk/key/evidence mutation; promotion/rollback execution unless separately authorized |
| Promotion executor capability | Invoked only by the approved promotion function path | Direct login; general table ownership; arbitrary request or approval mutation |
| Incident/quarantine authority | Invoke narrowly scoped quarantine and incident functions for assigned scope | Rewrite evidence, audit history, or already-committed release history |
| Audit verifier / exporter | Read-only verification and export of committed audit evidence | Mutate event bytes, chain head, WORM copy or source rows |
| External anchor writer | Append-only write to separately controlled immutable storage | Delete, overwrite, shorten retention or administer source database |

No role used by application traffic may own a protected object, be a member of an owner/capability role, possess SET ROLE into one, possess CREATEROLE/CREATEDB/REPLICATION/BYPASSRLS, or have an indirect path to those capabilities. NOLOGIN alone is not proof of safety: ownership, memberships, grant options and SECURITY DEFINER call paths must all be included.

#### D-01.3 Object-class privilege rules

The version-1 matrix must encode these minimum rules:

| Protected object class | Runtime | Verifier | Approver | Authority functions |
| --- | --- | --- | --- | --- |
| Trust/risk/identity/grant base tables | No INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER; scoped SELECT only where explicitly required | No writes; minimum read only | No writes; minimum read only | Access only through fixed-owner functions |
| Evidence/attestation base tables | No writes | No direct writes; registration function only | No writes | Registration/quarantine/re-verification functions only |
| Candidate/release/active-release tables | No authority-changing writes | No writes | No writes | Promotion/rollback functions only |
| Request/approval tables | No writes | No writes | No direct writes; approval function only | Request/approval/promotion functions only |
| Audit event/canonical-byte/chain-head tables | No writes | No writes | No writes | Authority functions append atomically; verifier reads only |
| Migration ledger and cutover marker | No writes | No writes | No writes | Migration executor under migration contract only |
| Sequences/identity generators | No direct USAGE/UPDATE unless explicitly required and proven non-authoritative | No direct use unless explicitly required | No direct use unless explicitly required | Functions own and consume required sequences |
| Views/materialized views | SELECT only when scoped and non-leaking | Minimum required reads | Minimum required reads | No authority is conferred by a view |
| Partitions and partition parents | Same restrictions as protected parent; no direct child bypass | Same | Same | Functions only |
| Functions/procedures/triggers | EXECUTE only on enumerated public entry points | Registration entry point only | Approval entry point only | Internal helpers inaccessible to application principals |

All protected schemas must revoke unneeded privileges from PUBLIC. Default privileges must be set for every object-creating owner before object creation and verified afterwards. A default-privilege rule is not a substitute for checking already-created objects.

The matrix must explicitly address partition attachment/detachment, inherited grants on partition children, ownership transfer, function replacement, trigger replacement, view owner semantics, security-invoker/security-definer behavior, extension objects, temporary schemas, search_path shadowing, overloaded functions, operators and casts that privileged SQL may resolve. Privileged functions must schema-qualify every non-catalog object reference, use a fixed safe search_path, reject untrusted dynamic SQL, and have no attacker-writable schema in name resolution.

#### D-01.4 Effective privilege report and fail-closed comparison

After migration and after every fresh-cluster restore, the migration gate must generate a database-derived effective-privilege report using catalog inspection and real role impersonation/session tests. It must calculate transitive membership closure and effective privileges, not merely display direct ACL entries. It must compare the observed inventory against the committed matrix and fail on:

- an unexpected owner, membership, grant, grant option, PUBLIC privilege or default-privilege rule;
- any protected object absent from the matrix;
- any runtime/verifier/approver path to protected DML, TRUNCATE, ownership, schema CREATE, function replacement or privileged SET ROLE;
- any partition whose effective privileges exceed its parent contract;
- any SECURITY DEFINER function with an unapproved owner, unsafe search_path, unexpected EXECUTE grant or mutable helper dependency;
- any RLS-disabled or non-FORCE-RLS protected table where the matrix requires both;
- any difference between the pre-restore and post-restore authority inventory.

The report must be retained with migration ID, database build, matrix version and cryptographic digest. A human-readable summary is insufficient without the raw machine-readable result and reproducible query/test harness.

#### D-01.5 Required acceptance tests

Use distinct real PostgreSQL login credentials for runtime, verifier, each approver, migration executor and break-glass DBA. Prove that runtime/verifier/approver cannot directly mutate protected tables, partitions, sequences, views, materialized views, functions, triggers or helper objects; cannot create a shadow object resolved by privileged code; cannot SET ROLE or inherit capability membership; and cannot exploit owner, default-privilege or PUBLIC paths.

Repeat the complete test after a clean fresh-cluster restore, not only same-cluster restart. Include a negative fixture that deliberately adds one unexpected grant, membership, owner or helper function and prove the gate fails. D-01 closes only when the matrix, observed report, adversarial tests and independent review agree.

---

### D-02 — One serialization protocol for all promotion-eligibility mutations

#### D-02.1 Scope mutex is mandatory for every authority-affecting writer

Every transaction that can change whether a promotion or rollback is eligible must acquire the same tenant/business-unit scope mutex used by promotion, before reading or mutating governed state. This includes, without exception:

- verifier identity activation, disablement, suspension and revocation;
- verifier key activation, expiry, revocation, compromise declaration and supersession;
- customer risk-acceptance creation, amendment, expiry-state transition, revocation and supersession;
- accountable-role appointment, replacement, grant, suspension and removal;
- evidence quarantine, quarantine release, supersession and re-verification;
- publisher-key trust changes where they affect the candidate's evidence;
- promotion-policy activation, retirement or revocation;
- approval grant creation, expiry, suspension and revocation;
- incident disposition that changes evidence eligibility;
- promotion and rollback request creation, approval and execution.

No direct table DML may mutate these records. Each class must have one or more narrowly scoped database entry-point functions; triggers may enforce invariants but must not create an alternate weaker authorization path.

#### D-02.2 Canonical lock order

All authority-changing transactions must acquire locks in this exact order, omitting only a class that the operation provably does not touch:

1. tenant/business-unit scope mutex row;
2. customer risk-acceptance record and accountable-role mapping rows, ordered by immutable UUID;
3. verifier identity and verifier-key trust rows, ordered by immutable UUID;
4. publisher-key trust rows, ordered by immutable UUID;
5. evidence/attestation/quarantine/supersession rows, ordered by immutable UUID;
6. candidate row;
7. promotion or rollback request row;
8. approval and grant rows, ordered by immutable UUID;
9. active-release pointer and relevant release-history rows;
10. audit chain-head row;
11. append-only audit event insertion and final state writes within the same transaction.

The implementation must publish a lock-acquisition map for every authority function. A function may not acquire a lower-order lock and later acquire a higher-order lock. Batch operations must sort same-class UUIDs lexicographically before locking. A missing scope mutex or trust row is a hard failure, not a reason to skip serialization.

Where foreign-key checks or trigger execution acquire implicit locks, the implementation must document and test those effects against this order. Deadlock detection/retry must be bounded and idempotent; retry must re-read all trust and request state under the complete lock protocol.

#### D-02.3 Linearization and winner semantics

The authorization linearization point is the final, database-derived eligibility evaluation performed by the authority function after all required locks are held and before the first irreversible state transition, while the scope mutex remains held until commit or rollback.

All writers listed in D-02.1 must hold that same scope mutex until their trust mutation, version increment and corresponding audit event commit. Therefore:

- If promotion obtains the scope mutex first, performs the final checks and commits first, the promotion is ordered before a later revocation/quarantine/expiry-state mutation. The later mutation must identify the just-committed release in its impact assessment; it must not rewrite history.
- If revocation, quarantine, risk-acceptance invalidation, key disablement or role removal obtains the mutex and commits first, a subsequent promotion must observe the invalid state and fail.
- A promotion must never commit based on a pre-lock or stale snapshot that predates a trust mutation committed before its own linearization point.
- A transaction that aborts has no authority effect and no committed audit event. Its lock release permits the next transaction to evaluate the then-current committed state.
- No asynchronous worker may make a previously approved request executable without repeating the complete final eligibility evaluation under the same lock protocol.

The contract requires PostgreSQL READ COMMITTED or a stricter isolation level with explicit row locking and re-read after lock acquisition. If REPEATABLE READ or SERIALIZABLE is used, the implementation must prove that stale snapshots cannot bypass the required post-lock checks and must treat serialization failures as full transaction retries, not partial continuation. The exact supported isolation level must be fixed in the implementation contract and tested.

#### D-02.4 Expiry semantics

Time-based validity is evaluated using PostgreSQL database time captured after the scope mutex and all relevant trust rows have been locked. A record is valid only when `effective_at <= authorization_time < expires_at`, with no grace period. Equality with expires_at is expired. The same captured authorization_time is used for all validity checks and persisted in the request/decision/audit event. Client clocks and application timestamps are never authoritative.

If an expiry boundary is crossed before the linearization point, the action fails. If the action linearizes before expiry and commits after the wall-clock expiry instant, it is ordered before expiry and records the captured authorization_time. Expiry itself does not depend on a background job: every authority function checks the timestamp directly. Background expiry workers may update display/status projections only and must use the same mutex if they mutate authoritative state.

#### D-02.5 Required concurrency tests

Use independent PostgreSQL sessions and deterministic barriers to test both lock acquisition orders for promotion racing with each of: verifier identity revocation, verifier key revocation, publisher-key revocation, risk-acceptance revocation, risk-acceptance expiry, accountable-role removal, approval-grant revocation, evidence quarantine, evidence supersession and policy retirement.

For each pair, prove the only outcomes are:
- mutation commits first and promotion fails; or
- promotion commits first and the mutation records its later ordering and affected release.

No third outcome is acceptable. Test lock timeout, deadlock, transaction rollback, serialization failure, retry, expiry equality, and a timestamp crossing while waiting for the mutex. Verify one audit event per committed state transition and none for rolled-back transitions. Preserve already-promoted release history unchanged.

---

### D-03 — Versioned customer risk acceptance as a serialized authorization object

#### D-03.1 Immutable version model

Customer Model A risk acceptance is a protected, versioned authorization object, not a mutable free-form flag. Each version must have:

- immutable risk_acceptance_id and monotonically increasing version;
- customer entity, deployment, tenant and business-unit scope;
- exact threat-model identifier and explicit Model A verifier-credential residual risk;
- explicit exclusions for DBA/superuser, host and secret-manager compromise;
- named, issuer-qualified accountable principal IDs and role assignments;
- approval evidence digest, approver authority reference and approval timestamp;
- effective_at, expires_at, revocation/supersession metadata and prior-version digest;
- schema version and immutable canonical record digest.

A version is never edited in place. Material changes create a new version and a supersession event. Revocation is a one-way state transition recorded by a protected function; revoked versions cannot be reactivated. The currently effective version pointer is protected and updated under the scope mutex.

#### D-03.2 Role-holder validity

Risk approval, verifier credential custody, signing-key custody, incident command, quarantine authority, independent re-verification and escalation must each map to an issuer-qualified principal with a validated customer authority record. The mapping must include immutable principal identity, issuer, subject, role, scope, grant ID, effective/expiry interval, status and evidence of customer appointment.

Removal, expiry or revocation of any required role invalidates the risk acceptance for new evidence registration and promotion at the next authorization linearization point. The risk acceptance does not remain valid merely because its original approval signature is intact. A replacement role-holder requires a new risk-acceptance version and customer approval; the implementation team cannot silently substitute itself.

#### D-03.3 Registration and promotion race behavior

Evidence registration and promotion both acquire the D-02 scope mutex and lock the current risk-acceptance version and all required role mappings in the D-02 order. After locking, the function captures database authorization_time and validates that exactly one current risk-acceptance version is in scope, active, unrevoked, unsuperseded, within its validity interval, and supported by all required active role mappings.

The registration or promotion request stores the risk_acceptance_id, version and canonical digest it relied upon. Promotion rechecks that exact version remains current and valid at its own linearization point. A newly approved replacement version does not silently grandfather old pending requests; they must be re-evaluated and, where the material risk or authority basis changed, re-requested and re-approved.

If revocation, supersession, role removal or expiry commits first, evidence registration and promotion fail. If registration or promotion linearizes first, its event records that ordering and the later governance mutation records the affected evidence, requests and releases. A previously registered receipt is not deleted; it becomes non-promotable if its risk-acceptance basis is invalidated.

#### D-03.4 Required tests

Race registration and promotion against risk-record revocation, expiry, supersession, role-holder removal, role-grant revocation and role-holder identity disablement in both lock orders. Test exact expiry equality and time crossing while blocked on the scope mutex. Test missing, duplicate, out-of-scope, expired, revoked, superseded and incorrectly issuer-qualified roles. Demonstrate that no client-supplied timestamp or caller-supplied risk-acceptance ID can override the database's current version.

---

### D-04 — Complete rollback request schema version 1

#### D-04.1 Closed envelope

A rollback request is a distinct immutable schema, not a promotion request with a different operation label. Version 1 uses the exact schema token `cephas.powerops.rollback-request.v1`, RFC 8785 canonicalization and SHA-256. The envelope contains exactly these fields:

| Field | Type / rule |
| --- | --- |
| request_schema_version | Exact string `cephas.powerops.rollback-request.v1` |
| canonicalization_version | Exact string `RFC8785` |
| digest_algorithm | Exact string `SHA-256` |
| operation_type | Exact string `rollback` |
| rollback_request_id | Unique lowercase canonical UUID |
| tenant_id | Canonical tenant UUID |
| business_unit_id | Canonical business-unit UUID |
| source_active_release_id | Canonical UUID of the exact currently active release |
| source_active_transition_sha256 | Digest of the immutable transition that made source release active |
| target_release_id | Canonical UUID of the exact historical target release |
| target_release_transition_sha256 | Digest of the immutable transition that created/activated the target release |
| target_candidate_id | Canonical UUID |
| target_candidate_version | Positive interoperable safe integer |
| target_artifact_sha256 | 64 lowercase hexadecimal SHA-256 |
| target_manifest_sha256 | 64 lowercase hexadecimal SHA-256 |
| target_evidence_version_id | Immutable UUID |
| target_attestation_id | Immutable UUID |
| target_receipt_sha256 | 64 lowercase hexadecimal SHA-256 |
| target_publisher_key_id | Immutable publisher-key identifier |
| target_verifier_identity_id | Immutable verifier identity identifier |
| target_verifier_key_id | Immutable verifier-key identifier |
| target_policy_id | Immutable policy identifier |
| target_policy_version | Immutable policy version token |
| target_policy_sha256 | 64 lowercase hexadecimal SHA-256 |
| rollback_policy_id | Immutable rollback-policy identifier |
| rollback_policy_version | Immutable rollback-policy version token |
| rollback_policy_sha256 | 64 lowercase hexadecimal SHA-256 |
| rollback_reason_code | Closed enumerated policy reason code; no arbitrary free-text authority |
| rollback_reason_sha256 | Digest of separately retained immutable reason/context record; required even when the record represents a minimal reason |
| eligibility_assessment_sha256 | Digest of the database-derived rollback eligibility assessment |
| requestor_principal_id | Canonical human principal UUID from protected DB identity mapping |
| requestor_issuer | Canonical issuer URI from protected identity mapping |
| requestor_subject | Exact canonical subject from protected identity mapping |
| request_created_at | PostgreSQL-generated UTC timestamp with exactly six fractional digits |
| risk_acceptance_id | Current immutable customer risk-acceptance UUID |
| risk_acceptance_version | Positive safe integer |
| risk_acceptance_sha256 | Canonical digest of the exact risk-acceptance version |

Every field is mandatory and non-null. There is no genesis/no-active-release rollback: rollback requires an existing source active release and an independently eligible historical target. If no active release exists, rollback is rejected; initial release is a promotion operation. No additional fields, omitted fields, implicit defaults or extension maps are permitted in v1.

The target must be independently revalidated at execution. It is not enough that the target was once active: its exact artifact, manifest, evidence, attestation, publisher/verifier trust, policy and quarantine status must remain eligible under current policy. A rollback must not revive evidence or trust that has since been revoked or quarantined.

#### D-04.2 Canonical bytes and digest

The database constructs the envelope from locked, authoritative rows. It persists exact canonical UTF-8 bytes R and computes:

`SHA-256(UTF8("CEPHAS-POWEROPS-ROLLBACK-REQUEST-V1") || 0x00 || R)`

The prefix is distinct from promotion. The exact schema token, canonicalization version, hash algorithm, canonical bytes and lowercase digest are immutable. Caller-supplied request bytes or digest are never authority.

#### D-04.3 Approval and execution binding

Rollback approvals bind the exact rollback_request_id and digest, operation type, scope, source active release and transition digest, target release and transition digest, target candidate/version, target artifact/manifest/evidence/attestation/receipt, publisher/verifier identities and keys, rollback policy/version/digest, reason code/digest, eligibility assessment, requestor and risk-acceptance version/digest. Each approval also binds the authenticated principal, active grant ID and role at recording time.

At execution the rollback function recomputes the envelope digest, rechecks the exact source active release and target, rechecks all current trust and quarantine state, rechecks grants and risk acceptance under D-02/D-03 locks, and rejects any mismatch. A changed source, target, reason record, policy, eligibility assessment, trust key, evidence, requestor or risk-acceptance version requires a new rollback request and fresh approvals. Promotion approvals cannot authorize rollback and rollback approvals cannot authorize promotion.

#### D-04.4 Required tests

Two independent implementations must emit byte-identical canonical rollback bytes and digest for normative fixtures. Negative fixtures cover every field, missing/extra/null fields, invalid UUIDs/digests, invalid timestamp, reason code, policy and source/target transition changes. PostgreSQL tests mutate each bound field after approval and prove execution fails; test cross-operation approval reuse; test target quarantine/revocation and source active-release changes; test duplicate/replayed request IDs.

---

### D-05 — Normative audit event registry and closed payload schemas

#### D-05.1 Registry rules

The audit registry is immutable and versioned as `cephas.powerops.audit-payload-registry.v1`. Every authority function must emit only an event type registered below. The event object's top-level fields remain exactly those specified by audit event v1; `event_payload_schema` must equal the exact registry token associated with `event_type`. Unknown event types, unknown schema tokens, missing fields, extra fields, wrong types, invalid references and inconsistent scope relationships fail closed.

All UUIDs below use lowercase canonical UUID text; all digest fields use 64 lowercase hexadecimal SHA-256 text; all timestamps use the audit-v1 database-generated UTC six-fractional-digit representation. Event payload objects are closed: no arbitrary maps, unknown properties or implicit nulls. Where a field is not applicable, the schema must define an explicit enum state rather than omit it.

#### D-05.2 Required event registry

| Event type | Payload schema token | Mandatory closed payload fields |
| --- | --- | --- |
| `risk_acceptance.created` | `cephas.powerops.audit-payload.risk-acceptance-created.v1` | risk_acceptance_id, version, record_sha256, customer_entity_id, deployment_id, tenant_id, business_unit_id, effective_at, expires_at, approver_principal_id, approval_evidence_sha256 |
| `risk_acceptance.revoked` | `cephas.powerops.audit-payload.risk-acceptance-revoked.v1` | risk_acceptance_id, version, record_sha256, revocation_reason_code, revoking_principal_id, prior_status, affected_evidence_count, affected_request_count |
| `risk_acceptance.superseded` | `cephas.powerops.audit-payload.risk-acceptance-superseded.v1` | prior_risk_acceptance_id, prior_version, prior_record_sha256, successor_risk_acceptance_id, successor_version, successor_record_sha256 |
| `accountable_role.changed` | `cephas.powerops.audit-payload.accountable-role-changed.v1` | risk_acceptance_id, risk_acceptance_version, role_code, prior_principal_id, new_principal_id, prior_grant_id, new_grant_id, change_reason_code |
| `verifier_identity.changed` | `cephas.powerops.audit-payload.verifier-identity-changed.v1` | verifier_identity_id, prior_status, new_status, verifier_key_id, change_reason_code, effective_at, actor_principal_id |
| `verifier_key.changed` | `cephas.powerops.audit-payload.verifier-key-changed.v1` | verifier_identity_id, verifier_key_id, prior_status, new_status, key_fingerprint_sha256, change_reason_code, effective_at |
| `publisher_key.changed` | `cephas.powerops.audit-payload.publisher-key-changed.v1` | publisher_key_id, prior_status, new_status, key_fingerprint_sha256, change_reason_code, effective_at |
| `evidence.registered` | `cephas.powerops.audit-payload.evidence-registered.v1` | candidate_id, candidate_version, evidence_version_id, attestation_id, receipt_sha256, artifact_sha256, manifest_sha256, dataset_snapshot_sha256, provenance_sha256, assessment_sha256, verifier_identity_id, verifier_key_id, risk_acceptance_id, risk_acceptance_version |
| `evidence.quarantined` | `cephas.powerops.audit-payload.evidence-quarantined.v1` | evidence_version_id, attestation_id, quarantine_id, incident_id, reason_code, verifier_identity_id, verifier_key_id, affected_request_count, affected_release_count |
| `evidence.quarantine_released` | `cephas.powerops.audit-payload.evidence-quarantine-released.v1` | evidence_version_id, quarantine_id, incident_id, independent_reverification_id, new_evidence_version_id, verifier_identity_id, verifier_key_id, disposition_code |
| `evidence.superseded` | `cephas.powerops.audit-payload.evidence-superseded.v1` | prior_evidence_version_id, prior_receipt_sha256, successor_evidence_version_id, successor_receipt_sha256, supersession_reason_code |
| `promotion.requested` | `cephas.powerops.audit-payload.promotion-requested.v1` | promotion_request_id, request_sha256, candidate_id, candidate_version, prior_active_release_state, prior_active_release_id, policy_id, policy_version, evidence_version_id |
| `promotion.approved` | `cephas.powerops.audit-payload.promotion-approved.v1` | promotion_request_id, request_sha256, approval_id, approval_role, approver_principal_id, grant_id, decision, approval_evidence_sha256 |
| `promotion.rejected` | `cephas.powerops.audit-payload.promotion-rejected.v1` | promotion_request_id, request_sha256, approval_id, approval_role, approver_principal_id, grant_id, rejection_reason_code |
| `promotion.executed` | `cephas.powerops.audit-payload.promotion-executed.v1` | promotion_request_id, request_sha256, release_id, release_transition_sha256, candidate_id, candidate_version, prior_active_release_id, evidence_version_id, policy_sha256 |
| `rollback.requested` | `cephas.powerops.audit-payload.rollback-requested.v1` | rollback_request_id, request_sha256, source_active_release_id, source_active_transition_sha256, target_release_id, target_release_transition_sha256, rollback_policy_sha256, reason_code, reason_sha256 |
| `rollback.approved` | `cephas.powerops.audit-payload.rollback-approved.v1` | rollback_request_id, request_sha256, approval_id, approval_role, approver_principal_id, grant_id, decision, approval_evidence_sha256 |
| `rollback.rejected` | `cephas.powerops.audit-payload.rollback-rejected.v1` | rollback_request_id, request_sha256, approval_id, approval_role, approver_principal_id, grant_id, rejection_reason_code |
| `rollback.executed` | `cephas.powerops.audit-payload.rollback-executed.v1` | rollback_request_id, request_sha256, source_active_release_id, target_release_id, target_release_transition_sha256, resulting_active_release_id, resulting_transition_sha256 |
| `incident.opened` | `cephas.powerops.audit-payload.incident-opened.v1` | incident_id, incident_type, severity_code, opened_by_principal_id, affected_verifier_identity_ids, affected_key_ids, affected_evidence_ids, exposure_start_state |
| `incident.dispositioned` | `cephas.powerops.audit-payload.incident-dispositioned.v1` | incident_id, disposition_code, disposition_record_sha256, incident_commander_principal_id, independent_reviewer_principal_id, affected_release_ids |
| `migration.transitioned` | `cephas.powerops.audit-payload.migration-transitioned.v1` | migration_id, migration_contract_version, prior_state, new_state, state_version, source_schema_version, target_schema_version, checkpoint_sha256, active_release_snapshot_sha256 |
| `audit.version_transition` | `cephas.powerops.audit-payload.audit-version-transition.v1` | transition_id, prior_audit_schema_version, prior_hash_algorithm, prior_last_sequence, prior_head_digest, prior_verification_report_sha256, new_audit_schema_version, new_hash_algorithm, new_genesis_or_continuation_rule, external_anchor_reference |

This registry is the minimum required event set for this gate. If an implementation emits another authority-affecting event, it must first define a new registry version with its exact payload schema and fixtures; silently emitting an unregistered event is prohibited. Fields whose values are arrays must use canonical UUID ordering, contain no duplicates, and have explicit maximum lengths. Empty arrays are permitted only where the schema semantics define “none”; otherwise the event is rejected.

#### D-05.3 Payload relationships and atomicity

Each event payload must reference the exact governed database row and immutable request/evidence digest that caused it. The database must validate tenant/business-unit relationships between event scope and every referenced record. A payload must not assert a different actor, candidate, release, risk-acceptance version, evidence version or request digest than the locked source rows.

For an authority mutation, the business state, immutable transition record, audit canonical bytes, event digest and chain-head update commit in one transaction. A failed append or schema validation aborts the authority mutation. The event actor and timestamp are database-derived. An event must not be emitted for an aborted state transition.

#### D-05.4 Required registry fixtures

Publish normative positive and negative fixtures for every event type. At minimum, two independently implemented validators must agree on schema acceptance/rejection and produce identical canonical bytes/digests. Negative fixtures must include unknown event type, unknown payload token, extra/missing property, null in a non-null field, malformed identifier/digest, duplicate or unsorted UUID array, cross-tenant reference, wrong request digest, wrong actor, wrong prior state and payload/state mismatch.

---

### D-06 — Historical audit-chain transition and external immutable-anchor handoff

#### D-06.1 Historical verification report

Before a historical chain transitions to audit v1, an independent verifier must produce a signed, immutable verification report containing exactly:

- verification_report_schema_version;
- source customer/deployment/tenant/business-unit scope;
- historical audit schema/hash algorithm/canonicalization versions;
- first and last sequence numbers verified;
- event count;
- exact last historical head digest;
- digest of the complete ordered event-digest manifest;
- verification software identity/version and build digest;
- verifier principal/issuer/subject and signing-key ID;
- verification timestamp;
- result and enumerated warnings/exceptions;
- immutable source snapshot/backup reference and digest;
- external anchor reference, if one exists, including provider/object/version/retention-lock evidence.

The report itself is canonicalized under a separately versioned report schema and signed by an independent audit-verification authority whose credentials are not held by the database administrator, verifier service or application runtime. If no prior external anchor exists, the report must state `anchor_status=not_previously_anchored`; it must not imply that a database-presented head is independently trustworthy. The customer must explicitly accept the historical chain's provenance limitation before treating it as a trusted transition source.

#### D-06.2 Exact transition event

The first transition event must use the D-05 `audit.version_transition` schema and bind:

- old schema version, canonicalization version and hash algorithm;
- old first/last sequence and exact old head digest;
- historical event count and ordered event-digest-manifest digest;
- signed verification-report digest and signer identity/key ID;
- immutable source snapshot/backup digest;
- old external anchor reference and anchor status;
- new audit schema/hash/canonicalization versions;
- explicit continuation rule: new chain sequence starts at 1 for its new versioned chain, and its genesis/transition event carries the prior chain head and verification-report digest as payload references;
- new external anchor reference for the transition event after it is committed.

The transition event is itself hashed using the new audit-v1 rules. The prior historical chain is never rewritten or rehashed under v1. Independent verifiers must verify the historical chain with its original algorithm, verify the signed transition report, validate the transition event's exact references, then verify the new chain from its defined genesis. A database-only reference to an old digest is not proof that the old digest was externally anchored.

#### D-06.3 External immutable/WORM anchor is a separate acceptance gate

The external anchor must be customer-controlled and administratively separate from the PowerOps database and application identities. The anchor contract must define:

- storage provider/service and customer ownership;
- immutable object format and exact bytes/digest;
- append-only or compliance-mode retention lock;
- retention duration and legal-hold semantics;
- writer identity and least-privilege append capability;
- independent reader/verifier identity;
- separation of duties for retention-policy changes and deletion;
- timestamping and object-version identifiers;
- periodic anchor cadence and maximum unanchored event window;
- acknowledgement, retry, duplicate/idempotency and outage behavior;
- monitoring/alerting for missed anchors or retention-policy changes;
- backup, export and recovery procedure;
- evidence that a database administrator cannot alter or delete the external copy.

The source database transaction must not claim that an external anchor has committed merely because an outbox row was written. An asynchronous anchor worker must persist a distinct acknowledgement containing anchor object ID/version, exact event range, digest, provider timestamp and verification result. An outage leaves events marked pending/unanchored and raises an operational alert; it does not permit deletion or mutation of source events. Promotion/approval availability during an anchor outage must follow a customer-approved bounded-outage policy; absent such policy, fail closed once the configured maximum unanchored window is reached.

#### D-06.4 Required acceptance tests

Build a fixture containing historical events, a signed historical verification report, the version-transition event, new audit-v1 events and an external anchor receipt. Two independent verifiers must validate the entire sequence. Tamper independently with the old head, historical manifest, verification report, signer key, source snapshot reference, transition payload, new chain event and anchor receipt; verification must fail at the corresponding boundary.

Demonstrate that a database administrator with full database privileges cannot modify or delete the externally anchored object or its retention settings. Test anchor outage, retry, duplicate acknowledgement, delayed acknowledgement, restore from backup and independent recovery of the anchored event range. Do not claim WORM compliance or close F-05 until these tests and customer acceptance pass.

---

### Consolidated closure matrix and required evidence

| Finding | Contract addition now specified | Evidence required before closure |
| --- | --- | --- |
| D-01 High | Versioned exhaustive privilege matrix, role classes, object inventory, effective-privilege comparison, partition/default privilege/ownership closure | Machine-readable matrix; catalog-derived report; real login adversarial tests; fresh-cluster restore repetition; independent review |
| D-02 High | One scope mutex and deterministic lock order for every trust/eligibility mutation; explicit linearization and winner semantics | Concurrent independent PostgreSQL sessions for every mutation pair; expiry, rollback, deadlock and retry tests |
| D-03 Medium | Immutable versioned risk acceptance; role-holder validation; serialized revocation/expiry/supersession | Both-order race tests for registration/promotion and all risk/role changes; exact database-time boundary tests |
| D-04 Medium | Complete closed rollback v1 envelope, canonical bytes and distinct domain-separated digest | Two independent serializers; per-field mutation tests; cross-operation approval rejection |
| D-05 Medium | Complete event-type/payload registry for this gate | Positive/negative fixtures for every event; two independent validators; atomicity tests |
| D-06 Medium | Signed historical verification report, exact transition event and separate customer-controlled WORM contract | End-to-end historical-to-v1 verification; tamper tests; external retention/access/recovery tests |

All six findings remain **OPEN pending independent reassessment**. The additions specify the contract; they do not constitute closure evidence.

### Explicit governance and authorization status

- Parent commit `de5e10dd23e643d4658fdbd9d25f64ffb95a1018` remains an immutable review record.
- Earlier baselines `428abadf5ed612408cfd82ac9c835d6769dcd95e` and `8442032703642e780ffdfd7fd348849640f35d04` remain preserved and unchanged.
- This amendment is documentation-only. No PostgreSQL implementation, migration, serializer, WORM integration, customer acceptance or adversarial test is claimed.
- **Implementation authorization: NOT GRANTED.**
- PR #20 remains Draft, open and unmerged.
- Synthetic-data-first, customer-hosted/customer-controlled and advisory-only boundaries remain unchanged. Model promotion remains registry governance only. No live IBEDC telemetry, SCADA/ADMS/DMS control, switching, dispatch, meter commands, billing adjustments, refunds, journal postings or automatic production model deployment is authorized.


---

## D-07 through D-10 — Required design-contract amendment

This section supplements, and where explicitly stated supersedes, the earlier D-02, D-04, D-05 and D-06 wording. It is additive to the reviewed history. No prior baseline or finding record is rewritten. If any earlier lock-order or event-field statement conflicts with this section, this section is normative for the next design version.

### D-07 — Principal/login identity-to-scope resolution and serialization

#### D-07.1 Canonical identity mapping

The authenticated database login is not itself an authorization principal. Authorization must resolve the authenticated session identity to exactly one active, issuer-qualified canonical principal and exactly one tenant/business-unit scope using a protected identity-mapping record.

The mapping key is the complete authenticated identity tuple defined by the authentication boundary: database-authenticated login identity plus issuer and immutable subject identifier where federated identity is used. Display names, email addresses, caller-supplied tenant IDs, request-body principal IDs and mutable aliases are never authoritative lookup keys. The mapping record must contain a stable mapping ID/version, canonical principal ID, issuer, subject, database login binding, tenant ID, business-unit ID, status, effective interval and audit provenance.

A login with zero mappings, multiple active mappings, an expired mapping, a disabled login, an ambiguous issuer/subject pair, or a mapping whose scope is inconsistent with the protected principal record fails closed. No fallback to a caller-provided scope or a default tenant is permitted.

#### D-07.2 Mapping-row lock before scope mutex

The identity mapping is the bootstrap authority needed to determine which scope mutex applies. Therefore the universal transaction lock order is amended as follows:

1. Resolve the authenticated login to its unique protected mapping key without trusting caller-supplied identity or scope fields.
2. Lock the exact identity-mapping row using a transaction-scoped row lock. Authorization transactions take a shared lock; mapping lifecycle transactions take an exclusive lock. The mapping lookup must use a unique constraint over the complete canonical mapping key.
3. While retaining the mapping-row lock, read the currently active mapping and derive the authoritative tenant/business-unit scope.
4. Acquire that scope's mutex.
5. Re-read and revalidate the mapping, principal, issuer/subject binding, login status, scope, effective interval and mapping version in a new SQL statement after the scope mutex is held.
6. Continue with the D-02 lock order only if the re-read values are identical to the locked mapping version and still valid. Any mismatch aborts the complete transaction; the caller must retry from identity resolution.

The mapping-row lock is intentionally acquired before the scope mutex because the scope cannot safely be selected until the authenticated mapping is locked. This is a narrowly defined bootstrap prefix to the D-02 scope protocol, not an exception allowing stale identity resolution. Every path that changes an identity mapping must take the same mapping-row lock first, then the affected scope mutex or mutexes, then the remaining D-02 locks in their normative order.

No code path may acquire a scope mutex and subsequently attempt to acquire an identity-mapping row lock. This prevents inversion between authorization and identity lifecycle operations.

#### D-07.3 Mapping lifecycle and cross-scope reassignment

The common serialized mutation inventory explicitly includes:

- login-to-principal mapping creation, activation, disablement and revocation;
- issuer/subject remapping and issuer trust changes that alter the identity binding;
- principal remapping and canonical-principal replacement;
- alias creation, consolidation, retirement and reassignment;
- login disablement, reassignment or re-enablement;
- tenant/business-unit scope assignment, removal or reassignment;
- identity proofing and mapping-status changes that affect authorization eligibility.

A mutation that changes scope must lock the mapping row exclusively, then acquire both old and new scope mutexes in ascending canonical byte order of the immutable scope key (tenant UUID followed by business-unit UUID). Duplicate scope keys are acquired once. It then locks affected principal/accountable-role/grant rows and remaining objects in the D-02 order. If either scope cannot be resolved or locked, the mutation aborts. No partial cross-scope reassignment is permitted.

For a newly created mapping with no prior scope, the transaction locks the mapping row and then the new scope mutex. For disablement without reassignment, it locks the mapping row and its current scope mutex. Alias consolidation affecting multiple mapping rows locks mapping rows in ascending immutable mapping UUID order before acquiring the union of old/new scope mutexes in ascending scope-key order. Every transaction must follow this ordering; implementations must not introduce a second lock order.

#### D-07.4 Fixed PostgreSQL isolation contract

The required isolation level for this gate is PostgreSQL READ COMMITTED. SERIALIZABLE is not an alternative mode for the authorization protocol in this gate. The contract relies on explicit row locks and fresh-statement re-reads, not on an implementation-dependent assumption about snapshot refresh.

After acquiring each required lock, the transaction must issue a new SQL statement that re-reads every authorization-relevant row whose value may have changed while waiting. The final eligibility query must execute after all locks in the applicable lock map are held. It must derive identity, scope, grants, accountable roles, risk acceptance, verifier/publisher trust, evidence, candidate, request, approvals, policy and active-release state from protected database rows. Values previously read before waiting for a lock must not be reused as authorization inputs.

All state-changing functions must reject transaction isolation levels other than READ COMMITTED. The check must occur within the protected function before any state mutation. Applications must not silently retry only the final statement: a serialization, deadlock, lock-timeout or mapping-version mismatch retry restarts the complete transaction from authenticated identity resolution. A retry must obtain a fresh mapping lock and repeat all scope derivation and eligibility checks.

The authorization linearization point remains the final database-derived eligibility evaluation after all required locks and re-reads have completed, immediately before the atomic state transition. Mapping validity must be true at that point. A mapping mutation that commits first causes the waiting authorization operation to re-read and fail or resolve under a newly initiated transaction; an authorization operation that reaches its linearization point first completes under the mapping version it locked, after which the mapping mutation proceeds and records its effect.

#### D-07.5 Required lock map and adversarial fixtures

The normative lock map must include the identity-mapping row as the first protected row, followed by one or two scope mutexes, then the D-02 ordered rows. The implementation must publish a machine-readable lock-map version and assert the same order in every stored procedure and mutation path.

Independent-session tests must cover both orderings for: login disablement versus approval; principal remapping versus promotion; issuer/subject remapping versus approval; alias consolidation versus promotion; tenant/business-unit reassignment versus approval and promotion; mapping creation versus attempted use; duplicate/ambiguous mapping insertion; and two-scope reassignment racing with operations in each scope. Tests must assert the exact winner, mapping version used, scope mutexes acquired, committed audit events, and absence of partial state. Include deadlock detection, lock timeout, transaction rollback and full-transaction retry. No authorization may proceed using a mapping or scope invalidated before its linearization point.

### D-08 — Rollback request v1 target-evidence completeness

#### D-08.1 Mandatory target evidence digests

The closed rollback request schema is amended to include these mandatory, non-null fields:

- target_dataset_snapshot_sha256;
- target_provenance_sha256;
- target_assessment_sha256.

Each is a lowercase 64-character SHA-256 digest of the exact immutable target evidence object used to establish target release eligibility. These fields are separate from target artifact and manifest digests and must not be inferred from an evidence-version ID, attestation ID, receipt digest or opaque reference.

The rollback request v1 envelope must bind all three values directly in its canonical field set. If the implementation uses a nested target-evidence envelope, that nested object must itself be closed and versioned, and the rollback envelope must include its digest as well as the three mandatory digests above. The nested form does not replace or weaken the explicit fields.

#### D-08.2 Creation, approval and execution checks

At request creation, the service must load the immutable target evidence record from the database, independently recompute or verify the three digests against the stored canonical evidence bytes, and populate the request fields from those protected records. Caller-supplied digest values are assertions only and must exactly match the database-derived values; they are never accepted as the source of truth.

Every approval must bind the complete rollback request digest, which includes the three target evidence digests. At execution, after all D-02/D-07 locks are held, the service must reload the same immutable target evidence version, verify its tenant/business-unit scope and recompute all three digests. Each must equal the values in the approved request. Any mismatch, missing evidence, superseded/quarantined evidence, invalid attestation or changed target transition aborts execution and invalidates the approval set for that request. A corrected target requires a new request ID, new canonical request bytes and new approvals.

#### D-08.3 Canonical fixtures

Publish independent serializer fixtures containing all three digests. For each field, mutate one digest after request creation and separately after approval; execution must fail. Also test omitted, null, malformed, wrong-scope, stale-version and evidence-reference substitution cases. Two independent serializers must produce byte-identical RFC 8785 canonical bytes and identical domain-separated SHA-256 request digests. Promotion and rollback request types remain non-interchangeable.

### D-09 — Complete audit registry for authority lifecycle mutations

#### D-09.1 Additional required event types

The D-05 registry is extended with these closed event types and schema tokens:

| Event type | Payload schema token | Mandatory closed payload fields |
| --- | --- | --- |
| approval_grant.created | cephas.powerops.audit-payload.approval-grant-created.v1 | grant_id, grant_version, scope_tenant_id, scope_business_unit_id, principal_id, issuer, subject, role_code, granted_by_principal_id, effective_at, expires_at, grant_record_sha256, reason_code |
| approval_grant.changed | cephas.powerops.audit-payload.approval-grant-changed.v1 | grant_id, grant_version, scope_tenant_id, scope_business_unit_id, principal_id, issuer, subject, role_code, prior_status, new_status, prior_expires_at, new_expires_at, changed_by_principal_id, effective_at, reason_code, grant_record_sha256 |
| identity_mapping.created | cephas.powerops.audit-payload.identity-mapping-created.v1 | mapping_id, mapping_version, database_login_binding, issuer, subject, principal_id, scope_tenant_id, scope_business_unit_id, status, effective_at, mapping_record_sha256, actor_principal_id, reason_code |
| identity_mapping.changed | cephas.powerops.audit-payload.identity-mapping-changed.v1 | mapping_id, prior_mapping_version, new_mapping_version, database_login_binding, issuer, subject, prior_principal_id, new_principal_id, prior_scope_tenant_id, prior_scope_business_unit_id, new_scope_tenant_id, new_scope_business_unit_id, prior_status, new_status, effective_at, mapping_record_sha256, actor_principal_id, reason_code |
| request.invalidated | cephas.powerops.audit-payload.request-invalidated.v1 | request_id, operation_type, request_sha256, prior_status, new_status, invalidation_reason_code, invalidating_object_type, invalidating_object_id, invalidating_object_version, actor_principal_id, effective_at |

The approval-grant events cover creation, activation, expiry, suspension, revocation, role change and replacement. The identity-mapping events cover creation, activation, disablement, issuer/subject remapping, principal remapping, alias consolidation/reassignment, login disablement/reassignment and scope reassignment. The event payload must preserve prior and new state and identify all affected scope keys. For multi-scope changes, the event is written in each affected scope's audit chain under the cross-scope atomicity rule below, with one globally unique mutation ID linking the records.

#### D-09.2 Expiry and durable request invalidation semantics

Grant expiry is an eligibility fact determined from database time during every authorization check; passage of time alone does not require a background mutation or an expiry event. If a worker or administrator persists an explicit grant status transition to expired, that committed status transition emits exactly one approval_grant.changed event. Expiry must not be represented as an unrecorded manual edit.

A request is not automatically mutated merely because an eligibility predicate becomes false. If the system persists a request status transition such as stale, invalidated, quarantined or superseded, it must emit exactly one request.invalidated event in the same transaction, binding the original request digest and the exact invalidating object/version. If no durable request-state transition is made, the request remains immutable and execution is rejected by re-evaluating current eligibility; no request.invalidated event is emitted. This distinction prevents invented lifecycle events and duplicate invalidations.

#### D-09.3 Complete mutation-to-event coverage and atomicity

Every mutation enumerated in D-02.1 and D-07.3 must map to exactly one registered event schema or to an explicitly documented, bounded event combination. The implementation must publish a machine-readable mutation-to-event coverage matrix. An unregistered mutation, missing event, duplicate event, wrong-scope event or event whose prior/new state differs from the authoritative transition causes the transaction to fail.

For a cross-scope identity mutation, all affected scope-chain events, the immutable mapping transition record and the mapping state change must commit atomically in one PostgreSQL transaction. The global mutation ID and canonical payload digest must be identical across the affected scope events; each event has its own scope-bound chain sequence and digest. If the database design cannot guarantee atomic append to all affected scope chains, cross-scope mapping mutation must fail closed; an asynchronous best-effort audit is prohibited.

Approval grant and identity mapping event actors must be database-derived from the authenticated, currently valid actor mapping and must not be caller-selected. The event must carry prior/new values from locked rows, the exact reason code and database timestamp. A failed event append aborts the corresponding authority mutation.

#### D-09.4 Required registry and coverage fixtures

Fixtures must cover every D-02.1 and D-07.3 mutation, each approval-grant state transition, each identity-mapping transition, and both persisted and non-persisted stale-request cases. Positive and negative tests must demonstrate that: a committed mutation has its required event; an aborted mutation has no event; no mutation emits an unregistered event; no event is committed without its matching mutation; multi-scope changes have all scope events or none; and duplicate event insertion is rejected by uniqueness constraints.

### D-10 — Non-circular audit transition and external-anchor acknowledgement

#### D-10.1 Pre-commit anchor contract identity

The D-05 audit.version_transition payload must not contain an object-version ID, acknowledgement ID, provider receipt or other value that is created only after the transition event has been committed and submitted to external storage.

Before constructing the transition event, the customer must provision and approve an immutable anchor contract identified by a stable anchor_contract_id and anchor_stream_id. The transition event binds only these pre-existing identifiers, the contract version/digest, the customer-controlled destination identity, the required retention mode, the expected writer/reader identities, the canonicalization/hash versions and the maximum unanchored window. These values must be known and immutable before the event is hashed.

The transition event also binds the historical verification report digest, old chain head and manifest digest, source snapshot digest, new chain version and continuation rule as already required. The event's canonical bytes and digest are finalized before the database transaction commits. They are never amended after external submission.

#### D-10.2 Transactional outbox and post-commit acknowledgement

The database transaction that appends the transition event must atomically write: the immutable transition event; the new audit chain head; and an outbox record containing the exact canonical event bytes, event digest, scope, sequence, anchor_contract_id, anchor_stream_id and idempotency key. The outbox record does not claim successful anchoring.

After commit, the anchor worker submits those exact bytes to the pre-approved external anchor destination. The external service returns an acknowledgement. The worker validates that the acknowledgement identifies the expected anchor contract/stream, exact event digest and byte length, sequence/range, provider object/version, provider timestamp and retention-lock evidence. It must reject an acknowledgement for different bytes, a different scope or a different stream.

The acknowledgement is stored as a separate immutable audit-anchor-acknowledgement.v1 record, with its own canonical bytes and digest. It includes the transition event digest, anchor contract/stream IDs and version, provider/object/version ID, exact event range, submitted-byte digest and length, provider acknowledgement timestamp, retention mode/status, provider receipt digest, verification result, worker identity and signer identity/key. It is never inserted retroactively into the already-hashed transition event or used to rewrite its payload.

The acknowledgement record is itself exported to the independently retained anchor evidence location, or to a separately configured acknowledgement stream under the same customer-controlled anchor contract. The export of the acknowledgement is recorded by a subsequent immutable acknowledgement-of-acknowledgement record or independently verifiable provider receipt. The system must document the trust boundary for this final receipt and must not claim that a database-only acknowledgement record is independently retained.

#### D-10.3 State model and recovery

Anchor state is derived from immutable records and has the closed states pending, submitted, acknowledged, verified, failed and quarantined. State transitions are append-only records; no acknowledgement or failure record is overwritten. Duplicate submissions use the same idempotency key and exact bytes. A duplicate provider acknowledgement is accepted only if every bound field matches the original; conflicting acknowledgements quarantine the stream and raise an incident.

If the external service is unavailable, the outbox remains pending or failed with bounded retry metadata. The transition event and database chain remain immutable. The configured maximum unanchored window is enforced according to the customer-approved outage policy; absent an approved policy, the service fails closed for governed promotion/approval once the limit is reached. Recovery resumes from the exact outbox bytes and verifies the resulting provider receipt. A restore must reconcile database outbox records, externally retained event objects and acknowledgement records without rewriting any chain event.

#### D-10.4 Required end-to-end fixture

The independent fixture must execute this exact order:

1. Verify the historical chain under its original algorithm and canonicalization.
2. Produce and sign the historical verification report.
3. Confirm the pre-provisioned anchor contract and stream identity.
4. Construct and hash the transition event using only pre-existing anchor contract/stream identifiers.
5. Atomically commit the transition event, new chain head and exact-byte outbox record.
6. Submit the exact committed bytes using the stable idempotency key.
7. Receive and validate the external provider acknowledgement.
8. Persist the acknowledgement as a separate immutable record without changing the transition event.
9. Independently export/anchor the acknowledgement record and verify its provider receipt.
10. Have two independent verifiers validate the historical report, transition event, outbox bytes, provider object, acknowledgement record and acknowledgement-retention receipt as one linked sequence.

Tampering with any event byte, digest, stream ID, object version, acknowledgement field, signer, receipt or retention evidence must be detected. Test delayed, duplicate, conflicting and missing acknowledgements; outage and recovery; and database restore. No WORM or F-05 closure claim is permitted until customer acceptance and independent end-to-end evidence exist.

### Updated closure matrix for D-07 through D-10

| Finding | Normative contract addition | Evidence required before closure |
| --- | --- | --- |
| D-07 High | Mapping-row bootstrap lock, scope derivation/revalidation, deterministic two-scope locking, READ COMMITTED only, fresh post-lock re-reads | Machine-readable lock map; two-session mapping/approval/promotion races; disablement/remapping/reassignment tests; deadlock/retry evidence |
| D-08 Medium | Explicit target dataset, provenance and assessment digests in rollback v1; creation/approval/execution recomputation | Two independent serializers; per-field mutation-after-approval tests; wrong-scope and stale-evidence rejection |
| D-09 Medium | Approval-grant and identity-mapping event schemas; explicit persisted/non-persisted request invalidation semantics; complete mutation-to-event matrix | Fixtures for every D-02.1/D-07.3 mutation; atomic multi-scope event tests; aborted-transaction and duplicate-event tests |
| D-10 Medium | Pre-existing anchor contract/stream in transition event; exact-byte outbox; separate immutable post-commit acknowledgement and independent retention receipt | End-to-end two-verifier fixture; outage, retry, duplicate/conflict, restore and tamper tests; customer WORM acceptance |

### Supersession and governance status

This amendment resolves the four identified design ambiguities at the specification level only. It does not close D-07 through D-10, earlier F/N findings, or any implementation acceptance criterion. D-01 and D-03 remain design-contract resolved only, subject to implementation evidence and independent acceptance. All other findings remain open until their stated evidence is delivered and independently reviewed.

This is documentation-only. No database schema, PostgreSQL function, migration, identity service, serializer, audit registry implementation, outbox worker, external anchor integration, customer risk acceptance or adversarial test implementation is claimed. Implementation authorization remains NOT GRANTED. PR #20 must remain Draft, open and unmerged. Product and operational boundaries remain unchanged.


---

### Independent reassessment amendment — D-07.1 through D-10.2

#### Status and scope

This is an additive, documentation-only amendment responding to independent reassessment of commit `3fb64cf277eab3d6ed333bc13a2f95aca138caf8`. It specifies the four outstanding conditions below. It does not claim implementation, test execution, customer acceptance, WORM compliance, production readiness or implementation authorization. It does not supersede earlier requirements except where it explicitly makes a previously ambiguous requirement more precise. In any conflict, the stricter fail-closed requirement applies pending independent resolution.

### D-07.1 — Database-login disablement and existing-session invalidation

##### Distinct security objects

The implementation must distinguish and independently track:

1. PostgreSQL role login capability (`pg_roles.rolcanlogin`);
2. the protected identity-mapping record and its enabled/disabled state;
3. the authenticated database session, identified from server-derived `SESSION_USER`, `pg_backend_pid()` and `pg_stat_activity.backend_start`;
4. a monotonically increasing protected authentication/session epoch for the login binding and mapping; and
5. any upstream federated credential state, where federated authentication is used.

A PostgreSQL `ALTER ROLE ... NOLOGIN` prevents new logins; it does not, by itself, invalidate sessions already authenticated. It must never be treated as sufficient revocation of existing sessions.

##### Authoritative disablement protocol

All application identity disablement and credential retirement must use a separately governed customer-administration procedure. The procedure must:

- acquire the identity-mapping row's exclusive lock first, then its current scope mutex and remaining D-02 locks;
- increment the protected login-binding/session epoch and mapping version;
- persist the mapping/credential disabled state, reason, actor and database timestamp;
- append the required D-09 lifecycle audit event in the same transaction;
- commit the protected disabled state and epoch as the authorization revocation linearization point;
- request PostgreSQL role `NOLOGIN` and terminate matching existing sessions using a separately controlled administrative capability; and
- record the result of role disablement and session termination as linked administrative outcome evidence.

Where PostgreSQL role alteration or session termination cannot participate in the same transaction as the protected mapping mutation, the protected mapping state and epoch remain authoritative for governed operations. The administrative procedure must retry and reconcile the external PostgreSQL actions. It must not report the login-disablement workflow complete until role state and session inventory have been reconciled. A failed or delayed termination does not restore authorization.

Every governed SECURITY DEFINER function must, at its final authorization check, derive the current database login from `SESSION_USER`, derive the current backend identity from PostgreSQL, resolve the protected mapping, and compare the session's registered epoch with the current protected login-binding and mapping epochs. The session registration must be server-bound to the actual login, backend PID and backend start time; callers must not be able to supply or change these values as authority. A missing, stale, ambiguous, disabled or mismatched session registration fails closed.

The epoch check is mandatory on every privileged operation, not only at connection establishment. A connection authenticated before disablement may remain open for non-privileged diagnostic or cleanup activity if customer policy permits, but it cannot invoke approval, evidence registration, promotion, rollback, grant mutation, mapping mutation or other governed authority after the disablement transaction commits. Connection termination is defence-in-depth; epoch and mapping validation are the authorization control.

For federated credentials, upstream revocation alone is not considered visible to an existing database session. The customer-controlled credential lifecycle must publish the revocation into protected database state and increment the same epoch. Until that state is committed, the system cannot claim that the database has observed upstream revocation.

##### Required race outcomes

- If disablement commits before the privileged operation reaches its final authorization linearization point, the operation must fail.
- If the privileged operation reaches its linearization point first while holding the required locks, it may complete under the still-valid epoch; disablement then proceeds and is audited afterward.
- A role changed to `NOLOGIN` while an old session remains connected must not allow that session to perform a governed operation after the protected epoch changes.
- Session PID reuse must not match an old registration; backend start time is part of the binding.
- Re-enablement requires a new authorized lifecycle transition and a new epoch. It must not restore old session registrations or stale grants automatically.

##### Closure fixtures

Provide PostgreSQL 16 tests using two or more real database sessions for both lock orderings of disablement versus approval/promotion; `NOLOGIN` with an already-authenticated session; delayed `pg_terminate_backend`; failed termination; stale and missing session registration; PID reuse/backend-start mismatch; mapping-only disablement; federated credential revocation propagation; epoch increment; re-enablement; and audit failure. Demonstrate that no pre-existing session can authorize after the committed revocation linearization point. Capture database role state, session inventory, mapping version, epoch, transaction outcome and audit chain evidence.

### D-08.1 — Canonical target-evidence object and digest preimage contract

##### Exact evidence objects

Rollback request v1 must bind the immutable identity and version of each target evidence object in addition to the three mandatory digest fields already specified:

- dataset snapshot object ID, immutable object version and `target_dataset_snapshot_sha256`;
- provenance object ID, immutable object version and `target_provenance_sha256`; and
- assessment object ID, immutable object version and `target_assessment_sha256`.

The identifiers and versions are protected database-derived values. Caller-supplied identifiers or digests are assertions only. All objects must be tenant/business-unit scoped, immutable, retrievable and non-quarantined at request creation, approval and execution.

##### Normative digest preimages

The digest field names in rollback request v1 have the following exact meanings:

1. `target_dataset_snapshot_sha256` is lowercase hexadecimal SHA-256 of the exact raw dataset snapshot bytes retrieved from the immutable, content-addressed object version. No text decoding, newline conversion, compression transformation, row reordering or reserialization is permitted before hashing. If the stored object is a defined compressed artifact, the digest covers the exact stored object bytes; any logical/uncompressed dataset digest is a separate explicitly named field and cannot substitute for this digest.
2. `target_provenance_sha256` is lowercase hexadecimal SHA-256 of the exact UTF-8 bytes of the complete canonical provenance object. The object schema is closed and versioned as `cephas.powerops.target-provenance.v1`; canonicalization is RFC 8785. It includes immutable provenance object ID/version, tenant and business-unit UUIDs, source snapshot digest, lineage edges in deterministic order, transformation identifiers/versions, preparation code/build digest, creation timestamp and applicable source references. Unknown fields, duplicate JSON keys, invalid Unicode, non-canonical bytes and missing required fields are rejected.
3. `target_assessment_sha256` is lowercase hexadecimal SHA-256 of the exact UTF-8 bytes of the complete canonical assessment object. The object schema is closed and versioned as `cephas.powerops.target-assessment.v1`; canonicalization is RFC 8785. It includes immutable assessment ID/version, tenant and business-unit UUIDs, candidate/model version, dataset snapshot digest, provenance digest, policy ID/version/digest, assessor identity and implementation version, result, reason codes and assessment timestamp. Unknown fields, duplicate JSON keys, invalid Unicode, non-canonical bytes and missing required fields are rejected.

For all three fields the digest is exactly `SHA-256(preimage_bytes)`; no implicit prefix, suffix, JSON wrapper or transport encoding is added. Domain separation and object typing are supplied by the closed object schema/version and the request's explicit object type, ID and version. Any future change to these preimage rules requires a new evidence schema version and new request schema version; version 1 must never be reinterpreted.

The canonical provenance and assessment objects must be persisted as the exact canonical UTF-8 bytes that were hashed. The dataset snapshot must be persisted as the exact immutable bytes that were hashed. Parsed database projections are not digest preimages. The service must reject a mismatch between stored bytes, object metadata and the digest. Hashes must be computed over byte arrays, not language-native object serialization.

##### Creation, approval and execution binding

At creation, the database-backed service retrieves each exact immutable object version, hashes its exact preimage, validates scope and schema, and writes the three values and corresponding object IDs/versions into the closed rollback request envelope. At approval, the approver's digest binding covers the entire canonical request, including all evidence IDs, versions and digest fields. At execution, the service retrieves the same exact versions again, recomputes all three digests and compares them with the approved request. Object replacement, version drift, byte mutation, missing object, non-canonical provenance/assessment bytes, wrong scope or quarantine causes fail-closed rejection and approval invalidation under D-09.

Two independently implemented serializers/verifiers must use the published byte fixtures and produce identical canonical provenance/assessment bytes and identical three SHA-256 values. Fixtures must include empty and non-ASCII values where schema permits, Unicode normalization edge cases, duplicate keys, reordered properties, altered whitespace, altered dataset bytes, changed lineage order, changed policy version, changed object version and wrong-scope substitution. Reordering JSON object properties must canonicalize identically; changing any semantic value or dataset byte must change the digest.

### D-09.1 — Closed cross-scope mutation linkage and reconstruction

##### Mutation identity

The existing top-level audit `operation_id` continues to identify the governed request/operation and must not be overloaded as the cross-scope mutation identifier. Every authority-lifecycle mutation must additionally carry a distinct, globally unique lowercase canonical UUID `mutation_id`. The mutation ID is generated by the trusted database function, not supplied by the caller, and is stable across all audit events emitted by one atomic mutation.

Every applicable D-09 payload schema is versioned additively to require these common fields:

- `mutation_id`: canonical UUID, identical in every event emitted by the mutation;
- `mutation_schema_version`: exact registered token `cephas.powerops.mutation.v1`;
- `mutation_payload_sha256`: lowercase SHA-256 digest of the canonical mutation manifest bytes;
- `affected_mapping_ids`: array of unique canonical mapping UUIDs, sorted by ascending UUID byte order;
- `affected_scope_keys`: array of unique objects containing exactly `tenant_id` and `business_unit_id`, sorted by canonical tenant UUID bytes then business-unit UUID bytes;
- `mutation_event_index`: integer starting at zero, unique and contiguous within the mutation; and
- `mutation_event_count`: positive integer equal to the total expected number of scope-chain events for the mutation.

These fields are mandatory, including for single-scope mutations. Empty arrays are permitted only for event types whose schema explicitly defines no affected mappings or scopes; identity mapping and grant mutations must identify their affected object and scope. Unknown properties, duplicate array entries, non-canonical identifiers and inconsistent counts are rejected.

##### Canonical mutation manifest

Before any mutation is committed, the database function constructs a closed canonical mutation manifest containing the mutation ID, operation ID, mutation type, authenticated actor, exact prior and resulting object versions/digests, complete sorted affected mapping IDs, complete sorted affected scope keys, reason code and expected event types/count. The manifest uses RFC 8785 UTF-8 canonical bytes and a versioned schema. Its SHA-256 digest is the `mutation_payload_sha256` repeated in every emitted scope event.

The manifest is stored immutably with the mutation record in the same PostgreSQL transaction. Each scope-chain event contains the same mutation ID, manifest digest, affected mapping list, affected scope list and expected event count. Each event retains its own tenant/business-unit scope, sequence number, previous digest and event digest. An independent verifier must be able to group all events by mutation ID, verify the common manifest digest, verify the exact expected event set and reconstruct the complete before/after mutation without consulting mutable current-state rows.

The top-level `operation_id` binds the originating governed operation/request. It may be shared by separately identified lifecycle mutations only where the operation explicitly contains multiple separately atomic mutations; each such mutation receives its own mutation ID and manifest. A retry of the same committed mutation must return/reconcile the existing mutation record and must not create a second mutation ID or duplicate event set. Reuse of a mutation ID with different manifest bytes is rejected.

##### Actor and grant-state semantics

For `approval_grant.created`, the event's `status` is mandatory and exactly `active` or `pending` as determined by the approved activation workflow. Creation and activation are separate transitions when activation is not immediate: creation emits the created event with status pending; activation emits a changed event with prior_status pending and new_status active. A grant cannot be used until active and all current eligibility checks pass.

Every grant lifecycle event must include the immutable grant version, principal/issuer/subject binding, scope, role, effective timestamp, expiry timestamp (nullable only where the schema allows a non-expiring grant), reason code, actor principal, prior status and resulting status as applicable, and a canonical grant-record digest. Grant replacement identifies both the superseded grant and replacement grant IDs/versions in the mutation manifest.

Every identity-mapping event must include the immutable mapping IDs/versions, exact prior and resulting login binding, issuer/subject, principal and scope values, status, actor and reason code. For alias consolidation or multi-mapping reassignment, the mutation manifest enumerates every affected mapping and its exact prior/resulting state. Per-scope events repeat the common complete affected-object lists and manifest digest; they are not interpreted as independent partial mutations.

##### Atomicity and independent reconstruction

The transaction must write the immutable mutation manifest, all affected scope-chain events, chain-head updates and all mapping/grant state changes atomically. `mutation_event_count` and contiguous `mutation_event_index` values allow an independent verifier to detect a missing scope event. If any scope event or chain-head append fails, every state change and event in the mutation rolls back. Cross-scope asynchronous audit repair is prohibited.

The event registry must publish the exact revised closed schemas and mutation-to-event matrix. The matrix must enumerate every D-02.1 and D-07.3 mutation, actor class, prior/resulting state, affected mapping/scope set and expected event count. Two independent verifiers must reconstruct the same mutation manifests and history from audit bytes alone. Tests must reject missing, duplicate, reordered, wrong-scope, mismatched-manifest, inconsistent-count, unknown-event and actor-substitution cases.

### D-10.1 — External provider idempotency and conditional-create contract

An anchor provider is eligible only if the customer-approved contract supports one of these two modes:

**Mode A — Provider-enforced idempotent create.** The provider must guarantee that a stable idempotency key is bound to the exact content digest and destination stream. Repeating the same key with the same digest returns the same immutable object identity/result. Repeating the same key with different bytes/digest or a different stream returns a hard conflict and must not create or overwrite an object. The provider must expose a verifiable immutable object/version identity and exact-byte readback or an independently verifiable content digest.

**Mode B — Conditional create and reconciliation.** If native idempotency is unavailable, the provider must support atomic conditional creation under a deterministic object key with create-if-absent semantics. Before retrying after an ambiguous response, the worker performs an authenticated lookup/read of that exact key. If absent, it retries conditional create. If present, it verifies exact bytes/digest, stream, immutable object version and retention evidence and records the existing object as the result. If the key exists with different bytes, metadata, stream or retention state, the stream is quarantined and no overwrite is attempted. A provider that supports neither Mode A nor Mode B is not an acceptable anchor provider for this gate.

The idempotency key is deterministically derived from the immutable anchor contract ID, stream ID, scope key, sequence number and event digest using a versioned domain-separated SHA-256 construction. The derivation contract and test vectors must be published. The key is never reused for a different event. The worker stores every attempt as an append-only attempt record with attempt ID, key, exact digest/byte length, request timestamp, response classification and worker identity.

A success acknowledgement is valid only after the worker verifies the provider object identity, exact submitted bytes or independently verifiable digest, expected stream/scope/sequence, retention mode and immutable version. A response received after a lost earlier response is reconciled against the exact object; it is not accepted solely because the HTTP/API status indicates success. An acknowledgement for a previous event, different attempt payload or different destination is rejected. Any same-key/different-content response, duplicate object with conflicting identity or unprovable object state quarantines the stream.

### D-10.2 — Closed anchor state-transition graph and deterministic outage gate

##### Permitted state transitions

Anchor state is derived from immutable attempt, acknowledgement, verification and quarantine records. The only permitted transitions are:

| Current state | Permitted next state | Required evidence |
| --- | --- | --- |
| pending | submitted | Exact outbox bytes and digest selected; attempt record committed |
| pending | failed | A classified permanent pre-submission failure record; no provider object may have been created |
| submitted | acknowledged | Provider response reconciled to exact object, bytes/digest, stream, sequence and retention metadata |
| submitted | failed | Bounded retry policy exhausted or a classified non-retryable provider failure; reconciliation proves no conflicting accepted object |
| failed | submitted | New append-only retry attempt after reconciliation proves the original exact object is absent, or Mode A/Mode B proves safe same-event retry |
| acknowledged | verified | Independent readback/verifier confirms exact bytes, object identity, stream, sequence and retention evidence |
| any non-quarantined state | quarantined | Conflicting acknowledgement, same-key/different-content result, tampering, unverifiable object, retention downgrade or integrity failure |

No transition out of `verified` or `quarantined` is permitted. Quarantine is terminal for that stream identity. Recovery from quarantine requires a separately approved new anchor contract and stream identity, a new version-transition event and an independently verified continuity/reconciliation package; it must not clear or rewrite the quarantined history. Repeated identical acknowledgements are recorded as duplicate observations linked to the original acknowledgement and do not create a second state transition. Out-of-order or stale acknowledgements are accepted only if independently reconciled to their exact event and do not regress state.

##### Unanchored-window measurement

The unanchored window is measured per anchor stream and scope from the PostgreSQL commit timestamp recorded for the earliest committed audit event in that stream/scope that has not reached `verified`. The authoritative clock is PostgreSQL server time captured in the transaction that commits the event/outbox row; application clocks and provider timestamps are not used to start or extend the interval. The comparison time is PostgreSQL server time obtained during the governed operation's final eligibility check.

The customer-approved anchor contract must define a positive maximum duration and the applicable scope/stream. If no approved maximum exists, the default is zero tolerance: governed promotion, rollback and approval fail closed whenever any required event remains unverified. The measured age is the elapsed database-time interval between the earliest unverified event's committed timestamp and the current database time. Restores must preserve original commit timestamps and reconcile them with external objects; a restore must never reset or shorten the unanchored interval.

When the configured maximum is reached or exceeded, all new governed approvals, promotions and rollbacks in the affected scope/stream fail closed. Read-only audit inspection, evidence export, outbox retry, reconciliation and incident response remain permitted. No administrator may waive the gate by editing timestamps, deleting outbox records, changing the stream identity or increasing the maximum window retroactively. Changing the customer-approved outage policy is a separately authorized, versioned contract transition and applies prospectively only.

The gate is cleared only when every event in the affected unanchored interval is independently verified under the active anchor contract and the chain/outbox/provider reconciliation report passes. A manual override cannot mark an event verified. If provider evidence is irrecoverable or conflicting, quarantine and a new-stream continuity procedure are required.

##### Required provider and state-machine fixtures

Test both provider modes, same-key/same-bytes replay, same-key/different-bytes conflict, lost response after successful object creation, duplicate object version, object readback mismatch, stale acknowledgement, wrong stream/scope/sequence, retention downgrade, delayed provider, outage beyond threshold, database restore with pending outbox, retry after failed state, quarantine, attempted quarantine clearing, verified-state regression and prospective policy change. Two independent verifiers must validate the full state-transition history and event-to-object chain.

### Updated disposition and governance

These clauses close the four specification ambiguities identified by the independent reassessment only when independently accepted against the exact resulting commit. They do not close D-07 through D-10 at implementation level, F-03, F-05 or any other prior finding. All listed concurrency, serializer, audit, migration, provider and recovery tests remain required implementation evidence.

This amendment is documentation-only. No database roles/functions, session registry, migration, evidence serializer, mutation registry, provider adapter, outbox worker, external anchor integration or tests are implemented or claimed. Implementation authorization remains NOT GRANTED. PR #20 must remain Draft, open and unmerged. Synthetic-data-first, customer-hosted/customer-controlled and advisory-only PoV boundaries remain unchanged. No live IBEDC telemetry, operational utility control, billing or financial posting, or automatic production model deployment is authorized.
