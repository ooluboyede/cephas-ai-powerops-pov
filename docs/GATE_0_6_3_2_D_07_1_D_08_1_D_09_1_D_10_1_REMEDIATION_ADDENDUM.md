# Gate 0.6.3.2 — D-07.1 through D-10.2 Design Remediation Addendum

**Status:** Documentation-only normative amendment. This addendum supplements, and must be read together with, `GATE_0_6_3_2_DATABASE_ENFORCED_PROMOTION_AUTHORITY.md`. It does not supersede prior requirements unless an explicit conflict is identified below; in a conflict, the stricter fail-closed requirement applies pending independent resolution.

**Parent design baseline:** `3fb64cf277eab3d6ed333bc13a2f95aca138caf8`

**Authorization:** IMPLEMENTATION NOT AUTHORIZED. No database implementation, migration, identity/session service, serializer, audit writer, outbox worker, provider integration or tests are claimed.

## D-07.1 — Database login disablement and existing-session invalidation

### D-07.1.1 Distinct security objects

The design distinguishes these independently governed facts:

1. PostgreSQL login-role state, including whether the role has LOGIN.
2. Protected identity-mapping state and version.
3. Authenticated connection identity, derived from PostgreSQL-authenticated `SESSION_USER`, never a caller-supplied principal or tenant.
4. A protected login/session generation (`login_epoch`) associated with the database login binding.
5. Session/transaction eligibility at the authorization linearization point.

Changing an application mapping to disabled does not itself prove that the PostgreSQL role is NOLOGIN, and changing a role to NOLOGIN does not terminate sessions that authenticated before the change. Neither operation alone is sufficient.

### D-07.1.2 Mandatory login lifecycle control plane

All supported disable, re-enable, credential rotation and identity-binding changes must use a customer-controlled privileged login-lifecycle procedure. Direct out-of-band role changes are break-glass operations and must trigger the same reconciliation procedure before governed operations resume.

The lifecycle procedure must:

- Resolve the exact PostgreSQL role OID and immutable protected login-binding ID; role names alone are not durable identifiers.
- Acquire the protected login-binding/mapping row lock before scope mutexes, following D-07.3 global lock order.
- Increment the monotonic `login_epoch` on disablement, credential retirement, identity remapping, or other event that invalidates existing authentication context. Epochs never decrement or get reused.
- Set the protected login binding and all associated identity mappings to the required disabled/revoked state in the same database transaction as the audit mutation.
- For a disable operation, apply PostgreSQL `ALTER ROLE ... NOLOGIN` through a narrowly controlled administrative capability and verify the resulting catalog state. The implementation must not grant ordinary runtime or verifier roles CREATEROLE, role ownership, or equivalent authority.
- After commit, terminate existing sessions for the affected role using a separately authorized session-termination capability, and record the observed termination outcome. Session termination is defense in depth; authorization rejection through epoch/mapping revalidation is the primary safety control.
- Reconcile sessions that race with termination. A session established before or during disablement must fail the protected authorization check because its captured epoch is older than the current epoch or its mapping is disabled.
- On re-enable, require explicit credential rotation or approved credential revalidation, a new epoch, fresh identity mapping validation and a complete audit event. Re-enabling LOGIN alone must not revive prior sessions or grants.

The lifecycle controller must not expose a general-purpose SQL execution facility. Its authority is limited to the enumerated role lifecycle operations and the associated protected registry transitions.

### D-07.1.3 Mandatory session binding and final check

At connection authentication, the trusted database entry path binds the connection to the authenticated `SESSION_USER`, role OID, protected login-binding ID, mapping ID/version and current `login_epoch`. Any session context supplied by the application is untrusted and cannot override these values.

Every privileged operation must, under the mapping-row lock and applicable scope mutex, perform a fresh-statement read of:

- authenticated `SESSION_USER` and resolved role OID;
- protected login-binding state and current `login_epoch`;
- session-bound login-binding ID and captured epoch;
- mapping status/version, issuer, immutable subject, principal and scope;
- grant and approval eligibility.

The operation fails closed if the binding is disabled, role OID differs, mapping is ambiguous or disabled, captured epoch differs from current epoch, or any required row cannot be read. The final check occurs after all locks and immediately before the atomic state transition. A cached application claim or connection-pool metadata is never sufficient.

All governed mutation paths must be callable only through protected database functions that enforce this check. Direct table writes, alternate functions, triggers, SECURITY DEFINER helpers and inherited privileges must not provide a bypass. A session that has not performed a fresh authorization check cannot perform a governed write.

### D-07.1.4 Out-of-band role changes and failure handling

Because PostgreSQL role DDL and application mapping changes may not be part of one ordinary transaction, the customer deployment must enforce an administrative boundary:

- Only the designated lifecycle controller and documented break-glass DBA process may change LOGIN, role membership, credential validity or role ownership for protected logins.
- A periodic reconciliation detects any catalog/mapping/epoch mismatch.
- Detection of an out-of-band change immediately places the affected login binding and impacted scopes into a fail-closed quarantine state; governed promotion, approval and rollback are denied until reconciled.
- Break-glass changes require an immutable incident record, before/after catalog evidence, affected-session inventory, epoch increment, session termination, mapping reconciliation and independent verification.
- If catalog state or session inventory cannot be established, the login remains quarantined. The design makes no claim that PostgreSQL `NOLOGIN` alone invalidates already-authenticated sessions.

### D-07.1.5 Required adversarial fixtures

The implementation evidence must include independent PostgreSQL sessions and actual customer-equivalent role credentials for:

1. Disablement commits before approval starts: approval is denied.
2. Approval obtains mapping/login locks first: the disable operation waits; approval completes under the still-valid locked epoch, then disablement commits and invalidates later operations.
3. Disablement starts while an authenticated session is idle: the next privileged operation is denied after epoch change.
4. Disablement races with a connection-pool checkout and with a new connection attempt.
5. PostgreSQL role is changed to NOLOGIN while an existing session remains connected: governed operations fail after reconciliation/epoch invalidation.
6. Out-of-band NOLOGIN or role-membership change: reconciliation quarantines the binding and prevents governed operations.
7. Role OID/name reuse, credential rotation, re-enable and stale pooled connection.
8. Failure to terminate one or more sessions: authorization still fails; incomplete termination remains an operational incident.
9. Login disablement, mapping disablement and audit append failure: no partial protected mutation commits.
10. Deadlock, timeout and retry: the entire transaction restarts from authenticated identity resolution and captures the current epoch.

Assertions must include exact linearization order, old/new epoch, mapping version, session termination result, audit records and absence of unauthorized state changes.

## D-08.1 — Canonical target-evidence serialization and digest preimages

### D-08.1.1 Evidence object version 1

The three rollback target evidence digests refer to three distinct, immutable, closed evidence objects:

- Dataset snapshot evidence: `cephas.powerops.rollback-target.dataset-snapshot.v1`
- Provenance evidence: `cephas.powerops.rollback-target.provenance.v1`
- Assessment evidence: `cephas.powerops.rollback-target.assessment.v1`

Each object is a complete versioned envelope. The canonical preimage is the UTF-8 byte sequence produced by RFC 8785 JSON Canonicalization Scheme over the complete closed envelope, excluding any digest/signature field that would recursively include its own digest. UTF-8 without BOM is mandatory. No trailing newline, whitespace normalization after canonicalization, alternate number representation, duplicate JSON keys, unknown fields, or implementation-specific serialization is permitted.

The envelope must contain, at minimum:

- `schema_token` and integer `schema_version`;
- immutable evidence object UUID and immutable version UUID;
- tenant UUID and business-unit UUID;
- candidate UUID and model version;
- evidence kind;
- content payload or a closed content-addressed payload descriptor;
- source/provenance references needed to reproduce the evidence;
- producer identity and producer software/version;
- creation timestamp as a canonical UTC RFC 3339 value with fixed precision;
- applicable policy/assessor version for assessment evidence;
- supersession/quarantine status reference where relevant, without mutating the original object.

A content-addressed descriptor must bind the payload media type, exact byte length, SHA-256 of the exact payload bytes, immutable object version and customer-controlled retrieval reference. A mutable URL, filename or display label is never sufficient.

### D-08.1.2 Digest definition

For each evidence object:

`<field>_sha256 = lowercase_hex(SHA256(canonical_utf8_bytes))`

The digest is the ordinary SHA-256 of the exact canonical envelope bytes. It is not a digest of a database row rendering, a JSONB textual representation, an opaque ID, a URI, a signature, or a provider response. The schema token and version, object/version UUIDs, tenant and business-unit scope, candidate/model binding and payload descriptor are inside the canonical preimage and therefore cryptographically bound.

The exact canonical bytes and their byte length must be retained with the immutable evidence record. Implementations must not reconstruct canonical bytes from mutable JSONB or from a display projection. Database storage may index parsed fields, but the retained canonical byte sequence is the authoritative digest preimage.

The rollback request fields `target_dataset_snapshot_sha256`, `target_provenance_sha256` and `target_assessment_sha256` must equal the corresponding recomputed evidence-object digests. These are three independent fields; a composite evidence digest cannot replace them.

### D-08.1.3 Parsing and validation rules

Reject:

- invalid UTF-8, BOM, duplicate keys, unknown schema token/version or unknown fields;
- non-canonical timestamps or unsupported numeric values;
- missing/null mandatory fields;
- mismatched tenant, business unit, candidate, model version or evidence kind;
- payload byte-length or payload-digest mismatch;
- missing immutable object version or unavailable required evidence bytes;
- superseded, quarantined, revoked or otherwise ineligible evidence;
- any canonical byte sequence that does not reproduce exactly from an independent RFC 8785 implementation.

No permissive parser mode or silent field defaulting is allowed for a security decision.

### D-08.1.4 Independent fixtures and closure criteria

Publish language-neutral golden fixtures for all three evidence types containing: source object, canonical UTF-8 bytes (hex and byte length), expected SHA-256, parsed field set and negative variants. At least two independently implemented serializers/verifiers must produce byte-identical canonical bytes and matching digests.

Tests must mutate each field independently, including object/version ID, scope, candidate/model, payload descriptor, provenance, assessor/policy version and timestamp. Mutation after request creation, after approval and before execution must fail. Tests must also cover omitted/null fields, unknown fields, duplicate keys, stale versions, wrong scope, evidence substitution, payload truncation, changed retrieval object and unavailable evidence bytes. The request digest and all three evidence digests must be recomputed from retained immutable bytes at creation, approval and execution.

No implementation closure is claimed by this specification.

## D-09.1 — Explicit cross-scope mutation identity and reconstructable event payloads

### D-09.1.1 Global mutation identifier

Every authority-lifecycle mutation that can produce one or more audit events must have one globally unique, immutable `mutation_id` (UUIDv7 or UUID generated by the database from an approved cryptographically secure source). The identifier is created inside the protected transaction and is not caller-selected.

For compatibility with the existing audit envelope, `operation_id` must equal `mutation_id` for these event families. Both fields must be present where the existing envelope requires operation_id; equality is a normative invariant. The payload itself must also include mandatory `mutation_id`. A missing or unequal value is rejected.

### D-09.1.2 Common mutation envelope

All D-09 approval-grant and identity-mapping lifecycle events use a closed common envelope with these mandatory fields:

- `event_id`, `event_type`, `schema_token`, `schema_version`;
- `mutation_id`, `operation_id`;
- `scope_tenant_id`, `scope_business_unit_id`;
- `affected_scope_keys`: complete sorted unique array of all affected tenant/BU scope pairs;
- `affected_object_refs`: complete sorted unique array of typed immutable object identifiers and versions (mapping IDs/versions, grant IDs/versions, request IDs/versions as applicable);
- `mutation_payload_sha256`: SHA-256 of the canonical mutation descriptor shared by every per-scope event;
- `actor_principal_id`, authenticated database login-binding ID, actor mapping version;
- `occurred_at`: database-generated UTC timestamp;
- `reason_code`;
- `prior_state_sha256` and `new_state_sha256` for every changed object, represented in the canonical object-change list.

The event's own scope key identifies the chain receiving that event. The common `affected_scope_keys` and `affected_object_refs` describe the complete mutation, not just the local chain row. Arrays are sorted by canonical UUID byte order and contain no duplicates. Each per-scope event has its own chain sequence and event digest, but all events for one mutation share the same mutation_id, operation_id and mutation_payload_sha256.

### D-09.1.3 Canonical mutation descriptor

Before appending per-scope events, the database constructs one closed canonical mutation descriptor containing the complete ordered list of changed objects, prior/new versions and states, all affected scopes, actor identity, reason code and operation type. Its bytes use RFC 8785 UTF-8 canonicalization and its digest is SHA-256 over those exact bytes. The descriptor is immutable and retained once per mutation. Per-scope event payloads bind its digest and include enough typed references to retrieve it.

An independent verifier must be able to retrieve the descriptor and reconstruct the full mutation from any one affected scope event. Missing descriptor, missing scope event, missing affected object reference, duplicate scope event, digest mismatch or inconsistent prior/new state invalidates the mutation's audit verification and quarantines the affected scope(s).

### D-09.1.4 Grant creation and state semantics

`approval_grant.created` must explicitly define the created grant's initial status. The only permitted initial status is `pending` unless the governing policy explicitly defines a separately authorized direct-activation flow; absent such a flow, creation and activation are separate transactions and separate events.

The creation event must include the full canonical grant state, including grant version, status, role code, scope, immutable principal/issuer/subject binding, granted-by actor, effective/expiry timestamps, policy version and grant-record digest. Activation is represented by `approval_grant.changed` with prior_status=pending and new_status=active. Every subsequent persisted status/role/expiry change carries complete prior and new state, actor, reason and exact grant version. A grant may not be activated by changing a projection or by omitting an event.

### D-09.1.5 Multi-mapping and alias consolidation

An alias consolidation or reassignment that changes multiple mapping rows is one mutation with one mutation_id and one canonical mutation descriptor. The descriptor lists every mapping UUID, old/new mapping version, old/new principal, issuer/subject, login binding, status, old/new scope and affected scope key. The database appends one event to every affected scope chain in the same PostgreSQL transaction as the mapping changes and descriptor insertion.

The number of affected scope events must equal the number of distinct affected scope keys defined by the mutation descriptor. No partial event set is permitted. If a transaction cannot atomically update all required chain heads and events, the entire mutation fails closed.

### D-09.1.6 Required closure evidence

Machine-readable JSON Schemas must enforce all mandatory fields, types, closed additionalProperties=false behavior, sorted unique arrays and cross-field equality constraints. SQL constraints/functions must enforce mutation_id/operation_id equality, uniqueness, descriptor digest, scope membership and expected event count. Tests must cover one-scope, two-scope and many-scope mutations; alias consolidation; duplicate/missing/wrong-scope events; mismatched operation IDs; incomplete affected-object lists; grant creation/activation/revocation; aborted transactions; and two independent verifiers reconstructing identical mutation history.

## D-10.1 — External anchor provider idempotency, state machine and outage gate

### D-10.1.1 Provider capability profile

An anchor destination is eligible only if the customer-approved provider supports at least one of these safe creation contracts:

**Profile A — Provider-enforced idempotent create**

- A stable idempotency key is bound to the exact event digest, exact byte length, anchor contract ID, stream ID and sequence/range.
- Repeating the same key and identical binding returns the original immutable object identity/receipt.
- Repeating the same key with any different bytes or binding returns a conflict and creates no new object.
- The provider exposes a read/verification operation that returns the stored object's exact digest, length, object version, stream/range and retention-lock evidence.

**Profile B — Conditional create plus reconciliation**

- The provider supports atomic create-if-absent at a deterministic object key derived from anchor contract, stream, scope, sequence and event digest.
- If create returns an ambiguous/lost response, the worker reads that deterministic key and verifies the exact stored bytes/digest/length and all binding fields before treating the attempt as successful.
- If the object is absent, the worker may retry the same conditional create.
- If the object exists with different bytes or metadata, the stream is quarantined; overwrite is prohibited.
- The provider must expose immutable object version and retention evidence.

A provider supporting neither profile is not an acceptable independent anchor destination for this gate. A client-generated idempotency key without provider-enforced semantics or conditional-create reconciliation is insufficient. Exactly-once network delivery is not claimed; the required outcome is idempotent, verifiable immutable object creation despite at-least-once delivery.

### D-10.1.2 Submission binding and acknowledgement validation

The outbox record binds the exact canonical event bytes, SHA-256 digest, byte length, anchor contract/version, stream ID, scope, sequence/range, provider profile, deterministic object key/idempotency key and creation timestamp.

Before marking an event acknowledged, the worker must read back or otherwise independently verify the provider object and compare exact bytes or a provider-attested digest backed by the provider's immutable object retrieval API. The acknowledgement must bind every outbox field plus immutable provider object/version ID, provider timestamp, retention mode/status and receipt digest.

A lost response is an ambiguous outcome, not a failure that permits blind creation. The worker must reconcile by idempotency key or deterministic object key. A repeated acknowledgement is accepted only if every bound field and immutable object identity matches the first accepted acknowledgement. Any conflict, digest mismatch, changed object version, missing retention proof or unexpected duplicate object quarantines the stream and raises an incident.

### D-10.1.3 Closed append-only state-transition graph

The anchor state is derived from immutable attempt, acknowledgement, verification and incident records. The allowed transition graph is:

- `pending -> submitted` when a durable submission-attempt record is committed.
- `submitted -> acknowledged` only after a matching provider acknowledgement and object verification are durably recorded.
- `submitted -> failed` only after a bounded attempt is conclusively failed or the provider returns a definitive rejection; ambiguous/lost responses remain submitted and require reconciliation.
- `failed -> submitted` only through a new append-only retry-attempt record using the same immutable outbox bytes and same provider idempotency/conditional-create binding.
- `acknowledged -> verified` only after independent verification confirms object bytes, digest, length, stream/range, object version and retention evidence.
- Any non-quarantined state -> `quarantined` upon conflicting receipt/object, tampering, unexpected duplicate, invalid retention evidence, chain mismatch or unreconciled restore inconsistency.
- `quarantined` is terminal for that stream and evidence sequence. It cannot be cleared or rewritten. Recovery requires a separately authorized incident disposition and a new anchor stream/contract version with a new transition event that references the quarantined stream and verified recovery report. Historical records remain unchanged.

No other transition is permitted. A state projection may be cached, but the authoritative state is recomputed from append-only records. No UPDATE/DELETE of prior attempts, acknowledgements, verification records or quarantine records is allowed to ordinary application roles.

### D-10.1.4 Deterministic maximum-unanchored-window gate

The customer-approved anchor contract must specify a positive maximum unanchored window in seconds. The clock is PostgreSQL server time from the committed outbox row's database-generated `created_at`; client clocks and worker clocks are not authoritative.

The limit is enforced per anchor stream and per governed scope. The oldest not-yet-verified event in that stream/scope determines the unanchored age. The age is calculated at each governed approval, promotion or rollback authorization using database time and the oldest outstanding outbox event. A missing clock value, missing outbox row, inconsistent chain sequence or unavailable state computation fails closed.

When age reaches or exceeds the configured limit, the database denies new governed approval, promotion and rollback operations for the affected scope/stream until all required events are independently verified and the stream is not quarantined. This gate does not authorize or block unrelated advisory reads, but no operation may bypass the governed mutation functions. The threshold and policy version are immutable fields of the pre-approved anchor contract and are bound into the transition event.

Recovery from an ordinary outage resumes exact-byte reconciliation under the same contract. Recovery from quarantine requires the separate incident/new-stream procedure above; an administrator cannot simply clear a status flag. Restores must compare database outbox and append-only records with provider objects/receipts and must quarantine any missing, extra, conflicting or unverifiable sequence.

### D-10.1.5 Required provider and state-machine fixtures

Tests must use a provider simulator implementing Profile A or B and cover:

- repeated identical submission and same-key/different-content conflict;
- provider accepts object but response is lost;
- provider returns stale acknowledgement for an earlier attempt;
- object exists at deterministic key with wrong bytes or metadata;
- unexpected second object/version;
- missing/expired retention lock;
- delayed acknowledgement, duplicate acknowledgement and out-of-order receipt;
- definitive rejection versus ambiguous timeout;
- each permitted state transition and every forbidden transition;
- quarantine terminality and new-stream recovery;
- threshold just below, exactly at and just above the configured window using database time;
- per-scope threshold isolation and multiple streams;
- database restore with matching, missing, extra and conflicting provider objects;
- two independent verifiers reconstructing the same outbox-to-object-to-acknowledgement sequence.

A test provider simulator proves protocol behavior only; customer acceptance and independent evidence from the actual customer-selected provider are still required before any WORM or F-05 claim.

## Updated disposition and governance

This addendum addresses the four conditions identified by the independent reassessment of commit `3fb64cf277eab3d6ed333bc13a2f95aca138caf8` at the design-contract level. It does not declare D-07 through D-10 closed. Closure requires implementation and independent evidence against the criteria in this addendum.

The implementation authorization decision remains **NOT AUTHORIZED** until a reviewer independently reassesses the exact amended commit and explicitly returns **ACCEPT — IMPLEMENTATION AUTHORIZED** for that exact SHA. Conditional acceptance, silence, CI success or approval of the general design direction is not authorization.

PR #20 must remain Draft, open and unmerged. No schema migration, PostgreSQL function, role lifecycle controller, serializer, audit mutation writer, anchor worker, provider integration, production deployment or live IBEDC integration is authorized.

All product boundaries remain unchanged: customer-hosted/customer-controlled deployment; synthetic-data-first; advisory-only; no live IBEDC telemetry; no SCADA/ADMS/DMS control; no switching, dispatch, meter commands, billing adjustments, refunds or journal postings; no automatic production model deployment. Revenue Assurance remains a PowerOps module.
