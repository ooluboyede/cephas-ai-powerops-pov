# Gate 0.6.3.2 — Consolidated Normative Amendment

**Status:** Historical consolidated amendment, supplemented and superseded for remaining reassessment findings by `docs/GATE_0_6_3_2_FINAL_DESIGN_CLOSURE.md`. The final closure contract is the single authoritative source for H-01–H-04 and M-01–M-04; this file remains the normative source for unaffected D-08 rollback-request v2 preimage and evidence-binding rules.

**Reviewed baseline:** `20361119cb17c6854f175b9fcc54a42dedd825d1`  
**Earlier design baseline preserved:** `3fb64cf277eab3d6ed333bc13a2f95aca138caf8`  
**PR:** #20 — Gate 0.6.3.2 Database-Enforced Promotion Authority

**Authorization:** IMPLEMENTATION NOT AUTHORIZED. This amendment specifies contracts only. It does not claim database objects, migrations, authentication hooks, serializers, audit writers, provider adapters, workers, or tests have been implemented.

## 0. Normative precedence and supersession

The later `GATE_0_6_3_2_FINAL_DESIGN_CLOSURE.md` supersedes this file where the independent reassessment identified remaining contradictions: global lock order, trusted session registration, registry v2 event coverage/schema versions, commit-time capture, quarantine reconciliation and descriptor-digest verification. In any conflict on those subjects, the final closure contract controls.

This amendment is intended to be read with the original Gate 0.6.3.2 design document. It consolidates and replaces the prior separate D-07.1–D-10.2 remediation addendum.

1. This file is the sole normative source for D-07.1, D-08.1, D-09.1 and D-10.1/D-10.2.
2. The earlier D-07.1–D-10.2 wording in the main design document and the separate remediation addendum is superseded in full for these subjects. The separate addendum must be removed from the PR; it must not remain as a parallel normative source.
3. D-04.1 rollback-request v1 remains immutable and unchanged. New rollback requests subject to this amendment use rollback-request v2 as specified in §2. No field may be silently added to or removed from v1.
4. D-05 audit-payload registry v1 and every v1 payload schema remain immutable. New mutation-aware events use registry v2 and the v2 payload schemas specified in §3. No v1 schema is reinterpreted.
5. D-06 historical-chain transition requirements remain in force, supplemented by the single anchor model in §4. Where an earlier D-06 outage or anchor statement conflicts with §4, §4 governs prospectively.
6. All earlier requirements not explicitly superseded remain in force. If a requirement cannot be reconciled with this amendment, implementation is blocked pending an explicit versioned amendment and independent review; “stricter fail-closed rule” is not a substitute for resolving contradictory preimages, schemas, identifiers or state transitions.
7. This amendment does not authorize implementation. A reviewer must issue an explicit acceptance decision against the exact resulting commit. Even acceptance does not remove the requirement for separate user authorization before implementation or merge.

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL** and **SHALL NOT** are normative.

## 1. D-07.1 — Login binding, session registration and revocation

### 1.1 Security objects and authoritative epochs

The design distinguishes the PostgreSQL login role, protected login binding, identity mapping, authenticated backend session, and federated identity credential. Names are labels, not durable identity keys.

The protected login-binding record MUST contain:

- immutable `login_binding_id` UUID;
- PostgreSQL database OID and authenticated role OID;
- canonical role name as an observed attribute, never as the durable key;
- protected mapping ID and mapping version;
- tenant and business-unit scope;
- login-binding status;
- monotonic `login_epoch`;
- monotonic mapping version;
- credential/federation binding identifier and credential generation;
- last lifecycle mutation ID and audit reference.

The protected mapping record MUST bind issuer, exact subject, human principal, login-binding ID, tenant, business unit, status and mapping version. One authenticated login MUST resolve to exactly one active protected mapping for a governed operation. Ambiguity is a denial.

The session registration captures a **pair** of generations: `captured_login_epoch` and `captured_mapping_version`. These values are not interchangeable. A governed operation is eligible only when both still equal the current protected values and the login binding and mapping are active.

### 1.2 Protected session-registration record

The closed session-registration record MUST contain exactly:

| Field | Rule |
|---|---|
| session_registration_id | Server-generated immutable UUID |
| database_oid | OID of the authenticated database |
| role_oid | OID resolved from authenticated `SESSION_USER` |
| login_binding_id | Protected immutable login-binding UUID |
| mapping_id | Protected immutable mapping UUID |
| mapping_version | Captured protected mapping version |
| captured_login_epoch | Captured protected login epoch |
| backend_pid | Server-derived backend PID |
| backend_start | Server-derived backend start timestamp, fixed UTC precision |
| session_nonce | Server-generated cryptographically random 256-bit nonce |
| authn_generation | Authenticated credential/federation generation |
| registered_at | Database-generated timestamp |
| registration_state | `active` or `retired` |
| retired_at | Database-generated timestamp or explicit schema-defined absent state |
| retirement_reason | Closed enum; explicit `not_retired` when active |

The unique key is `(database_oid, role_oid, backend_pid, backend_start, session_nonce)`. A uniqueness constraint MUST prevent two active registrations for the same authenticated backend identity. PID alone is never sufficient because it can be reused.

Ordinary runtime, verifier and application roles MUST have no direct INSERT, UPDATE or DELETE privileges on session registrations. Registration fields MUST NOT be accepted as caller-supplied function arguments, session variables, JWT claims or connection-pool metadata.

### 1.3 Trusted registration and connection-pool contract

A session registration MUST be created by a customer-controlled trusted authentication entry point that can prove the database-authenticated role and bind the captured login epoch and mapping version to that authentication event. Acceptable implementation candidates are a reviewed PostgreSQL authentication hook/extension or a customer-controlled connection broker using a one-time, cryptographically authenticated registration assertion bound to database OID, role OID, backend PID, backend start, nonce, login binding, mapping version, login epoch and authentication generation.

A plain application-callable SQL function that reads the *current* epoch after authentication is not sufficient: an old connected session could call it after re-enablement and obtain a fresh registration. A caller-supplied assertion without one-time replay protection and backend binding is also insufficient. The selected mechanism MUST be documented and independently reviewed before implementation.

For governed database paths:
- transaction pooling is prohibited unless a separately reviewed mechanism proves that each transaction is re-authenticated and re-registered to the exact backend and cannot inherit another client's identity or session context;
- session pooling is permitted only when a client session remains bound to the same authenticated backend and its registration is not transferred;
- backend reassignment, backend restart, role change, authentication refresh or loss of binding retires the registration and requires a fresh authentication event;
- disconnect and backend termination trigger retirement; stale rows are harmless only because final checks also require exact live backend identity and current epochs;
- PID reuse cannot match because backend start and nonce must also match.

### 1.4 Final authorization check and lock order

The global lock order for a governed operation is:

1. Lock all relevant protected login-binding and identity-mapping rows in deterministic immutable-ID order.
2. Derive authoritative scope only from the locked mappings.
3. Lock all required tenant/business-unit scope mutexes in canonical scope-key order.
4. Acquire remaining D-02 locks in the existing prescribed order.
5. Re-read, in a fresh SQL statement under the locks, the authenticated session registration, live backend identity, role OID, login-binding status/epoch, mapping status/version, grant and approval eligibility.
6. Perform the governed state transition and transactional audit append.

No code path may acquire a mapping/login-binding row after acquiring a scope mutex. Multi-mapping operations lock the complete mapping set first, then the complete derived scope set. The implementation MUST include foreign-key, trigger, row-level-security and implicit catalog-lock effects in its lock map and deadlock tests.

The final check rejects if the registration is missing, retired, replayed, bound to a different backend, role OID, login binding or authentication generation, or if either captured epoch/version differs from current protected state. A cache or application claim cannot satisfy this check.

### 1.5 Lifecycle states and completion

Disablement has two separately observable phases:

- **revocation committed:** protected login binding/mapping is disabled or revoked, the relevant epochs are incremented, governed operations are denied, and the state mutation plus audit record have committed atomically;
- **operational reconciliation pending:** PostgreSQL LOGIN state, active backend inventory, session termination, federated revocation propagation and external identity-provider state are being reconciled.

A disablement request MUST NOT report operational completion until the required reconciliation evidence is recorded. Failure or delay in `ALTER ROLE ... NOLOGIN`, session termination or federated revocation does not undo protected revocation; it leaves an incident open and the binding quarantined. The actor permitted to close the incident MUST be a separately authorized security-administration role plus an independent reviewer. Closure evidence includes before/after catalog snapshots, role OIDs, session inventory, terminated-session results, epoch and mapping versions, federated-provider acknowledgement where applicable, and successful stale-session denial tests.

Re-enablement requires credential rotation or independently approved credential revalidation, new login epoch, fresh mapping validation and new session authentication. It MUST NOT reactivate old registrations or grants. Out-of-band role or membership changes trigger quarantine and reconciliation. A failure to append the required audit event rolls back the protected lifecycle mutation.

### 1.6 Required implementation evidence

PostgreSQL 16 adversarial tests MUST cover both race orderings, idle pre-existing sessions, stale pooled connections, transaction pooling rejection or reviewed safe alternative, delayed/failed termination, role OID/name reuse, PID reuse, out-of-band NOLOGIN and membership changes, mapping reassignment, multiple mappings, federated revocation, credential retirement, re-enablement, audit failure, deadlock retry and proof that no pre-revocation session can authorize after the revocation linearization point.

## 2. D-08.1 — Evidence bytes, object identity and rollback request v2

### 2.1 One authoritative preimage per evidence object

The dataset snapshot digest is SHA-256 of the **exact raw immutable stored dataset bytes**. No decoding, decompression, newline conversion, row sorting, parsing or reserialization occurs before hashing. If the stored artifact is compressed, the digest covers the exact compressed bytes stored. A logical-content digest, if needed, is a separately named field and is not a substitute.

The provenance and assessment digests are SHA-256 of the exact canonical UTF-8 bytes of their complete closed evidence envelopes under RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8 without BOM, no trailing newline. Duplicate keys, invalid UTF-8, unknown fields, missing fields, unsupported numeric values and non-canonical timestamps are rejected.

The exact schema tokens are:
- dataset metadata descriptor: `cephas.powerops.rollback-target.dataset-snapshot.v1`;
- provenance envelope: `cephas.powerops.rollback-target.provenance.v1`;
- assessment envelope: `cephas.powerops.rollback-target.assessment.v1`.

The dataset schema token describes the immutable metadata descriptor, not a wrapper inserted into the raw dataset-byte digest. The immutable dataset object registry MUST bind that descriptor to exact raw byte length, raw-byte digest, immutable object UUID/version UUID, media type, tenant UUID, business-unit UUID, candidate UUID and model version. The descriptor itself is canonical and immutable. This cleanly separates the raw dataset preimage from the metadata that binds its identity and scope.

The provenance envelope MUST bind immutable object ID/version, tenant/BU, candidate/model, dataset object ID/version and dataset raw-byte digest, ordered lineage edges, transformation IDs/versions, preparation build digest, source references and canonical creation timestamp.

The assessment envelope MUST bind immutable object ID/version, tenant/BU, candidate/model, dataset object ID/version/digest, provenance object ID/version/digest, policy ID/version/digest, assessor identity and software/build version, result, closed reason codes and canonical assessment timestamp.

For all three digests the rule is exactly `lowercase_hex(SHA-256(preimage_bytes))`. No implicit prefix, suffix, transport encoding, database JSONB rendering or display projection is included.

### 2.2 Immutable evidence binding

Each evidence object MUST be immutable and content-addressed. Its protected registry record binds object type, object UUID, immutable version UUID, tenant UUID, business-unit UUID, candidate UUID, model version, exact byte length, digest and customer-controlled retrieval reference. A mutable URL, filename or display label is not identity.

At creation, approval and execution the service MUST retrieve the same exact object versions, validate all scope relationships, recompute all three digests and reject missing, unavailable, superseded, quarantined, wrong-scope or changed evidence. The complete evidence IDs, version IDs and digests are bound into the rollback request canonical bytes. Independent verification MUST be possible from retained immutable bytes and registry metadata, not mutable current-state projections.

### 2.3 Rollback request v1 remains frozen; v2 is mandatory for new requests

The existing `cephas.powerops.rollback-request.v1` envelope and its exact field list remain frozen. It MUST NOT gain evidence IDs, versions or other fields. Existing v1 records remain verifiable under their original semantics but MUST NOT be newly created for a rollback requiring the three target evidence objects defined here.

All new rollback requests governed by this amendment MUST use `cephas.powerops.rollback-request.v2`. There is no silent v1 extension and no implicit v1-to-v2 conversion. A historical v1 request may be represented by a separately created v2 request only after all source/target/evidence data is revalidated; it receives a new request ID and fresh approvals. Existing approvals never transfer.

### 2.4 Exact rollback-request v2 envelope

The v2 envelope is closed and contains exactly the following fields. All fields are mandatory unless a field explicitly defines a closed enum value for absence.

| Field | Type / rule |
|---|---|
| request_schema_version | Exact `cephas.powerops.rollback-request.v2` |
| canonicalization_version | Exact `RFC8785` |
| digest_algorithm | Exact `SHA-256` |
| operation_type | Exact `rollback` |
| rollback_request_id | Unique lowercase canonical UUID |
| tenant_id, business_unit_id | Canonical UUIDs |
| source_active_release_id | Exact currently active release UUID |
| source_active_transition_sha256 | 64 lowercase hex |
| target_release_id | Historical target release UUID |
| target_release_transition_sha256 | 64 lowercase hex |
| target_candidate_id | Canonical UUID |
| target_candidate_version | Positive safe integer |
| target_artifact_sha256 | 64 lowercase hex |
| target_manifest_sha256 | 64 lowercase hex |
| target_evidence_version_id | Immutable UUID |
| target_attestation_id | Immutable UUID |
| target_receipt_sha256 | 64 lowercase hex |
| target_publisher_key_id | Immutable key identifier |
| target_verifier_identity_id, target_verifier_key_id | Immutable identifiers |
| target_policy_id, target_policy_version | Immutable identifier and version token |
| target_policy_sha256 | 64 lowercase hex |
| target_dataset_snapshot_object_id | Immutable UUID |
| target_dataset_snapshot_object_version_id | Immutable version UUID |
| target_dataset_snapshot_schema_token | Exact dataset metadata descriptor token above |
| target_dataset_snapshot_byte_length | Non-negative safe integer |
| target_dataset_snapshot_sha256 | 64 lowercase hex of exact raw stored bytes |
| target_provenance_object_id | Immutable UUID |
| target_provenance_object_version_id | Immutable version UUID |
| target_provenance_schema_token | Exact provenance token above |
| target_provenance_sha256 | 64 lowercase hex of canonical envelope bytes |
| target_assessment_object_id | Immutable UUID |
| target_assessment_object_version_id | Immutable version UUID |
| target_assessment_schema_token | Exact assessment token above |
| target_assessment_sha256 | 64 lowercase hex of canonical envelope bytes |
| rollback_policy_id, rollback_policy_version | Immutable identifier and version token |
| rollback_policy_sha256 | 64 lowercase hex |
| rollback_reason_code | Closed enumerated policy code |
| rollback_reason_sha256 | Digest of separately retained immutable reason/context record |
| eligibility_assessment_sha256 | Digest of database-derived eligibility assessment |
| requestor_principal_id | Protected-mapping-derived human principal UUID |
| requestor_issuer, requestor_subject | Exact canonical mapped issuer and subject |
| request_created_at | PostgreSQL-generated UTC timestamp with six fractional digits |
| risk_acceptance_id | Immutable UUID |
| risk_acceptance_version | Positive safe integer |
| risk_acceptance_sha256 | 64 lowercase hex |

All three evidence object IDs and immutable version IDs MUST be checked against the registry records for exact tenant, BU, candidate and model binding. The object metadata descriptor digest and raw dataset digest are both checked; neither substitutes for the other.

### 2.5 v2 canonical request digest and compatibility

The database constructs the envelope from locked authoritative rows and persists the exact RFC 8785 UTF-8 bytes `R2`. The digest is:

`SHA-256(UTF8("CEPHAS-POWEROPS-ROLLBACK-REQUEST-V2") || 0x00 || R2)`

The prefix, schema token, canonicalization version, exact bytes and digest are immutable. v1 continues to use its original `...REQUEST-V1` prefix and exact field set. A v1 digest MUST never be verified using v2 rules or vice versa.

Approvals bind the exact v2 request ID and digest, operation, scope, source and target transitions, all evidence object IDs/versions/digests, publisher/verifier trust, policy, reason, eligibility assessment, requestor and risk-acceptance version/digest. Execution recomputes the full v2 digest and all evidence digests from retained bytes. Any change requires a new v2 request and fresh approvals.

### 2.6 Golden fixtures and closure

Publish byte-level fixtures for the dataset raw bytes, dataset descriptor, provenance envelope, assessment envelope, and complete rollback-request v2. Each fixture includes source representation, exact preimage bytes in hex, byte length, schema token/version and expected SHA-256. Two independently implemented serializers/verifiers MUST produce byte-identical canonical bytes and digests. Negative fixtures cover every field, Unicode, reordered JSON properties, whitespace, duplicate keys, null/omitted/extra fields, payload truncation, object/version substitution, wrong scope, stale versions and changed bytes at creation, approval and execution.

## 3. D-09.1 — Versioned mutation manifest and deterministic audit reconstruction

### 3.1 Registry and payload versioning

The existing audit-payload registry v1 and all v1 event payload schemas are immutable. The revised registry token is `cephas.powerops.audit-payload-registry.v2`. Mutation-aware payload schemas use explicit v2 tokens, for example `cephas.powerops.audit-payload.identity-mapping-changed.v2` and `cephas.powerops.audit-payload.approval-grant-created.v2`. Every v2 event declares the exact registry token and payload token. No v1 payload acquires fields by implication.

The audit event's existing top-level `operation_id` retains its existing meaning: the originating governed request/operation. It is NOT the mutation identifier. Each atomic authority-lifecycle mutation has a separate database-generated globally unique `mutation_id`. One operation may contain multiple separately atomic mutations; each has a different mutation ID. A mutation retry reconciles the existing committed mutation and MUST NOT create a second mutation or event set.

### 3.2 Closed v2 common mutation envelope

Every v2 mutation-aware event payload MUST contain exactly the registered fields below plus its event-type-specific closed fields:

- `mutation_schema_version`: exact `cephas.powerops.mutation.v1`;
- `mutation_id`: globally unique canonical UUID generated by the protected database function;
- `operation_id`: originating request/operation UUID; distinct from mutation_id;
- `mutation_type`: closed enum from the registry;
- `mutation_payload_sha256`: SHA-256 of the canonical immutable mutation-manifest bytes;
- `mutation_event_index`: zero-based integer assigned by canonical ordering;
- `mutation_event_count`: positive integer equal to the exact expected per-scope event count;
- `affected_mapping_ids`: complete sorted unique mapping UUID array;
- `affected_scope_keys`: complete sorted unique array of exact `{tenant_id,business_unit_id}` pairs;
- `affected_object_refs`: complete sorted unique typed immutable object ID/version references;
- `actor_principal_id`, `actor_login_binding_id`, `actor_mapping_version`;
- `reason_code`;
- `prior_state_digest` and `resulting_state_digest` for the canonical changed-object list.

The event's own tenant/BU fields identify the local chain scope. The arrays identify the complete mutation across all scopes. All arrays use canonical UUID-byte ordering, no duplicates, no unknown fields and explicit bounded lengths. A mutation with no mapping change uses an empty mapping array only where its event schema expressly permits it.

### 3.3 Canonical manifest and expected event set

Before state mutation or event append, the protected database function constructs and retains one immutable closed mutation manifest containing mutation ID, operation ID, mutation type, actor, reason, complete affected object IDs/versions, exact prior/resulting states and digests, complete sorted affected mapping IDs, complete sorted scope keys, and the exact expected event type for each scope.

The canonical ordering is:
1. sort affected scope keys by tenant UUID bytes ascending, then business-unit UUID bytes ascending;
2. emit exactly one mutation event per distinct affected scope key;
3. assign `mutation_event_index` 0 through N-1 in that order;
4. set `mutation_event_count=N` in every event;
5. within a scope, append the event to that scope's chain using the existing locked chain-head sequence.

The manifest contains the expected scope-to-event-type mapping before any event is appended. Therefore an independent verifier can distinguish a missing expected event from an event that was never expected. Multiple changed objects in one scope are represented in the same scope event and complete manifest; they do not create additional events. If a future mutation genuinely requires multiple events per scope, it requires a new registry version and a revised deterministic assignment algorithm before implementation.

### 3.4 Closed mutation-to-event registry v2

Every event below has exactly one event-specific payload schema token. Its payload is the common envelope in §3.2 plus exactly the event-specific fields listed below. No unlisted property, implicit default, arbitrary map or free-text authority field is permitted. All status and reason fields use registry-defined enums; all UUIDs and digests use the canonical formats defined above.

| Mutation type | Event type | Exact payload schema token | Event-specific fields |
|---|---|---|---|
| login_binding.disabled | `identity.login-binding-disabled` | `cephas.powerops.audit-payload.identity-login-binding-disabled.v2` | login_binding_id, database_oid, role_oid, prior_status, resulting_status, prior_login_epoch, resulting_login_epoch, affected_session_count, session_termination_state, incident_id |
| login_binding.reenabled | `identity.login-binding-reenabled` | `cephas.powerops.audit-payload.identity-login-binding-reenabled.v2` | login_binding_id, database_oid, role_oid, prior_status, resulting_status, prior_login_epoch, resulting_login_epoch, credential_generation, credential_rotation_evidence_sha256, mapping_ids |
| identity_mapping.created | `identity.mapping-created` | `cephas.powerops.audit-payload.identity-mapping-created.v2` | mapping_id, prior_mapping_version, resulting_mapping_version, login_binding_id, issuer, subject, principal_id, tenant_id, business_unit_id, status |
| identity_mapping.changed | `identity.mapping-changed` | `cephas.powerops.audit-payload.identity-mapping-changed.v2` | mapping_id, prior_mapping_version, resulting_mapping_version, prior_login_binding_id, resulting_login_binding_id, prior_issuer, resulting_issuer, prior_subject, resulting_subject, prior_principal_id, resulting_principal_id, prior_status, resulting_status |
| identity_mapping.disabled | `identity.mapping-disabled` | `cephas.powerops.audit-payload.identity-mapping-disabled.v2` | mapping_id, prior_mapping_version, resulting_mapping_version, login_binding_id, prior_status, resulting_status, disable_reason_code |
| identity_mapping.reassigned | `identity.mapping-reassigned` | `cephas.powerops.audit-payload.identity-mapping-reassigned.v2` | change_set_sha256, changed_mapping_count, prior_scope_count, resulting_scope_count |
| approval_grant.created | `approval.grant-created` | `cephas.powerops.audit-payload.approval-grant-created.v2` | grant_id, prior_grant_version, resulting_grant_version, status, role_code, principal_id, issuer, subject, granted_by_principal_id, effective_at, expires_at, policy_id, policy_version, grant_record_sha256 |
| approval_grant.activated | `approval.grant-activated` | `cephas.powerops.audit-payload.approval-grant-activated.v2` | grant_id, prior_grant_version, resulting_grant_version, prior_status, resulting_status, activated_by_principal_id, activation_policy_id, activation_policy_version, grant_record_sha256 |
| approval_grant.changed | `approval.grant-changed` | `cephas.powerops.audit-payload.approval-grant-changed.v2` | grant_id, prior_grant_version, resulting_grant_version, prior_status, resulting_status, prior_role_code, resulting_role_code, prior_expires_at, resulting_expires_at, grant_record_sha256 |
| approval_grant.revoked | `approval.grant-revoked` | `cephas.powerops.audit-payload.approval-grant-revoked.v2` | grant_id, prior_grant_version, resulting_grant_version, prior_status, resulting_status, revocation_reason_code, revoked_by_principal_id, affected_request_count |
| approval_grant.expired | `approval.grant-expired` | `cephas.powerops.audit-payload.approval-grant-expired.v2` | grant_id, prior_grant_version, resulting_grant_version, prior_status, resulting_status, expiry_at, affected_request_count |
| governed_request.invalidated | `governed-request.invalidated` | `cephas.powerops.audit-payload.governed-request-invalidated.v2` | request_id, request_version, request_digest, prior_status, resulting_status, invalidation_reason_code, invalidating_object_ref, affected_approval_ids |
| security_incident.quarantined | `security.incident-quarantined` | `cephas.powerops.audit-payload.security-incident-quarantined.v2` | incident_id, quarantine_reason_code, quarantine_actor_principal_id, quarantined_object_count, quarantined_object_refs_sha256, prior_stream_condition, resulting_stream_condition |
| security_incident.reconciled | `security.incident-reconciled` | `cephas.powerops.audit-payload.security-incident-reconciled.v2` | incident_id, disposition_code, disposition_record_sha256, incident_commander_principal_id, independent_reviewer_principal_id, reconciled_object_count, reconciled_object_refs_sha256, prior_stream_condition, resulting_stream_condition |

The mutation manifest uses exact schema token `cephas.powerops.mutation-manifest.v1` and contains exactly: schema_token, schema_version, mutation_id, operation_id, mutation_type, actor_principal_id, actor_login_binding_id, actor_mapping_version, reason_code, created_at, affected_mapping_ids, affected_scope_keys, affected_object_refs, changed_objects, expected_events, expected_event_count. Each `changed_objects` entry contains exactly object_type, object_id, prior_version, resulting_version, prior_state_sha256, resulting_state_sha256. Each `expected_events` entry contains exactly tenant_id, business_unit_id, event_type, event_payload_schema_token and mutation_event_index. The expected event array is sorted by the canonical scope ordering in §3.3. The manifest bytes are RFC 8785 UTF-8 and its SHA-256 is the common `mutation_payload_sha256`.

The registry v2 release artifact MUST publish machine-readable JSON Schemas for the common envelope, manifest and every event-specific payload above, including exact types, nullability, enums, maximum array lengths, cross-field constraints and examples. A row in this table is not implementation-closed until its corresponding machine-readable schema and positive/negative golden fixtures exist. Any future field change requires a new payload schema token and registry version.

### 3.5 Grant and actor semantics

Grant creation MUST have initial status `pending`. Direct activation is prohibited in this gate; creation and activation are separate mutations and events. Activation requires the separately authorized activation function and a fresh serialized eligibility check. A grant is unusable unless active and all current eligibility conditions pass.

Every grant event records grant ID/version, role, scope, principal/issuer/subject binding, granted-by actor, prior/resulting status, effective/expiry timestamps, policy version, reason and canonical grant-state digest. Mapping events record all prior/resulting mapping IDs/versions, login binding, issuer/subject, principal, scope, status, actor and reason. Multi-mapping reassignment/alias consolidation includes every affected mapping and old/new scope in one manifest and one event per affected scope.

### 3.6 Atomicity, verification and schema transition

The mutation manifest, all expected per-scope events, chain-head updates and all mapping/grant/request state changes MUST commit in one PostgreSQL transaction. Any event/schema/chain failure rolls back all changes. Aborted transactions leave no committed mutation manifest or events. Mutation IDs cannot be reused with different manifest bytes.

Two independent verifiers MUST reconstruct identical mutation histories from retained immutable manifest and event bytes alone. They reject missing, duplicate, reordered, wrong-scope, unknown, unregistered, count-mismatched, index-mismatched, wrong-actor, mismatched-manifest, prior/resulting-state mismatch and aborted-transaction events. Registry v2 requires explicit compatibility rules: v1 records are verified only with v1 schemas; v2 records only with v2 schemas; a registry transition is itself versioned and audited. No in-place v1 payload mutation is permitted.

## 4. D-10.1/D-10.2 — External anchor, immutable verification and outage gate

### 4.1 Separate immutable event facts from current stream condition

Anchor state is represented by two independent records:

1. **Per-event immutable lifecycle facts:** outbox event, submission attempts, provider acknowledgements, independent verification records and their exact bytes/digests. A `verified` record is a permanent historical fact and is never rewritten or deleted.
2. **Current stream-integrity condition:** `healthy` or `quarantined`, derived from append-only integrity incident records. A stream may become quarantined after an event was verified if later evidence shows tampering, retention downgrade, provider mutation, conflicting object identity or other integrity failure. Quarantine does not delete, reverse or rewrite the earlier verified record.

Quarantine is terminal for that stream identity. Recovery requires a separately approved new contract and stream ID, an immutable continuity/version-transition event and independent verification. The old stream's verification history and quarantine remain visible forever.

### 4.2 Per-event lifecycle state graph

The only permitted per-event lifecycle transitions are:

| Current | Next | Required condition |
|---|---|---|
| pending | submitted | Exact outbox bytes/digest selected and immutable attempt committed |
| pending | failed | Permanent pre-submission failure; proof no provider object could have been created |
| submitted | acknowledged | Provider result reconciled to exact event, stream, sequence, bytes/digest and retention metadata |
| submitted | failed | Retry policy exhausted or non-retryable failure; reconciliation proves no conflicting accepted object |
| failed | submitted | New append-only attempt; Mode A or Mode B proves safe same-event retry |
| acknowledged | verified | Independent readback/verifier confirms exact object identity, bytes/digest, stream, sequence and retention evidence |

No per-event transition leaves `verified`. Duplicate identical acknowledgements are retained as duplicate observations linked to the original acknowledgement and do not create a new state transition. A conflicting or stale acknowledgement creates an integrity incident and may quarantine the stream; it never regresses or overwrites a verified fact.

### 4.3 Provider contract and idempotency

A provider is eligible only if it supports either:

- **Mode A:** provider-enforced idempotent creation where the same key + same digest + same stream returns the same immutable object identity, and same key with different content or stream is a hard conflict; or
- **Mode B:** atomic conditional create-if-absent under a deterministic object key, followed by authenticated reconciliation after every ambiguous response.

The deterministic key is derived from a versioned domain-separated SHA-256 construction over immutable anchor contract ID, stream ID, scope key, sequence and event digest. The derivation and golden test vectors are part of the customer-approved contract. A client-generated key alone is not proof of idempotency.

Every attempt, response, acknowledgement, readback and verification result is append-only. A success is recorded only after independent validation of exact object ID/version, exact bytes or independently verifiable digest, stream, scope, sequence and retention evidence. Same-key/different-content, duplicate conflicting object, lost-response ambiguity that cannot be reconciled, stale/wrong-stream receipt or retention downgrade quarantines the stream. No overwrite is attempted.

### 4.4 Authoritative commit timestamp

A normal row `created_at`, `now()` or transaction-start timestamp MUST NOT be described as the actual commit timestamp.

For every audit/outbox event, the transaction stores its full transaction ID (`xid8`) and immutable event ID. The customer PostgreSQL deployment MUST enable and validate `track_commit_timestamp=on`. After commit, a trusted anchor-ledger process obtains the event transaction's commit timestamp from PostgreSQL's commit-timestamp facility, verifies the transaction/event identity, and persists that timestamp in a separate immutable commit-time ledger. The ledger capture MUST occur before PostgreSQL can truncate the relevant commit-timestamp metadata. If the timestamp cannot be obtained or validated, the event is treated as unanchored with unknown start time and all governed approval/promotion/rollback operations fail closed until reconciliation establishes a valid timestamp.

The unanchored interval begins at that persisted PostgreSQL commit timestamp for the earliest committed event in the relevant stream/scope not yet verified. The final eligibility check obtains comparison time from PostgreSQL `clock_timestamp()`; application and provider clocks are never authoritative. Restores preserve the original commit-time ledger and reconcile it against external objects. Missing, reset or inconsistent ledger state fails closed; restore must never shorten the measured interval.

### 4.5 Outage policy and threshold

A customer-approved anchor contract MUST define a positive maximum unanchored duration, scope/stream applicability, retention policy and recovery authority. If no valid approved contract or maximum exists, the default is **zero tolerance**: any required event not yet verified blocks new governed approval, promotion and rollback immediately.

At the configured maximum, the affected scope/stream fails closed for:
- new promotion or rollback requests, approvals and executions;
- new approval-grant creation or activation;
- new or expanded risk acceptance;
- identity/login re-enablement or any mutation that expands authority;
- any action that would create new governed release authority.

The following remain permitted as security containment or recovery actions, provided their local database audit append succeeds:
- read-only audit inspection and evidence export;
- outbox retry, provider reconciliation and independent verification;
- incident opening, quarantine, investigation and incident disposition;
- login disablement, credential retirement, mapping disablement and grant revocation/expiry;
- corrective mapping changes whose net effect only reduces or contains authority;
- session termination and security containment;
- backup/restore validation and new-stream continuity preparation.

A mapping correction, grant change or incident action that expands authority is not permitted during the outage. This asymmetry is deliberate: security-reducing actions remain available; authority-expanding actions do not.

Threshold evaluation is per exact anchor contract + stream + tenant/BU scope. The age is `database_clock_now - earliest_unverified_commit_timestamp`. At equality with the configured maximum, the gate is closed (`age >= maximum`). A restore cannot reset the clock. Policy changes are versioned and prospective only; no retroactive extension, timestamp editing, outbox deletion or stream renaming can waive an already reached threshold.

The gate clears only when every event in the relevant unanchored interval is independently verified, the immutable commit-time ledger is complete, and the chain/outbox/provider reconciliation report passes. Manual override cannot mark an event verified.

### 4.6 Required provider and recovery evidence

Tests MUST cover both provider modes, same-key replay, different-content conflict, lost response after successful create, duplicate object version, readback mismatch, stale/wrong-scope receipt, retention downgrade, delayed provider, threshold boundary, no-policy zero tolerance, missing commit timestamp, commit-time metadata truncation, database restore, retry, quarantine after prior verification, prohibited quarantine clearing, new-stream continuity and security-containment operations during outage. A customer-selected provider must be independently assessed before any WORM or immutable-retention claim.

## 5. Cross-cutting lock, schema and acceptance requirements

1. The complete lock map MUST include login-binding rows, identity mappings, session registration/epoch records, scope mutexes, grants, approvals, requests, audit chain heads, mutation manifests and anchor-policy/stream state.
2. Lock order is mapping/login-binding bootstrap first, then canonical scope mutexes, then the remaining D-02 locks. No reverse acquisition is permitted.
3. PostgreSQL 16 concurrency tests MUST include multi-mapping reassignment, foreign-key and trigger effects, implicit locks, deadlock retries, out-of-band role changes and anchor-outage security containment.
4. Every closed schema has an explicit token/version, exact field set, nullability, encoding, canonicalization and golden fixtures. No “stricter rule wins” interpretation is allowed to reconcile conflicting schemas.
5. Two independent implementations MUST reproduce all evidence bytes/digests, rollback-request v2 bytes/digest, mutation manifests, event ordering and audit verification results.
6. The effective-privilege closure, migration/legacy-record handling, transactional audit atomicity, external anchor and historical audit transition requirements remain open until their own implementation evidence is independently reviewed.
7. CI success on documentation changes is repository workflow evidence only. It does not prove PostgreSQL session enforcement, digest correctness, audit reconstruction, provider idempotency, WORM retention or operational security.

## 6. Explicit implementation evidence checklist

Implementation remains unauthorized until all relevant design conditions are independently accepted and, after separate authorization, the implementation evidence demonstrates:

- trusted session registration, protected storage, epoch comparison and PostgreSQL 16 revocation race tests;
- immutable evidence registries, exact raw/canonical preimages, golden byte fixtures and two independent implementations;
- rollback-request v2 closed schema, v1 compatibility preservation and fresh approvals;
- audit registry v2, complete payload schemas, mutation-to-event matrix, deterministic ordering and independent reconstruction;
- atomic cross-scope state + manifest + events + chain-head writes;
- provider Mode A or Mode B conformance, commit-time ledger, outage gate and restore/recovery tests;
- effective privilege closure and no bypass through direct SQL, functions, triggers, ownership or inherited grants;
- migration preflight, cutover, legacy classification and active-release preservation;
- customer-controlled deployment, customer-approved anchor provider and independent retention evidence.

## 7. Governance and product boundary

**Disposition requested:** independent reassessment of this consolidated design against the exact commit containing this file and removal of the competing addendum.

**Current authorization:** IMPLEMENTATION NOT AUTHORIZED. No database schema, migration, SECURITY DEFINER function, role change, session hook, serializer, audit writer, outbox worker, anchor provider integration, production deployment or certification is authorized or claimed.

PR #20 MUST remain Draft, open and unmerged. Synthetic-data-first, customer-hosted/customer-controlled and advisory-only PoV boundaries remain unchanged. No live IBEDC telemetry, SCADA/ADMS/DMS control, switching, dispatch, meter commands, billing adjustments, refunds, journal postings or automatic production model deployment is authorized.
