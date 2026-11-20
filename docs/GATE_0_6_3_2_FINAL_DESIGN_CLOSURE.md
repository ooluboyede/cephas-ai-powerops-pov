# Gate 0.6.3.2 — Final design-closure contract

**Authority:** This is the single authoritative closure layer for the independent reassessment of 0470b3e0cf2a7b06739b2ccdf0d5f6b0135e7026.
**Status:** Design-only. Implementation is NOT AUTHORIZED.
**Scope:** H-01–H-04 and M-01–M-04.
**Precedence:** This document supersedes conflicting D-02, D-07, D-09 and D-10 wording for lock ordering, session registration, mutation registry, commit-time capture, incident reconciliation and descriptor verification. Unaffected D-02/D-05/D-06 requirements remain in force.
**Artifacts:** schemas/gate-0.6.3.2/lock-order.v1.json, audit-registry-v2.schema.json and fixture-catalog.v1.json.

## 0. Binding decisions

1. There is one complete global lock order in §1. No document-specific prefix or alternative order is permitted.
2. The only permitted D-07 registration design is a customer-controlled authentication broker integrated with a trusted PostgreSQL authentication extension. An application-callable registration function and broker-only post-login SQL registration are prohibited.
3. Every new D-02.1 or D-07 authority-changing mutation MUST emit registry-v2 mutation events. Registry v1 remains read-only for historical verification and explicitly classified legacy informational events; it MUST NOT be used for new authority mutations.
4. Registry, event-envelope, mutation-envelope, manifest and event-payload versions are distinct tokens and are carried explicitly. No verifier may infer one version from another.
5. Commit timestamps are captured from PostgreSQL WAL commit records through a durable logical-decoding slot. track_commit_timestamp and pg_xact_commit_timestamp() are not the durability mechanism.
6. Incident disposition never clears a quarantined stream. Recovery always uses a new stream identity and contract.
7. Rollback-request v2 remains unchanged. Its dataset descriptor digest is verified from the immutable registry record bound by object ID and immutable version ID; it is not added to the closed request envelope.
8. Schema-defined absence is explicit JSON null or a closed enum sentinel. Omitted fields are never interpreted as absence.

## 1. H-01 — One complete global lock hierarchy

### 1.1 Normative hierarchy

Every transaction changing or authorizing governed state MUST acquire locks in this order. This list is complete; references to remaining D-02 locks are not normative.

| Rank | Lock class | Row ordering within class |
|---:|---|---|
| 0 | Protected login-binding rows | login_binding_id UUID bytes ascending |
| 1 | Protected identity-mapping rows | mapping_id UUID bytes ascending |
| 2 | Session-registration and epoch rows | registration UUID, then backend identity tuple |
| 3 | Tenant/business-unit scope mutex rows | tenant UUID bytes, then BU UUID bytes |
| 4 | Risk-acceptance rows | risk-acceptance UUID, then version |
| 5 | Accountable-role assignment rows | role-assignment UUID |
| 6 | Verifier-identity trust rows | verifier identity UUID |
| 7 | Verifier-key trust rows | verifier key ID byte order |
| 8 | Publisher-key trust rows | publisher key ID byte order |
| 9 | Promotion/rollback policy rows | policy UUID, then version |
| 10 | Evidence registry and quarantine rows | object type, object UUID, immutable version UUID |
| 11 | Candidate rows | candidate UUID bytes ascending |
| 12 | Governed request rows | request UUID bytes ascending |
| 13 | Approval-grant rows | grant UUID bytes ascending |
| 14 | Approval-decision rows | approval UUID bytes ascending |
| 15 | Release and active-release-pointer rows | release UUID bytes ascending; pointer last |
| 16 | Anchor-contract and stream-condition rows | contract UUID, stream UUID |
| 17 | Audit-chain-head rows | tenant UUID, BU UUID; global chain last |
| 18 | Mutation-manifest idempotency row | mutation UUID bytes ascending |
| 19 | Transactional outbox rows | stream UUID, sequence, event UUID |

Ranks 0–2 are acquired FOR UPDATE for lifecycle mutations and FOR SHARE for authorization reads. Scope mutexes at rank 3 are FOR UPDATE. Each later class uses FOR SHARE for read/eligibility and FOR UPDATE for mutation, except immutable approval decisions, which are never updated. Outbox rows are inserted only after all authority locks; workers do not hold source-transaction locks.

The immutable commit-time ledger is written by a separate WAL-decoder transaction and is not locked by a source transaction. A governed operation reads a committed ledger snapshot only after acquiring the anchor-contract/stream lock at rank 16.

### 1.2 D-02.2 supersession

The former D-02.2 scope-mutex-first order is expressly superseded. Ranks 0–2 are mandatory identity bootstrap locks; rank 3 is the first scope lock. No function may acquire a scope mutex and subsequently acquire a login-binding, mapping or session-registration lock.

Resolve authenticated identity and all mapping-derived scopes while ranks 0–2 are held. Then acquire every affected scope mutex in canonical order before any rank-4-or-later lock.

### 1.3 Implicit locks and execution rules

- Before writes, pre-lock every referenced parent row and every row a foreign-key check, trigger, cascade or deferred constraint can lock, at its assigned rank. Foreign-key KEY SHARE locks count in that class.
- Triggers and RLS policy functions MUST NOT acquire locks outside this hierarchy. Triggers may validate already-locked rows but may not initiate another lock sequence. RLS predicates are side-effect-free and acquire no locks.
- Privileged writes pass through reviewed functions using one shared lock-acquisition routine. Direct DML, ad-hoc advisory locks, dynamic lock order and trigger-driven cross-scope writes are prohibited.
- Multi-scope mutations lock all identity rows first, then all scope mutexes in canonical byte order, then each later class in rank order. Do not interleave classes by scope.
- No application or worker transaction may hold rank 16 or later and call an authority function requiring ranks 0–15.
- DDL/catalog locks are outside the online protocol. Migrations run in a maintenance window with governed writes disabled.
- Deadlock/serialization failure aborts the complete transaction. A bounded retry restarts at rank 0 and repeats authentication, epoch and eligibility checks.

The machine-readable rank map is normative. Independent acceptance requires two-session race/deadlock fixtures for mapping reassignment versus approval/promotion and disablement versus grant use, including FK, trigger, RLS and multi-scope paths.

## 2. H-02 — Trusted fresh-authentication registration protocol

### 2.1 Selected mechanism

The only acceptable path is a customer-controlled authentication broker plus a trusted PostgreSQL authentication extension. The extension registers a session as part of successful authentication completion. No SQL-callable registration API exists for application, runtime, verifier, approver or broker roles. The broker MUST NOT authenticate a user and then ask that user's SQL session to call a registration function.

The broker creates one dedicated physical PostgreSQL backend per authenticated principal session. Transaction pooling is prohibited. Session pooling is permitted only while the same authenticated client remains bound to the same physical backend; a backend is never reassigned to another principal.

### 2.2 Fresh authentication and signed assertion

For every new backend, the broker MUST validate a fresh upstream IdP assertion: signature, exact issuer, audience, subject, iat/nbf/exp, unique jti, auth_time, required MFA/authentication context and current revocation status. auth_time MUST be later than the login binding's most recent re-enable/credential-rotation time. Token refresh or cached broker session is not fresh authentication.

The broker resolves exactly one active protected mapping and current mapping version, login epoch, credential generation and canonical human principal. During the PostgreSQL authentication exchange, the trusted extension supplies a server-generated single-use challenge bound to the new backend's server-observed database OID, role OID, PID and backend start time.

The broker signs a closed assertion containing exactly: assertion_schema, issuer, audience_cluster_id, database_oid, role_oid, backend_pid, backend_start, server_challenge, assertion_jti, idp_issuer, idp_subject, idp_jti, login_binding_id, mapping_id, mapping_version, login_epoch, credential_generation, authn_generation, auth_time, issued_at, expires_at and broker_key_id.

Assertion lifetime is at most 30 seconds. It is bound to one PostgreSQL cluster and one backend. Signature is Ed25519 over RFC 8785 canonical UTF-8 bytes with domain prefix CEPHAS-POWEROPS-SESSION-REGISTRATION-V1 followed by 0x00. Broker keys are customer-controlled, versioned and pinned in extension configuration. Unknown, expired or revoked keys fail authentication.

### 2.3 Extension verification and atomic one-time consumption

During authentication completion, the extension independently derives live database OID, SESSION_USER role OID, PID and backend start from PostgreSQL server state. It verifies exact equality with the assertion and verifies the challenge is outstanding, unexpired and issued for this backend.

The extension then executes one protected registration transaction:
- locks login binding and mapping at ranks 0–1 and session/epoch state at rank 2;
- rechecks active status, current login epoch, mapping version and credential generation;
- inserts assertion_jti and idp_jti into protected replay tables with unique constraints;
- inserts exactly one active session-registration row;
- commits replay consumption and registration atomically.

This transaction is initiated only by the authentication extension's trusted server-side path, not by a SQL function exposed to the client. If validation, a unique constraint, insert or commit fails, authentication fails and the extension terminates the backend. Failed registration MUST NOT leave a reusable assertion or active registration.

The session-registration key is database_oid, role_oid, backend_pid, backend_start and session_nonce. A separate partial unique constraint MUST enforce at most one active registration for database_oid, role_oid, backend_pid and backend_start regardless of nonce. Unique constraints also cover assertion_jti and (idp_issuer,idp_jti) for the replay-retention window.

### 2.4 Freshness, lifecycle and governed-operation checks

- An existing backend can never obtain a new assertion for itself. Assertions are issued only during creation of a new physical backend after fresh upstream authentication.
- Reject auth_time predating re-enablement, credential rotation, IdP revocation cutoff or latest required step-up.
- Every governed operation compares captured login epoch and mapping version with current protected rows under ranks 0–2 and checks exact live backend identity and active registration.
- Disablement increments login epoch and/or mapping version before commit; that commit is the revocation linearization point.
- Re-enablement increments login epoch again and requires credential rotation or independently approved revalidation plus new upstream authentication. Old registrations and grants never reactivate.
- Disconnect, termination, restart, role change, mapping reassignment, credential refresh, authn-generation change or broker revocation retires registration.
- PID reuse cannot match because backend start and nonce are bound. An old backend cannot re-register after re-enablement because registration is possible only during a new authentication handshake for a new backend.
- If the PostgreSQL 16 extension cannot demonstrate trusted assertion validation, atomic replay consumption and active-backend uniqueness, the gate remains rejected. There is no fallback to application-callable SQL registration.

Required tests: valid, expired, wrong-cluster/database/role/PID/backend-start, challenge replay, assertion-JTI replay, IdP-JTI replay, wrong issuer/subject, stale auth_time, old credential generation, revoked IdP token, revoked broker key, mapping/epoch race, concurrent duplicate assertion, failed registration commit, backend termination, PID reuse and attempted registration from an already authenticated stale backend. The last test must prove no SQL-callable stale-session path exists.

## 3. H-03 / M-02 / M-04 — Complete authority mutation registry v2

### 3.1 Version hierarchy and verifier selection

| Layer | Exact token | Meaning |
|---|---|---|
| Registry | cephas.powerops.audit-payload-registry.v2 | Catalogue of event schemas and mutation mappings |
| Event envelope | cephas.powerops.audit-event-envelope.v2 | Common outer event structure |
| Mutation envelope | cephas.powerops.mutation.v1 | Mutation identity and ordering semantics |
| Mutation manifest | cephas.powerops.mutation-manifest.v1 | Canonical immutable before/after manifest |
| Event payload | One cephas.powerops.audit-payload.*.v2 token per event | Event-specific closed fields |

Every event carries registry_token, registry_version, event_envelope_schema_token, mutation_schema_version, manifest_schema_token, event_payload_schema_token, event_type and mutation_type. The verifier selects registry by registry_token plus registry_version, then validates envelope token, manifest token, mutation/event mapping and exact payload token. Unknown combinations fail closed.

Registry v1 and its payloads remain byte-for-byte frozen and verify historical v1 records only, plus explicitly classified legacy informational records. Every new mutation changing, granting, revoking, superseding, quarantining, approving, executing or expanding authority uses registry v2. A v1 event cannot satisfy a v2 mutation's expected event set.

### 3.2 Complete mutation coverage

The registry is exhaustive for D-02.1 and D-07 authority objects. Any unlisted authority mutation is blocked pending a new independently reviewed registry version.

| Mutation type(s) | Event type(s) |
|---|---|
| verifier_identity.created / changed / disabled | trust.verifier-identity-created / changed / disabled |
| verifier_key.activated / expired / revoked / compromised | trust.verifier-key-activated / expired / revoked / compromised |
| publisher_key.activated / expired / revoked / compromised | trust.publisher-key-activated / expired / revoked / compromised |
| risk_acceptance.created / amended / expired / revoked / superseded | risk.risk-acceptance-created / amended / expired / revoked / superseded |
| accountable_role.appointed / replaced / removed | authority.accountable-role-appointed / replaced / removed |
| evidence.registered / quarantined / released / superseded / reverified | evidence.registered / quarantined / released / superseded / reverified |
| promotion_policy.activated / retired | policy.promotion-policy-activated / retired |
| approval_grant.created / activated / changed / revoked / expired | Existing five approval.grant-* v2 events |
| approval.recorded / invalidated | approval.decision-recorded / invalidated |
| login_binding.disabled / reenabled | Existing two identity.login-binding-* v2 events |
| identity_mapping.created / changed / disabled / reassigned | Existing four identity.mapping-* v2 events |
| promotion_request.created / approved / invalidated / executed | governed-request.promotion-created / approved / invalidated; release.promoted |
| rollback_request.created / approved / invalidated / executed | governed-request.rollback-created / approved / invalidated; release.rolled-back |
| security_incident.quarantined / reconciled | Existing two security.incident-* v2 events |
| anchor_contract.activated / retired | anchor.contract-activated / retired |

Each atomic mutation emits exactly one event per distinct affected scope key. The manifest enumerates the complete scope-to-event-type set before writes. Multi-scope order is tenant UUID bytes then BU UUID bytes. mutation_event_index is contiguous from zero; mutation_event_count equals the manifest expected count. A verifier rejects missing, duplicate, extra, reordered, wrong-scope, wrong-event-type or wrong-payload-token events.

A trust/key/policy mutation affecting multiple scopes enumerates every affected tenant/BU. If a control-plane mutation affects no tenant/BU, it emits exactly one separately chained global event with scope_kind=global and tenant_id=null and business_unit_id=null. Tenant events use scope_kind=tenant_business_unit and both UUIDs non-null. No mutation has an empty expected event set.

### 3.3 Absence and state-transition semantics

The companion JSON Schema file is closed: additionalProperties is false at every object level. Every field is required unless its schema explicitly permits null.

- Creation has prior_version=null and prior_state_sha256=null; resulting version/digest is mandatory.
- Existing-object mutation has non-null prior/resulting versions/digests and resulting version greater than prior.
- Nullable prior status is allowed only for creation and is exactly null, never omitted or empty.
- expires_at=null means explicitly non-expiring, only where policy permits it.
- session_termination_state is one of not_required, no_active_sessions, pending, completed or failed. affected_session_count=0 requires no_active_sessions or not_required; a positive count forbids those two values.
- incident_id=null is allowed only when no incident was opened; otherwise it references an immutable incident.
- Session/request/object counts are non-negative integers backed by a deterministic query snapshot digest in the manifest.
- identity.mapping-created requires prior_mapping_version=null, prior_status=null and resulting_mapping_version=1. Other mapping events require non-null prior version/status.
- approval.grant-created requires prior_grant_version=null, prior_status=null, resulting_grant_version=1 and status=pending. expires_at=null is non-expiring only under explicit policy.
- A no-active-session disablement uses session_termination_state=no_active_sessions, never omission.
- For security.incident-reconciled, if prior_stream_condition=quarantined then resulting_stream_condition MUST equal quarantined. Recovery uses a new contract and stream ID.

Grant creation is absent -> pending only. Activation is pending -> active only. Change is active -> active or pending -> pending unless a separate activation event is emitted. Revocation is pending/active -> revoked. Expiry is pending/active -> expired only after expiry time. No transition leaves revoked/expired; re-grant creates a new grant ID.

Approval decisions are immutable and bind one exact request version/digest and grant ID/version. Correction requires a separate invalidation event and a new approval ID; no row is overwritten. Promotion/rollback request transitions are draft -> submitted -> approved -> executed, or a non-executed state -> invalidated. Execution creates a new release transition and never mutates historical release bytes or reactivates an old row.

### 3.4 Manifest and atomicity

The manifest schema token is cephas.powerops.mutation-manifest.v1; the common mutation token is cephas.powerops.mutation.v1. The manifest contains exact mutation/operation IDs, mutation type, actor principal/login binding/mapping version, reason, canonical creation time, complete affected mapping IDs, scope keys, typed immutable object references, changed-object prior/resulting versions and digests, expected event list and event count.

Manifest bytes are RFC 8785 canonical UTF-8 without BOM or trailing newline. Its digest is SHA-256 of those bytes. The event envelope carries registry token/version explicitly; the manifest token is not a registry token. One transaction writes changed rows, immutable manifest, all scope-chain events, chain-head updates and transactional outbox rows. Any failure rolls back the complete mutation. The outbox worker cannot asynchronously repair a missing authority event.

The companion registry JSON Schema contains the common envelope, manifest and every event-specific v2 payload schema. The fixture catalog contains positive and negative validation cases for every event token. A row is not implementation-closed until schema validation, canonical-byte fixtures and independent reconstruction tests pass.

## 4. H-04 — Durable PostgreSQL commit-time ledger from WAL

### 4.1 Superseded mechanism

track_commit_timestamp and pg_xact_commit_timestamp() are not sufficient durability mechanisms because commit timestamp metadata may be truncated. They are not authoritative inputs to the unanchored-window calculation.

### 4.2 WAL capture protocol

The customer PostgreSQL deployment MUST provide logical decoding through a persistent logical replication slot and a decoder/output plugin exposing the actual WAL commit-record timestamp, commit LSN, transaction ID and committed event/outbox rows. PostgreSQL logical replication Begin metadata carries commit timestamp and transaction identity; the selected plugin MUST preserve these values without substituting worker or insertion timestamps.

Every transactional audit/outbox row stores immutable event UUID, full transaction ID xid8 captured in the source transaction, expected low 32-bit WAL xid, exact scope/stream/sequence and event digest, source database system identifier and timeline identity. The decoder correlates committed WAL rows to event UUID and xid8, and rejects mismatched WAL xid, xid8 low bits, event identity, system identifier or timeline.

### 4.3 Durable ledger and slot-ack ordering

The decoder writes an immutable commit-time ledger row to a separately protected durable ledger store containing event UUID, source system identifier, timeline, full xid8, WAL xid, commit LSN, commit timestamp, scope, stream, sequence, event digest, decoder version and ledger insertion identity.

Required order:
1. Decode source WAL commit record and exact event/outbox rows.
2. Validate transaction/event identity and obtain timestamp from the WAL commit record.
3. Commit immutable ledger row to durable ledger store.
4. Read back and verify committed ledger row and unique key/digest.
5. Only then advance logical slot confirmed_flush_lsn / acknowledge source WAL.

Never acknowledge or advance the slot before ledger commit and read-back verification. Crash after step 3 but before step 5 is idempotently replayed against the same event key and commit tuple. Crash before step 3 replays retained WAL. No worker clock or later timestamp can substitute.

### 4.4 WAL retention, crash recovery and truncation

The logical slot restart LSN pins required WAL until ledger acknowledgement. Monitor slot lag, retained WAL volume, disk headroom and decoder health. If the ledger cannot keep pace or the WAL safety threshold is reached, governed approvals/promotions/rollbacks fail closed before required WAL can be lost. Do not advance the slot to restore disk space while unledgered events exist.

Restart replays from the last acknowledged slot position. Commit-timestamp metadata truncation is irrelevant while the WAL commit record remains retained and decoded. Wraparound uses stored full xid8, source system identifier, timeline and commit LSN; 32-bit xid is only a correlation component. Ledger uniqueness includes source system identifier + timeline + commit LSN + event UUID.

Backups preserve durable ledger and logical-slot restart/ack position. WAL archives needed to replay unledgered commits are retained for the backup/restore horizon. Restore reconciles each event/outbox row against immutable ledger entry and source timeline; it never generates a new timestamp for an old event.

If original WAL or ledger entry is unavailable, original commit time is unknown. The stream remains unanchored and authority-expanding operations fail closed. No restore, insertion, worker, current or provider timestamp may be substituted. Recovery requires a separately approved new stream/contract with continuity evidence. Loss of all original WAL before ledger capture is an unrecoverable integrity incident, not permission to fabricate a timestamp.

## 5. M-01 — Terminal quarantine

Incident reconciliation changes incident disposition only. It MUST NOT change old stream condition from quarantined to healthy, pending or any other value. For a quarantined prior stream, security.incident-reconciled encodes prior_stream_condition=quarantined and resulting_stream_condition=quarantined. A new stream identity and contract is the only recovery path. Historical per-event verification facts remain unchanged.

## 6. M-03 — Dataset descriptor digest without changing rollback v2

Rollback-request v2 remains frozen and binds target_dataset_snapshot_object_id and target_dataset_snapshot_object_version_id, raw byte length and raw dataset SHA-256.

The protected immutable dataset registry stores object ID/version, exact canonical descriptor bytes (RFC 8785 UTF-8, no BOM/trailing newline), descriptor schema token, descriptor SHA-256, raw stored byte length and digest, and tenant/BU/candidate/model bindings.

At creation, approval and execution, retrieve the exact registry record by request-bound object ID/version, recompute descriptor digest from retained canonical descriptor bytes, verify descriptor schema and every request-bound field, and independently hash exact raw dataset bytes. The descriptor digest is therefore obtained through the immutable version-bound registry record; it is not a missing request field and MUST NOT be added to rollback-request v2. Missing bytes/version or digest mismatch invalidates the request and denies execution.

## 7. Independent acceptance evidence

| Finding | Closure artifact | Evidence required before acceptance |
|---|---|---|
| H-01 | §1 and lock-order JSON | Two-session lock/race/deadlock tests including FK, trigger, RLS and multi-scope paths |
| H-02 | §2 | PostgreSQL 16 extension/broker prototype, one-time assertion/replay tests, partial unique active-backend constraint and stale-backend denial |
| H-03 | §3 and audit schemas | Complete D-02.1/D-07 matrix, exact schema selection, positive/negative fixtures, two independent reconstructions |
| H-04 | §4 | WAL decoder/slot/ledger crash-replay, no-ack-before-ledger proof, restart, wraparound, WAL archive and restore tests |
| M-01 | §5 | Attempted quarantine-clearing transition rejected |
| M-02 | Schema and fixture artifacts | All schemas parse and fixtures pass/fail as labelled |
| M-03 | §6 | Descriptor digest independently reproduced from immutable bytes at all lifecycle points |
| M-04 | §3.3–3.4 | Null/absence and state-transition fixtures for every event |

No finding is accepted by author declaration. These documents and static fixtures define the contract only. Implementation evidence and independent review remain separate.

## 8. Governance

Documentation-only design closure. No PostgreSQL extension, broker, schema, migration, role/privilege change, serializer, audit writer, WAL decoder, ledger, outbox worker, external anchor provider or production deployment is implemented or authorized.

PR #20 MUST remain Draft, open and unmerged. Synthetic-data-first, customer-hosted/customer-controlled, advisory-only PoV boundaries remain unchanged. No live IBEDC telemetry, SCADA/ADMS/DMS control, switching, dispatch, meter commands, billing adjustments/refunds, journal postings or automatic production model deployment is authorized. F-03/F-05 and production certification remain open pending separate implementation and independent acceptance gates.
