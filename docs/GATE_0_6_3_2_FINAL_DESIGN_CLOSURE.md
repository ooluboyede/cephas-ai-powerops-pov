# Gate 0.6.3.2 — Final design-closure contract

**Authority:** This is the single authoritative closure layer, amended by §9 for the latest independent reassessment. §9 controls over earlier inconsistent wording.
**Status:** Normative design amendment only. Runtime prototype and implementation acceptance remain outstanding.
**Scope:** H-01–H-04 and M-01–M-04.
**Precedence:** This document and §9 supersede conflicting D-02.1/D-02.2, D-07, D-09 and D-10 wording for the subjects expressly covered. Unaffected D-05/D-06 requirements remain in force.
**Artifacts:** schemas/gate-0.6.3.2/lock-order.v1.json, lock-concurrency-fixtures.v1.json, audit-registry-v2.schema.json and fixture-catalog.v1.json.

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

The only acceptable path is a customer-controlled authentication broker plus a trusted PostgreSQL authentication extension. The extension validates the assertion during authentication and retains a backend-local, non-SQL-mutable pending-authentication context. A trusted pre-execution hook then materializes the protected registration before the first user SQL command is allowed to execute. No SQL-callable registration API exists for application, runtime, verifier, approver or broker roles. The broker MUST NOT authenticate a user and then ask that user's SQL session to call a registration function.

The broker creates one dedicated physical PostgreSQL backend per authenticated principal session. Transaction pooling is prohibited. Session pooling is permitted only while the same authenticated client remains bound to the same physical backend; a backend is never reassigned to another principal.

### 2.2 Fresh authentication and signed assertion

For every new backend, the broker MUST validate a fresh upstream IdP assertion: signature, exact issuer, audience, subject, iat/nbf/exp, unique jti, auth_time, required MFA/authentication context and current revocation status. auth_time MUST be later than the login binding's most recent re-enable/credential-rotation time. Token refresh or cached broker session is not fresh authentication.

The broker resolves exactly one active protected mapping and current mapping version, login epoch, credential generation and canonical human principal. During the PostgreSQL authentication exchange, the trusted extension supplies a server-generated single-use challenge bound to the new backend's server-observed database OID, role OID, PID and backend start time.

The broker signs a closed assertion containing exactly: assertion_schema, issuer, audience_cluster_id, database_oid, role_oid, backend_pid, backend_start, server_challenge, assertion_jti, idp_issuer, idp_subject, idp_jti, login_binding_id, mapping_id, mapping_version, login_epoch, credential_generation, authn_generation, auth_time, issued_at, expires_at and broker_key_id.

Assertion lifetime is at most 30 seconds. It is bound to one PostgreSQL cluster and one backend. Signature is Ed25519 over RFC 8785 canonical UTF-8 bytes with domain prefix CEPHAS-POWEROPS-SESSION-REGISTRATION-V1 followed by 0x00. Broker keys are customer-controlled, versioned and pinned in extension configuration. Unknown, expired or revoked keys fail authentication.

### 2.3 Extension verification and atomic one-time consumption

During authentication completion, the extension independently derives live database OID, SESSION_USER role OID, PID and backend start from PostgreSQL server state. It verifies exact equality with the assertion and verifies the challenge is outstanding, unexpired and issued for this backend. It stores the verified assertion only in backend-local extension memory; it MUST NOT expose or accept that context through GUCs, startup parameters, temporary tables or caller-controlled SQL arguments.

Before the first user SQL command executes, an extension-owned pre-execution hook covering both executor and utility-command paths MUST run one protected registration transaction in the same transaction context as that first command:
- locks login binding and mapping at ranks 0–1 and session/epoch state at rank 2;
- rechecks active status, current login epoch, mapping version and credential generation;
- inserts assertion_jti and idp_jti into protected replay tables with unique constraints;
- inserts exactly one active session-registration row;
- commits replay consumption and registration atomically with the first command.

No user command may execute if the hook cannot complete the registration write. If the first command's transaction aborts, the registration and replay inserts roll back together; the backend-local assertion remains bound to that same backend only and the hook may retry on a later command after rechecking current epochs. It cannot be transferred to another backend or re-issued to an already authenticated backend. If validation, a unique constraint, insert or commit fails, the command is rejected and the extension terminates the backend. Failed registration MUST NOT leave a reusable assertion or active registration.

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

Required tests: valid, expired, wrong-cluster/database/role/PID/backend-start, challenge replay, assertion-JTI replay, IdP-JTI replay, wrong issuer/subject, stale auth_time, old credential generation, revoked IdP token, revoked broker key, mapping/epoch race, concurrent duplicate assertion, first-command hook on SELECT and utility commands, first-command transaction abort/retry, failed registration commit, backend termination, PID reuse and attempted registration from an already authenticated stale backend. The last test must prove no SQL-callable stale-session path exists. The PostgreSQL 16 prototype must demonstrate that the chosen pre-execution hooks can enforce this ordering without permitting a command to run before registration.

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
| verifier_identity.created / activated / changed / suspended / disabled / revoked | trust.verifier-identity-created / activated / changed / suspended / disabled / revoked |
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

The companion registry JSON Schema contains the common envelope, manifest and all 55 event-specific v2 payload schemas. The fixture catalog contains 55 positive event payloads, 278 exact negative payload variants, mutation-reconstruction negative scenarios, and a 1,404-byte canonical mutation-manifest golden fixture with SHA-256 6eaa3b02ca572028fc70a71defeeb5014ccd64271bc0d2fa6b25f5b7e2e63ea5. An author-side JSON parse and fixture-structure preflight found zero structural errors; this is not a substitute for a standards-compliant JSON Schema validator, two independent canonicalizers/verifiers or PostgreSQL concurrency/recovery tests. A row is not implementation-closed until those independent tests pass.

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


## 9. Reassessment remediation — binding amendments

This section is a normative amendment responding to the independent rejection of commit `eefae3b4903633ba618e412e99a310aae1045796`. It controls over earlier inconsistent statements in this file and D-02.1/D-02.2 only for the subjects expressly amended below. It does not claim runtime proof.

### 9.1 F-01 — Protocol-complete execution gate (PostgreSQL 16)

The earlier extension-only proposal is withdrawn as insufficient. ExecutorStart and ProcessUtility hooks are defence-in-depth, not the sole enforcement boundary. The supported target is a customer-maintained, source-pinned PostgreSQL 16 server build carrying a reviewed CEPHAS protocol/authentication patch. An unpatched stock PostgreSQL 16 server is not a supported governed deployment for this control.

The patch MUST gate every execution-bearing frontend protocol path before user code runs:
- Simple Query (`Q`): registration gate inside the command transaction before parsing/executing the first statement.
- Extended Query Execute (`E`): registration gate after the portal execution transaction has begun and before portal execution.
- Function Call (`F`): registration gate in the direct FunctionCall handler before function OID lookup/invocation; a first-message FunctionCall MUST be rejected unless registration can be committed atomically with that call.
- Utility statements, including DDL and COPY command setup, remain covered by the Q/E execution gate and ProcessUtility defence-in-depth. COPY data messages cannot initiate a command without the already-gated Q/E command.

The protocol dispatcher MUST fail closed for any execution-bearing message type not explicitly enumerated in the reviewed patch. ExecutorStart and ProcessUtility hooks independently assert that the backend has a committed registration before proceeding. Prepared statements, portals, simple-query multi-statements, extended-query pipelining, COPY and direct FunctionCall receive dedicated tests. This patch-level gate—not a claim that extension hooks see every protocol path—is the authority boundary.

### 9.2 F-02 — Exact broker authentication exchange

The prior generic authentication-extension wording is replaced with a named custom SASL mechanism, `CEPHAS-BROKER-V1`, implemented in the same pinned PostgreSQL 16 source patch. It is not claimed to be registerable by a loadable extension alone.

Sequence:
1. The customer-controlled broker is the PostgreSQL protocol client and opens a new dedicated physical backend connection over verified TLS. It has already performed fresh IdP authentication and resolves the one active protected identity mapping.
2. During PostgreSQL startup authentication, the patched server selects only `CEPHAS-BROKER-V1` for governed roles and emits a server-generated 256-bit nonce plus cluster ID, database OID, role OID, backend PID and backend start timestamp in the SASL challenge. The challenge is bound to the TLS connection and expires after 30 seconds.
3. The broker returns a broker-key-signed Ed25519 assertion containing the exact challenge tuple, IdP issuer/subject/JTI, login-binding ID, mapping ID/version, login epoch, credential generation, authn generation, auth_time, issued_at, expires_at and broker key ID. Signature preimage is RFC 8785 canonical UTF-8 with the existing domain prefix `CEPHAS-POWEROPS-SESSION-REGISTRATION-V1\0`.
4. The patched server verifies the signature, key status, challenge, expiry and exact server-observed backend tuple before AuthenticationOk. It stores the verified assertion only in backend-local memory. No GUC, startup parameter, temporary table or SQL-callable registration function is accepted as authority input.
5. The protocol execution gate described in §9.1 materializes registration and replay consumption in the same transaction as the first Q/E/F command. If that transaction aborts, both inserts roll back; the assertion remains bound to that backend and may retry only after rechecking current epochs. A failed registration terminates the backend.

The patch MUST reject password, SCRAM, certificate-only or other fallback authentication for governed roles unless those methods are explicitly disabled by customer policy. A broker reconnect creates a new physical backend and repeats fresh authentication. Transaction pooling and backend reassignment are prohibited. No already-authenticated backend can request a replacement challenge or re-register itself.

### 9.2.1 F-02 — Corrected registration linearization and complete SASL contract

**This subsection supersedes §9.2 step 5 and every earlier statement requiring registration/replay consumption to commit in the same transaction as the first user command.** The same-transaction design is withdrawn because an explicit first `BEGIN` would leave registration uncommitted while the next command requires committed registration.

#### A. Single registration linearization point

The registration linearization point is the successful durable COMMIT of one server-owned registration transaction, executed by the patched PostgreSQL backend **before it begins, parses, plans or executes any user SQL command**. Registration is not part of the user's transaction and is never rolled back by user `ROLLBACK`.

The protocol dispatcher MUST invoke this transaction before handing any user-originated message to a command handler that can parse, plan, execute, invoke a function, or cause a user-visible side effect. The minimum guarded message set is Simple Query `Q`, Parse `P`, Bind `B`, Execute `E`, and direct FunctionCall `F`. The gate runs before `exec_simple_query`, parse analysis/planning, portal binding/execution, or function OID lookup/invocation. ExecutorStart and ProcessUtility remain defence-in-depth. COPY data messages are accepted only after a gated COPY command. Unknown or future execution-bearing message types fail closed until explicitly added to the reviewed patch.

The server MUST run registration while the backend is idle and no user transaction or portal execution transaction is active. The patch uses a narrowly scoped internal registration mode, starts a top-level transaction, writes the protected registration and replay rows, commits, clears the internal mode, and only then dispatches the original frontend message. Internal registration code MUST NOT call user SQL, user-defined functions, application hooks or untrusted triggers. The internal-mode flag is backend-local and cannot be set by SQL, GUC, startup parameters or the client.

The protected registration transaction MUST lock login binding, identity mapping and session/epoch records in prescribed rank order; recheck active status, login epoch, mapping version, credential generation, IdP revocation cutoff and backend identity; insert assertion JTI and (IdP issuer, IdP JTI) into protected replay tables with unique constraints; insert exactly one active session-registration row bound to cluster/database/role/PID/backend-start/session nonce; and commit all rows atomically.

The successful COMMIT is the sole registration linearization point. No user command is parsed, planned, executed or invoked before it. An explicit first `BEGIN` is dispatched only after registration commits. A first `ROLLBACK` cannot undo registration. A multi-statement `Q` is gated once before its first statement. A first `F` call is gated before function lookup/invocation. Extended-query `P/B` messages are gated before parse/plan work; `E` independently asserts committed registration before portal execution.

#### B. Failure and abort semantics

- If authentication, assertion verification, replay insertion, registration insertion, lock acquisition or registration COMMIT fails, the server MUST return a fatal authentication/authorization error and terminate the backend. It MUST NOT dispatch the pending user message.
- If registration COMMIT outcome is uncertain, the backend MUST terminate without dispatch. A possibly committed registration is harmless because it is bound to the terminated backend; reconnect requires fresh IdP authentication and new assertion/JTIs.
- If registration commits and the subsequent user command fails or its transaction is rolled back, registration and replay consumption remain committed. The same backend may issue a later command only while its live backend identity and captured epochs remain current.
- If the registration transaction aborts, no active registration is left and the backend terminates. Retry requires a new physical backend and fresh upstream authentication.
- The backend-local assertion is consumed exactly once by successful registration. An authenticated backend cannot request a replacement challenge, re-register, or refresh captured epochs.

#### C. Exact PostgreSQL SASL wire exchange

The patched server and customer broker MUST implement this exact exchange for governed roles; no password/SCRAM/certificate fallback is permitted unless a separately versioned policy explicitly excludes that role from this protocol.

1. Server sends AuthenticationSASL (`R`, auth code 10) with the single C-string mechanism `CEPHAS-BROKER-V1\0`, followed by the terminating empty mechanism C-string.
2. Broker sends SASLInitialResponse (`p`) with the mechanism C-string, signed 32-bit network-byte-order initial-response length zero, and no initial-response bytes.
3. Server sends AuthenticationSASLContinue (`R`, auth code 11). SASL data is UTF-8 RFC 8785 canonical JSON with exactly `challenge_schema`, `cluster_id`, `database_oid`, `role_oid`, `backend_pid`, `backend_start`, `nonce_base64url`, `issued_at`, `expires_at`. Nonce is 32 cryptographically random bytes encoded base64url without padding. Challenge is TLS-connection-bound, backend-bound and valid for at most 30 seconds.
4. Broker sends SASLResponse (`p`) whose data is UTF-8 RFC 8785 canonical JSON containing the closed assertion fields from §9.2 plus `idp_expires_at` and `signature_base64url`. The signed preimage is canonical UTF-8 of assertion fields excluding signature, prefixed by exact domain bytes `CEPHAS-POWEROPS-SESSION-REGISTRATION-V1\0`. Assertion binds exact challenge tuple, IdP issuer/subject/JTI/expiry, login-binding ID, mapping ID/version, login epoch, credential generation, authn generation, auth_time, issued_at, expires_at and broker key ID.
5. After signature, key-status, challenge, expiry, issuer/audience, MFA/auth_time, revocation and backend-binding checks pass, server sends AuthenticationSASLFinal (`R`, auth code 12) with exact ASCII SASL data `CEPHAS-BROKER-V1-OK`.
6. Server sends AuthenticationOk (`R`, auth code 0), followed by normal startup completion messages. AuthenticationOk confirms authentication only; it does not mean protected session registration has committed. First `Q/P/B/E/F` remains blocked until §9.2.1(A) commits registration.

Malformed framing, unexpected message order, invalid UTF-8/JSON, duplicate JSON keys, unknown assertion fields, invalid canonicalization, bad signature, wrong TLS/backend tuple, challenge replay, expired challenge/assertion, unknown/revoked broker key, duplicate JTI, stale epoch/version, IdP replay or unsupported fallback MUST produce ErrorResponse with SQLSTATE `28000`, severity FATAL, followed by connection termination. Error details MUST NOT disclose which identity predicate failed.

#### D. Replay retention, cleanup and disaster recovery

The broker assertion MUST include original IdP token expiry as `idp_expires_at`. Assertion and challenge lifetimes are each at most 30 seconds. The verifier accepts no clock-skew grace beyond the explicit customer-configured maximum of 30 seconds; participants MUST use monitored time synchronization.

- Assertion JTI rows are retained until at least `assertion.expires_at + 30 seconds`.
- IdP replay rows keyed by `(idp_issuer,idp_jti)` are retained until at least `idp_expires_at + 30 seconds`.
- Replay rows are durable, append-only during their retention horizon, protected from runtime/broker-role UPDATE/DELETE, and committed synchronously with registration.
- Cleanup may delete a replay row only when database time is strictly later than `retain_until`, through a privileged maintenance function that records cleanup counts and the highest retained/expired horizon. Cleanup MUST NOT shorten a horizon due to token revocation, role disablement or cache eviction.
- The in-memory challenge is single-use and destroyed on success, failure or backend termination. A challenge from one TLS connection/backend cannot be replayed on another.
- Backup/restore MUST preserve every replay row through `retain_until`. After restore, governed authentication remains disabled until replay rows and cleanup high-watermark are restored and verified from a protected backup/WORM replay journal. If completeness cannot be proven, authentication remains fail-closed; operators MUST NOT truncate replay rows or re-enable the broker.
- Failover/restore without provable replay continuity quarantines governed authentication and requires separately reviewed recovery/new-cluster identity procedure. A WAL archive without replay-table commit horizon is insufficient.

#### E. Required PostgreSQL 16 runtime proof

The source-pinned PostgreSQL 16 patch MUST prove with real protocol clients: first `Q`; first `P/B`; first `E`; first `F`; explicit first `BEGIN`; first `ROLLBACK`; multi-statement `Q`; prepared statements/portals; COPY; registration transaction abort; registration COMMIT failure/uncertain commit; user-command abort after registration commit; duplicate assertion JTI; duplicate IdP JTI; replayed challenge; expired challenge/assertion; stale login epoch after disable/re-enable; concurrent duplicate backend registration; stale backend/PID reuse; unsupported SASL fallback; replay cleanup boundary; and backup/restore replay continuity.

**Evidence boundary:** this amendment resolves the specification's transaction-ordering contradiction and defines the wire/replay contract. It does not claim the PostgreSQL C patch or broker implementation exists. Runtime F-02 acceptance remains blocked until the source-pinned PG16 patch and real-protocol tests are present and independently reviewed.

### 9.3 H-03 — Exhaustive authority lifecycle events

Registry v2 explicitly includes these previously omitted transitions:

| Mutation | Event | State transition |
|---|---|---|
| `verifier_key.superseded` | `trust.verifier-key-superseded` | active → superseded; names successor key and reason |
| `accountable_role.suspended` | `authority.accountable-role-suspended` | active → suspended |
| `approval_grant.suspended` | `approval.grant-suspended` | active/pending → suspended |
| `promotion_policy.revoked` | `policy.promotion-policy-revoked` | active → revoked |
| `session_registration.created` | `identity.session-registration-created` | absent → active |
| `session_registration.retired` | `identity.session-registration-retired` | active → retired |

These are separate closed payload schemas and positive fixtures. Suspension, supersession and revocation cannot be smuggled through generic change/retirement events. Registry, fixture and schema catalogues MUST contain exactly one matching entry for every event. New authority mutation types are denied unless registered in a separately reviewed registry version.

### 9.3.1 F-03 — Accountable-role grant is a distinct canonical event

D-02.1's accountable-role mutation vocabulary is closed and maps one-to-one:

| D-02.1 operation | Canonical mutation type | Canonical registry-v2 event |
|---|---|---|
| Appointment | `accountable_role.appointed` | `authority.accountable-role-appointed` |
| Direct grant | `accountable_role.granted` | `authority.accountable-role-granted` |
| Replacement | `accountable_role.replaced` | `authority.accountable-role-replaced` |
| Suspension | `accountable_role.suspended` | `authority.accountable-role-suspended` |
| Removal | `accountable_role.removed` | `authority.accountable-role-removed` |

A direct grant MUST emit `accountable_role.granted`; it MUST NOT be represented as appointment, replacement, generic change or suspension. Appointment MUST emit only `accountable_role.appointed`. The grant payload is a closed, separately registered schema and fixture. It binds the same immutable assignment/principal/role/scope identity fields as appointment, but mutation and event tokens are distinct. Both creation events use absent → active state; operation intent is distinguished by canonical mutation/event identity, not caller interpretation.

The database mutation dispatcher MUST map each D-02.1 operation to exactly its corresponding canonical mutation type before protected state changes. It MUST reject unknown, ambiguous, multi-mapped or unregistered mutation types before writing role-assignment state. Registry, schema, fixture catalogue and mutation dispatcher must contain exactly one entry for each operation above.

### 9.4 F-04 — Enforced scope and state semantics

Every event-specific schema composes the shared `commonScopeConstraints` definition. A global event requires both tenant and BU identifiers to be JSON null; a tenant/BU event requires both to be UUID strings. No event schema may redefine or bypass these constraints.

Login epochs are integers. The semantic verifier and database transition function MUST enforce `resulting_login_epoch > prior_login_epoch`; JSON Schema alone cannot compare two instance values. Approval-grant change is limited to active → active or pending → pending. Suspension and revocation use their own event types. Grant/object versions MUST strictly increase, enforced by the semantic verifier and database transition function. Negative fixtures cover malformed scope, equal/decreasing epochs and suspension through grant-change.

### 9.4.1 F-04 — Manifest expected-event scope is schema-enforced

Every `mutationManifest.expected_events.items` object MUST compose the same `commonScopeConstraints` definition used by event payloads. A global expected event requires `tenant_id=null` and `business_unit_id=null`; a tenant/business-unit expected event requires both identifiers to be UUID strings. Either malformed combination is rejected by the Draft 2020-12 validator itself.

Semantic reconstruction additionally requires each event's local scope to equal its expected-event entry and to be present in the manifest's affected-scope set. This is an enforced schema and reconstruction rule, not an undocumented convention.

### 9.5 F-05 — D-02.1 identity-bootstrap carve-out

Ranks 0–2 are the exclusive identity-bootstrap exception to D-02.1: they may read and lock only protected login-binding, identity-mapping and session-registration/epoch rows required to derive the authenticated principal and complete affected scope set. They MUST NOT read, evaluate, lock or mutate any D-02 eligibility object, candidate, evidence, policy, grant, approval, release, anchor or audit-chain state. After the identity/scope set is resolved, all rank-3 scope mutexes are acquired in canonical tenant/BU UUID byte order. Only after all scope mutexes are held may the transaction read or mutate D-02 eligibility objects at rank 4 or later. This wording is the sole interpretation of D-02.1 and is consistent with the 20-rank machine-readable hierarchy.

### 9.6 F-06 — PostgreSQL 16 WAL consumer and failover boundary

The logical-decoding output plugin is read-only and MUST NOT write the ledger. It only emits committed source transaction identity, commit timestamp, commit LSN and immutable event/outbox rows. A separately running customer-controlled logical-decoding consumer writes the durable ledger to a distinct protected store, reads back and verifies the committed row, and only then acknowledges the source slot. The consumer is idempotent on source system identifier, timeline, commit LSN and event UUID.

PostgreSQL 16 does not provide built-in logical-slot synchronization to a standby. Therefore, if a primary failover cannot prove continuity of the exact logical slot restart LSN, confirmed flush LSN, catalog_xmin horizon, source system identifier and timeline, the old stream is immediately marked unavailable/quarantined and cannot be continued on the promoted standby. A WAL archive alone is not sufficient evidence that logical decoding can be resumed if required catalog history or slot state is missing. The system MUST NOT synthesize old commit timestamps from pg_waldump, worker time or restore time. The old stream remains immutable; recovery starts a new stream identity/anchor contract after independent reconciliation. Seamless PostgreSQL 16 failover is unsupported unless a separate, tested continuity mechanism proves every required slot/catalog/WAL invariant.

### 9.7 M-02 — Standards validation and JCS evidence

CI acceptance requires JSON Schema Draft 2020-12 validation with format assertion enabled for every positive fixture and every negative payload fixture. It also requires two independently implemented RFC 8785 canonicalizers to produce identical canonical UTF-8 bytes and SHA-256 for golden vectors covering UTF-16 property ordering, control-character escaping, number serialization and nested arrays/objects. The new `jcs-golden-vectors.v1.json` is a test corpus, not a claim that independent verification has run. The existing ASCII manifest vector remains unchanged.

### 9.7.1 M-02/M-04 — Mandatory fixture execution and semantic verifier

CI MUST execute every fixture in the catalogue and fail if a fixture is unrecognized, skipped, duplicated by ID or lacks an asserted result.

- Every positive event fixture is passed to its event-specific Draft 2020-12 schema.
- Every schema-negative payload is passed to the same event schema and MUST be rejected.
- Every `semantic-reconstruction` negative is schema-validated and passed to event-to-manifest reconstruction; it MUST be rejected for manifest/event mismatch.
- Every `semantic:` negative is schema-validated and passed to the semantic assertion declared in `x-semanticAssertions`; it MUST be rejected by that assertion, not an unrelated schema failure.
- Every state-transition negative is schema-validated and passed to the lifecycle verifier; quarantine is terminal for a stream identity and reconciliation cannot make it healthy.
- Every manifest golden fixture is schema-validated and canonicalized by both independent JCS implementations; both must reproduce pinned UTF-8 bytes and SHA-256.
- Every mutation-reconstruction negative descriptor is converted into an executable adversarial case: missing/duplicate event, wrong scope, wrong event type/token, actor substitution, manifest digest mismatch, non-contiguous ordering and v1/v2 substitution.

The harness reports and asserts executed fixture totals. A threshold such as `checked >= 200` is insufficient. Every semantic assertion must have at least one valid positive and one schema-valid negative fixture. The four declared assertions cover disablement epoch, re-enablement epoch, grant-change version and grant-suspension version monotonicity.

### 9.8 Evidence boundary and gate disposition

The above closes the identified normative omissions and schema defects at design/artifact level. It does NOT establish that the PostgreSQL 16 source patch, SASL exchange, protocol dispatch guard, transactional registration, lock concurrency, logical-decoding consumer or failover behavior has been implemented or tested. Gate 0.6.3.2 remains **NOT READY for implementation acceptance** until a separate executable PostgreSQL 16 prototype and independent test evidence satisfy §§9.1–9.7. No production deployment, merge or utility-control capability is authorized by this amendment.
