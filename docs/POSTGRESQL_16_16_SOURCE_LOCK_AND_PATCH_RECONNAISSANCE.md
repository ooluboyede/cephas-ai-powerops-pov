# Gate 0.6.3.2 — PostgreSQL 16.16 source lock and patch reconnaissance

**Baseline ID:** CEPHAS-PG16-16.16-2026-11  
**Status:** Source baseline pinned; CEPHAS source patch and broker are not yet implemented.  
**Required major:** PostgreSQL 16, as required by the authoritative Gate 0.6.3.2 design.

## A. Exact upstream baseline

| Field | Locked value |
|---|---|
| Upstream Git mirror | https://github.com/postgres/postgres.git |
| Release tag | REL_16_16 |
| Tag object | Direct commit, not an annotated tag |
| Exact commit | c0534eb02de050ac1035ad7b3ad7c3f02980f153 |
| Commit subject/date | Stamp 16.16. / 2026-11-09 |
| Official release archive | https://ftp.postgresql.org/pub/source/v16.16/postgresql-16.16.tar.bz2 |
| Official SHA-256 sidecar value | 9d5cd8633043b75740d5d59749c6b7365e6aeb53c47098b1a5e80bb18f87881a |
| Release date | 2026-11-12 |
| Upstream support end | 2028-11-09 |

PostgreSQL's versioning policy lists 16.16 as the current supported 16.x minor on 2026-11-20. The release announcement identifies security and bug fixes. The pin is a fixed release, not the moving REL_16_STABLE branch.

**Signature caveat:** GitHub reports the tag target commit as unsigned. Do not claim a signed Git commit/tag. Before building, retrieve the release archive and SHA-256 sidecar from the official PostgreSQL FTP host, verify with sha256sum -c, preserve both files and retrieval metadata, and compare the extracted source against the pinned tag. A checksum fetched over TLS is not a detached publisher signature.

### Reproducible acquisition

~~~bash
git init postgresql-16.16-cephas
cd postgresql-16.16-cephas
git remote add upstream https://github.com/postgres/postgres.git
git fetch --no-tags upstream refs/tags/REL_16_16
git checkout --detach c0534eb02de050ac1035ad7b3ad7c3f02980f153
test "$(git rev-parse HEAD)" = "c0534eb02de050ac1035ad7b3ad7c3f02980f153"

curl --fail --location --output postgresql-16.16.tar.bz2 \
  https://ftp.postgresql.org/pub/source/v16.16/postgresql-16.16.tar.bz2
curl --fail --location --output postgresql-16.16.tar.bz2.sha256 \
  https://ftp.postgresql.org/pub/source/v16.16/postgresql-16.16.tar.bz2.sha256
sha256sum -c postgresql-16.16.tar.bz2.sha256
~~~

The build record must preserve source commit, archive checksum, compiler/toolchain versions, configure flags, crypto/TLS providers, patch-series digest and resulting binary digests. Never build from a moving branch, distro-patched package or floating container tag.

## B. Upstream source files inspected

The following blob SHAs are provenance anchors for the exact upstream commit; none has been modified.

| Path | Blob SHA | Responsibility |
|---|---|---|
| src/backend/tcop/postgres.c | 7ba3e283dc3f3442cd3f04c30540d0277f74eb02 | SocketBackend and PostgresMain; Q/P/B/E/F dispatch; command transaction helpers |
| src/backend/tcop/fastpath.c | 2f70ebd5fae625da59cba05ae94f8762544d3441 | Direct FunctionCall lookup, ACL checks and invocation |
| src/backend/libpq/auth.c | ea149e478b08040be8cb199f38dcb111ebdb84be | HBA-selected authentication and AuthenticationOk |
| src/backend/libpq/auth-sasl.c | 684680897bcd39031a13a92b6f75afa219669499 | Generic SASL mechanism list, initial response, continuation and final |
| src/backend/libpq/hba.c | 75fd2a88939bb18881782b826f34d5c2ee646744 | pg_hba.conf method-token parser and names |
| src/include/libpq/hba.h | 189f6d0df24815e508e359993b893a68c1dadaa0 | UserAuth enum and HBA types |
| src/include/libpq/sasl.h | 7a1b1ed0a00c0c74f93a9695eaf48de4e7eef362 | Backend SASL mechanism interface |
| src/include/libpq/libpq-be.h | 3b2ce9908f81d685af82de64ed554524ac38f5a7 | Port/backend connection state |

## C. Confirmed patch integration points

### Authentication/SASL

1. auth.c: ClientAuthentication(Port *) dispatches the HBA auth method and emits AuthenticationOk. Add a dedicated cephas-broker method; do not treat stock SCRAM/password/certificate authentication as governed authentication.
2. auth-sasl.c: CheckSASLAuth() already handles PostgreSQL SASL packet framing. Reuse it with a dedicated CEPHAS mechanism instead of writing a parallel framing parser.
3. hba.c and hba.h: add a dedicated HBA token, enum and canonical method name. Governed roles must not fall back to password, SCRAM or certificate-only authentication.
4. sasl.h: implement pg_be_sasl_mech for CEPHAS-BROKER-V1.
5. Proposed auth-cephas.c: challenge generation, closed assertion parsing, signature/key/revocation validation and backend-local verified-auth state; add to libpq Makefile.

### Protocol dispatch/registration

1. postgres.c: SocketBackend() reads/validates the frontend message; PostgresMain() dispatches Q/P/B/E/F. Add the fail-closed gate after message read and before the dispatch switch invokes any handler.
2. Q reaches exec_simple_query(); P reaches exec_parse_message(); B reaches exec_bind_message(); E reaches exec_execute_message(); F reaches HandleFunctionRequest().
3. fastpath.c performs FunctionCall OID lookup, ACL checks and invocation. The authoritative gate must precede this handler.
4. postgres.c already has start_xact_command()/finish_xact_command(), backed by StartTransactionCommand()/CommitTransactionCommand(). The server-owned registration transaction must be separate from user transaction state and commit before parsing, planning or executing the pending user message.
5. Proposed cephas_session.c/private header: backend-local registration state machine and protected internal transaction. Exact implementation and transaction API require regression proof. No application SQL function, GUC, startup parameter, user-defined function or untrusted trigger may confer registration authority.

## D. Implementation sequence

1. Reproduce an unmodified PG16.16 build and record toolchain, configure options, crypto/TLS providers, regression results and binary digest.
2. Add dedicated cephas-broker HBA method and CEPHAS-BROKER-V1 SASL mechanism.
3. Add backend-local verified assertion state, inaccessible to SQL/GUC/startup parameters and safely cleared on failure/disconnect.
4. Implement server-owned registration transaction before Q/P/B/E/F dispatch: lock and recheck identity/epochs; atomically insert assertion JTI, IdP issuer/JTI and one active backend registration; commit before dispatch.
5. Add fail-closed execution gate and ExecutorStart/ProcessUtility defence-in-depth.
6. Implement customer-controlled broker for fresh IdP auth, mapping resolution and Ed25519 assertion signing.
7. Add real-wire adversarial tests: first Q/P/B/E/F, BEGIN/ROLLBACK, multi-statement Q, prepared statements, portals, COPY, registration abort/uncertain commit, user abort after registration, duplicate/replayed JTIs, challenge replay/expiry, epoch changes, concurrent duplicate registration, PID reuse, fallback auth, cleanup boundary and backup/restore.
8. Run assertion-enabled build, full upstream check-world, focused TAP/protocol tests, sanitizers/fuzzing where available, and independent source review.

## E. Design blockers before C implementation

These contracts are not sufficiently defined by the current design closure. They must be closed in a separate sub-gate rather than guessed in code.

1. **TLS channel binding:** specify the exact binding primitive and bytes, supported TLS versions/providers, and how the broker obtains and signs the same binding. “TLS-connection-bound” alone is not implementable.
2. **Crypto provider:** decide whether OpenSSL is mandatory for Ed25519 verification or provide a separately audited provider. Governed authentication must fail build/configuration if verification is unavailable.
3. **Canonical JSON:** specify a duplicate-key-rejecting parser and closed-field validation before RFC 8785 canonical verification. Do not assume jsonb preserves duplicate-key evidence.
4. **Trust/key storage:** specify broker public-key loading, rotation/revocation, cluster identity, reload atomicity and fail-closed behavior.
5. **Protected registration storage:** specify table/catalog ownership, bootstrap/migration, lock order, privilege boundary, crash recovery and how C code writes protected rows without user SQL/triggers.
6. **HBA governance binding:** specify how a role is classified as governed and prevent earlier/more-specific HBA rules from selecting a weaker method.
7. **Parallel workers:** specify which non-secret registration facts may propagate; never serialize the assertion, private data or replay authority into worker state.

## F. Boundaries and acceptance

This work does not implement F-06's logical-decoding consumer/failover prototype. It does not enable live IBEDC telemetry, SCADA/ADMS/DMS control, switching, dispatch, meter commands, billing adjustments/refunds, journal postings or automatic production model deployment. Customer-hosted/customer-controlled, synthetic-data-first and advisory-only boundaries remain.

Do not mark runtime F-02 resolved until the exact PG16.16-derived patch builds reproducibly, a broker interoperates over real PostgreSQL wire connections, all adversarial tests pass, upstream regression tests pass and an independent reviewer accepts the exact source commit. PR #20 remains Draft/open/unmerged.
