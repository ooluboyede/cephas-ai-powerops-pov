# Gate 0.6.0 — Enterprise Authentication and Token Authority

## Gate status

**Status: design baseline committed; implementation and acceptance tests not yet complete.**

This gate addresses independent security finding F-02. It is intentionally provider-neutral: no identity provider, OAuth/OIDC vendor, token format profile, customer IdP, or production key-management service is presumed to have been selected.

## Objective

Establish a trusted enterprise identity boundary for the PowerOps PoV so that user and service identities, authentication assurance, token issuance, authorization scope, expiry, revocation, and key lifecycle are controlled by a trusted authority—not by caller-supplied headers, request bodies, browser state, or self-asserted tenant claims.

## Non-negotiable security properties

1. **Trusted authentication:** authenticate through a configured upstream enterprise identity provider using a documented OIDC Authorization Code flow with PKCE for interactive users. Do not accept password collection or direct password verification by PowerOps.
2. **Issuer and audience validation:** validate signature, exact configured issuer, intended audience, allowed algorithm, expiry, not-before, issued-at, and token identifier. Reject the none algorithm, algorithm confusion, unknown key IDs, malformed claims, and tokens from untrusted issuers.
3. **Server-side authorization:** resolve PowerOps subject, tenant, business unit, role and permissions from trusted server-side mappings. Do not authorize from caller-controlled tenant/business-unit/role headers or unverified token claims.
4. **Scope enforcement:** bind the authenticated principal to an enabled tenant + business-unit assignment and enforce that assignment at the database boundary already established by Gate 0.5.8–0.5.11. Missing, ambiguous, disabled or stale assignments fail closed.
5. **Short-lived credentials:** define a short access-token lifetime (initial target 5 minutes, configurable only within a bounded policy); no long-lived browser bearer tokens or refresh tokens in local storage. Refresh/session renewal must be server-controlled and revocable.
6. **Revocation:** support principal disablement, session revocation and signing-key retirement. Revocation checks must have a documented maximum propagation interval and fail-closed behavior when the authority is unavailable.
7. **Service identities:** separate machine-to-machine identity from human user sessions. Use workload identity or mutually authenticated service credentials; never reuse a human token as a service credential.
8. **Key custody:** use an injected signing/verifying interface with an external KMS/HSM or approved secret manager in production. Local ephemeral keys may be used in tests only. Never commit private keys, production secrets or customer credentials.
9. **Auditability:** record authentication success/failure, issuer/subject identifiers (privacy-minimized), token issuance/rejection, authorization denial, scope changes, revocation and key lifecycle events. Never log raw tokens, authorization codes, client secrets or private keys.
10. **No privilege escalation:** roles and permissions are least-privilege server mappings; user-controlled claims, query parameters and request payloads cannot grant roles or widen scope.

## Proposed implementation slices

### 0.6.0-A — Threat model and trust-boundary specification
- Document human and service actors, trust boundaries, data flows and abuse cases.
- Define the provider adapter contract and configuration requirements.
- Define claim mapping and server-side principal/scope resolution.
- Record unresolved customer-specific choices rather than inventing defaults.

### 0.6.0-B — Authentication adapter and protocol validation
- Implement a provider-neutral OIDC discovery/JWKS adapter behind an explicit configuration interface.
- Validate Authorization Code + PKCE callback state, nonce, issuer, audience, signature and time claims.
- Pin allowed signing algorithms and reject downgrade/algorithm-confusion cases.
- No IdP-specific production configuration until the customer/CEPHAS deployment selects a provider.

### 0.6.0-C — Token authority and session lifecycle
- Implement minimal, short-lived access-token issuance and validation.
- Resolve roles and tenant/business-unit scope from server-side mappings.
- Add session identifiers, revocation state and bounded revocation propagation.
- Keep signing operations behind a KMS/HSM adapter; local test signer only.

### 0.6.0-D — Service identity
- Define separate machine identity and token exchange/client-authentication contract.
- Require workload identity or mTLS-backed client authentication in production.
- Deny service tokens access to human-only actions unless explicitly granted.

### 0.6.0-E — Adversarial tests and reviewer handoff
- Add positive and negative tests for signature tampering, wrong issuer/audience, expired/not-yet-valid tokens, none algorithm, unknown key ID, key rotation, revoked sessions, disabled principals, missing/ambiguous scope, role escalation, tenant/BU substitution, replay/state/nonce mismatch and service/human token confusion.
- Exercise DB scope binding with the existing SESSION_USER-based boundary.
- Produce an exact-commit test report and independent F-02 review brief.

## Acceptance criteria

- No request is authorized solely by a caller-provided identity, role, tenant or business-unit value.
- Only a configured trusted issuer and explicit audience are accepted.
- Invalid, expired, revoked, malformed, incorrectly scoped or unverifiable credentials fail closed.
- Principal and tenant/BU scope are resolved server-side and map to the existing database-scoped identity boundary.
- Human and service identities are distinct and tested against privilege confusion.
- Key rotation and revocation behavior are tested, including unknown and retired keys.
- No raw token, authorization code, client secret or private key appears in logs or repository history.
- Tests cover both successful authentication and adversarial negative cases.
- Independent reviewer explicitly accepts F-02 against an exact commit before the finding is closed.

## Explicit exclusions

- No identity-provider vendor is selected by this gate.
- No production KMS/HSM, secret manager, customer IdP tenant or customer credentials are provisioned by this repository-only gate.
- No claim of production SSO certification or regulatory compliance.
- No SCADA/ADMS/DMS control, switching, dispatch, meter commands, billing adjustments, refunds or journal postings.
- No change to the advisory-only product boundary.

## Dependencies and finding register

- F-01: closed; do not reopen without new evidence.
- F-02: target of Gate 0.6.0; currently open.
- F-03: trusted model-artifact verifier integration; remains open and separate.
- F-04: fresh-cluster role reconstruction; awaiting independent acceptance of PR #12 exact head 1d6b3fc34068c0e160bc4c3f51bcc84ae52b26a6.
- F-05: independently anchored WORM audit evidence; remains open.
- F-06: customer disaster recovery, measured RPO/RTO and full environment recovery; remains open.

Gate 0.6.0 is not complete until implementation, CI, adversarial testing and independent review are all recorded.