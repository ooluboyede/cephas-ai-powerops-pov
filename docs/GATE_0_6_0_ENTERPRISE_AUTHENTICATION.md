# Gate 0.6.0 — Enterprise Authentication and Token Authority Foundation

## Objective
Replace the PoV's static, server-configured HMAC bearer-token foundation with a provider-neutral external-identity boundary and a short-lived CEPHAS session-token authority. No identity provider has been selected or integrated in this gate.

## Implemented contract
- A mandatory injected external assertion verifier. It must validate the chosen IdP's signature, issuer, audience, expiry, not-before, nonce/state and approved authentication context before returning a verified issuer/subject pair. The adapter is not supplied by this gate.
- A mandatory server-side principal resolver maps the verified issuer + subject to tenant, business unit and approved CEPHAS roles. Client-supplied roles or scope are never accepted.
- Short-lived HS256 session tokens use an explicit issuer, audience, key id, subject, tenant, business unit, role list, issued-at, not-before, expiry and unique token id.
- A key ring supports verification with retained previous keys while new sessions use the configured active key. Retiring a key invalidates sessions signed by it.
- A mandatory revocation-store adapter is checked on every session verification. The adapter must be durable and shared by all application instances; this repository includes only test fixtures, not a production persistence adapter.
- Authorization resolves permissions from the server-defined role map and fails closed.

## Security boundary / not yet implemented
- No OIDC/SAML provider-specific adapter, login callback, PKCE/state/nonce browser flow, MFA policy, upstream IdP, production key vault/HSM/KMS, durable revocation database adapter, service-to-service workload identity or operational key-rotation runbook is included.
- Do not deploy using the test adapters. No secrets belong in source control.
- Integrate the resulting identity only with the existing per-tenant/business-unit PostgreSQL login-pool resolver. PostgreSQL SESSION_USER remains the final database scope authority; JWT claims do not override database identity.
- This gate does not close F-02 until the independent reviewer validates the concrete IdP adapter, key custody/rotation and durable revocation implementation.
- F-01 remains closed. F-04 remains separately open pending independent review of PR #12. F-03, F-05 and F-06 remain open.

## Acceptance tests
Run `npm test`. Unit tests cover rejected external assertions, server-mapped scope/roles, signed-claim tampering, revocation, expiry, issuer/audience/lifetime enforcement and fail-closed construction.
