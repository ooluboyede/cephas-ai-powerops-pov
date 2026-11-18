# Gate 0.6.1 — Trusted Model Artifact Verification Integration

## Finding addressed

F-03 identified a trust-boundary gap in the 0.5.5 registry: candidate registration accepted a caller-supplied object with `artifactVerification.verified === true`. The receipt shape was documented as trusted, but the registry did not itself invoke the Gate 0.5.4 Ed25519 verifier. A caller able to reach registration could therefore assert verification without proving that the bytes were signed by a trusted publisher.

## Implemented in this gate

- Added `src/trusted-artifact-verifier.js`, which constructs a publisher key ring from trusted configuration supplied by the trusted composition root.
- Publisher IDs are strictly validated; public keys must be Ed25519 public keys. The key ring is copied into a private Map and is not accepted from candidate/artifact metadata.
- The verifier computes SHA-256 over the exact artifact bytes and invokes the existing Gate 0.5.4 `verifyArtifactBeforeLoad` function.
- Signature encoding must be canonical base64 and exactly 64 decoded bytes. Unknown publisher IDs, malformed signatures, invalid signatures and modified bytes fail closed.
- JSON parsing occurs only inside the fixed verifier callback after digest and Ed25519 verification. No candidate-supplied deserializer or public key is accepted.
- The parsed artifact schema, algorithm, model version, feature schema and dataset digest are validated.
- `createRegistry` now requires an injected trusted verifier whenever artifact verification is mandatory.
- `registerCandidate` accepts raw bytes, signature and publisher key ID. It invokes the injected verifier itself, compares verified artifact metadata to the signed model manifest, computes/stores the artifact digest from verified bytes, and constructs the verification receipt internally.
- A caller-provided `artifactVerification` receipt or `artifactSha256` cannot satisfy the mandatory verification path.
- Added integration tests for valid signatures, missing verifier configuration, forged caller receipts, malformed signatures, tampering, unknown publishers, manifest/artifact mismatch and the existing approval/release/rollback controls.

## Trust and operational boundaries

- The trusted composition root remains security-critical: it must instantiate the verifier with a separately governed, pinned publisher public-key configuration. Candidate data must never control that configuration.
- This gate does not implement production publisher private-key custody, HSM/KMS signing, key rotation/revocation distribution, multi-tenant key governance or a customer-specific trust-store administration workflow.
- The verifier receipt is an in-process result. It is not a cryptographic attestation signed by a separate verifier service.
- The registry and event chain remain the existing in-memory reference implementation; persistence, authenticated approvals, external WORM anchoring and non-repudiation remain separate gates.
- Verification proves byte integrity and publisher-key possession, not model quality, safety, operational suitability, regulatory compliance or customer approval.
- Synthetic data only. No customer or IBEDC operational telemetry is used.
- Advisory-only. No SCADA/ADMS/DMS commands, switching, dispatch, meter commands, billing adjustments, refunds or journal postings. No automatic model deployment or operational activation.

## Acceptance criteria

1. Registry construction fails closed when mandatory artifact verification has no trusted verifier.
2. Candidate registration cannot be satisfied by a caller-created `verified: true` receipt.
3. Exact signed bytes are hashed and signature-verified before JSON parsing.
4. Wrong publisher, malformed signature, altered bytes and manifest/artifact metadata mismatch are rejected.
5. Valid signed bytes from a configured Ed25519 publisher produce an internally constructed receipt bound to the computed artifact SHA-256, publisher key ID and verifier version.
6. Existing approval separation, promotion eligibility, release and rollback tests remain green.
7. Exact-head GitHub Actions CI passes; independent security review remains required before F-03 can be closed.

## Validation status

Implementation and tests are committed on the isolated branch. CI and independent review are pending. This gate does not certify production readiness and does not close F-03 until exact-head CI and independent review are complete.
