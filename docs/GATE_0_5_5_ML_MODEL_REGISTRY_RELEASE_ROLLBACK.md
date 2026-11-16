# Gate 0.5.5 — ML Model Registry, Release Approval and Rollback Intelligence

## Purpose
Add a governed model lifecycle layer to the overall CEPHAS PowerOps PoV. This does not change the separate PowerOps Revenue Assurance PoV repository.

## Implemented in this gate
- Model candidate registration bound to a Gate 0.5.3 model-manifest digest and Gate 0.5.4 serialized-artifact SHA-256.
- Registration requires a verification receipt identifying the artifact digest, trusted publisher key ID and verifier version. The receipt is an integration contract: production must construct it only from the trusted Gate 0.5.4 verification path, never from user/artifact claims.
- Fail-closed release policy requires a positive Gate 0.5.3 promotion-eligibility decision, verified artifact receipt and independent approvals from model-risk, security and operations-owner roles.
- Creator/approver separation, distinct approvers, one decision per role, explicit rejection and unique approval IDs.
- Release records bind candidate, model version, manifest digest, artifact digest, approver roles and previous release.
- Rollback may target only a previously released version; rollback is recorded and explicitly requires post-rollback review.
- Append-only-in-process event sequence with SHA-256 hash chaining and verification.
- Tests cover eligibility gates, missing approvals, creator self-approval, duplicate approvers/roles, rejected candidates, rollback constraints and event-chain behavior.

## Deliberate limitations
- The current registry is an in-memory reference implementation for the synthetic PoV. It is not persistent across process restarts, tamper-proof against a privileged process, authenticated, multi-tenant, or production-grade.
- Approval identities/roles are supplied by the caller. Production must derive them from authenticated identity, RBAC and a separately governed approval service.
- Artifact verification receipts are trusted integration inputs. Production must generate them inside the trusted Gate 0.5.4 verifier boundary and protect the key trust store.
- Hash chaining detects accidental or unauthorised mutation only when the trusted chain head is independently retained; it does not provide WORM storage or non-repudiation.
- Rollback changes the registry's active-release pointer only. It does not deploy, unload or alter a model in a live utility environment.
- All data remains synthetic. No IBEDC/customer telemetry or operational data is used.

## Safety boundary
Advisory-only. No SCADA/ADMS/DMS commands, switching, dispatch, meter commands, billing adjustments, refunds or journal postings. No automatic deployment or operational activation is performed. A human-controlled deployment process remains outside this PoV gate.

## Validation status
Unit tests are authored for Node.js 20+ and must be run with `npm test` locally and in GitHub Actions on this branch. Browser integration, persistence, authenticated RBAC, independent security review, customer validation and production deployment remain pending. This gate does not certify production readiness.
