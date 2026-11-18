# Gate 0.6.2 — Signed Promotion Evidence

## Finding addressed

Gate 0.6.1 made the registry invoke its trusted Ed25519 model-artifact verifier, but candidate registration still accepted caller-supplied promotion eligibility. A caller could present a valid signed model artifact alongside a forged `eligibility.eligible = true` decision. Artifact authenticity is not evidence of model quality or release suitability.

## Implemented

- Added a trusted promotion evaluator with an Ed25519 evaluator-key ring supplied only by the trusted composition root.
- Registry construction fails closed when promotion eligibility is mandatory but no trusted evaluator is injected.
- Candidate registration passes the signed evaluation report bytes, signature, evaluator key ID, verified manifest and internally computed artifact digest to the injected evaluator.
- The evaluator verifies the signature over exact report bytes before parsing, limits report size, requires canonical JSON, validates schema and metrics, and binds the report to the exact manifest and artifact digests.
- The evaluation dataset digest must differ from the model's training dataset digest.
- The evaluator applies the existing promotion policy thresholds for minimum evaluation cases, precision, recall and feature drift.
- The registry stores the internally returned decision and verification receipt; caller-supplied eligibility is ignored.
- Added negative tests for forged eligibility, altered report bytes, unknown evaluator keys, malformed signatures, artifact/manifest binding mismatch and training/holdout dataset reuse.

## Trust boundaries and limitations

- The evaluator signing key and promotion policy are trusted composition-root configuration. Their production custody, governance and rotation remain separate deployment controls.
- This reference implementation verifies the report signature and policy metrics; it does not independently prove the evaluation dataset's provenance, label quality, representativeness or absence of leakage. Those require governed evaluation pipelines and independent validation.
- The default thresholds are demonstration policy values, not IBEDC-approved operational acceptance criteria.
- The registry remains in-memory. Durable approvals, authenticated approver identity, persistent state and independent WORM anchoring remain separate gates.
- Signed evidence does not authorize automatic deployment or operational action. PowerOps remains advisory-only and synthetic-data-only.

## Acceptance criteria

1. Registry fails closed without both mandatory trusted verifiers.
2. Caller-supplied eligibility cannot affect the registry's promotion decision.
3. Exact signed report bytes are verified before canonical JSON parsing.
4. Report is bound to exact manifest and artifact digests and a separate holdout dataset.
5. Existing promotion thresholds and three-role approval requirements remain enforced.
6. Exact-head CI and independent security review pass before F-03 is considered closed.

No production certification or F-03 closure is claimed by this gate.
