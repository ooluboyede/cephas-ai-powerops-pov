# Gate 0.4.2 — Deterministic synthetic reconciliation

## Delivered in this gate

- Extracted the hard-coded reconciliation summary from the dashboard and replaced it with a deterministic reconciliation engine.
- Added versioned synthetic billing and payment fixtures.
- Implemented exact matches, split-payment aggregation, duplicate candidates, partial payments, reversals, unmatched payments, overpayments and currency-mismatch quarantine.
- Added a run summary with input snapshot and rule version.
- Added Node unit tests for expected counts, split payments, exception classifications, deterministic replay and invalid-input rejection.
- The UI builds exception rows using DOM text nodes, not HTML string interpolation.

## Synthetic baseline

- Billing records: 6
- Payment records: 9
- Exact matched bills: 3
- Matched amount: NGN 450,000
- Exception classes: duplicate candidate, partial, unmatched payment and reversal

These values are test-fixture outputs only. They are not IBEDC measurements, revenue leakage estimates, or collection performance.

## Controls and limitations

- Integer NGN minor-unit arithmetic is used for this synthetic fixture. Currency is checked before comparison.
- A repeated reference with repeated posted amount is flagged as a duplicate candidate; distinct amounts sharing a reference are aggregated as split payments.
- This is a demonstration rule set, not a production bank/payment matching policy. Real matching requires source-specific identifiers, effective dates, reversal semantics, settlement cut-offs and customer sign-off.
- No ledger posting, refund, bill adjustment or customer action is performed.

## Acceptance status

- [x] Deterministic engine implemented.
- [x] UI consumes calculated results instead of fixed 1,142/44 values.
- [x] Unit tests authored.
- [ ] CI execution on this branch.
- [ ] Browser end-to-end test.
- [ ] Independent code/security review.

**Gate 0.4.2 implementation is committed for review; validation is pending.**
