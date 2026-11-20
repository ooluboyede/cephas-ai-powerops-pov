# Gate 0.6.3.2 — Reassessment remediation implementation note

**Baseline:** `6d420fadb9fd5495b2c8b15582b00a3cbdc20565`  
**Branch:** `gate/0.6.3.2-database-enforced-promotion-authority`  
**PR:** #20 — keep Draft/open/unmerged.

## Changes in this commit

- F-02: supersedes the contradictory same-user-transaction registration design with a server-owned registration transaction committed before user SQL parsing/planning/execution; specifies Q/P/B/E/F gating, exact SASL framing, assertion binding, fatal failure semantics, replay retention, cleanup and restore requirements.
- F-03: adds distinct `accountable_role.granted` registry-v2 schema/catalogue/fixture; maps appointment, grant, replacement, suspension and removal one-to-one.
- F-04: applies common global-vs-tenant scope constraints to every manifest expected-event item.
- M-02: adds a strict harness for every positive/negative event fixture, manifest golden fixture and mutation-reconstruction negative descriptor.
- M-04: declares four semantic assertions and executes them against positive and schema-valid negative fixtures; quarantine terminality is tested.
- Adds a shared application-level registry/semantic/reconstruction verifier module and a reference protocol state-machine test for pre-command registration ordering.

## Evidence boundary

The semantic verifier is a reusable application-level validation component; it is not yet wired into a PostgreSQL authority-mutation dispatcher. The reference protocol test is a contract model, **not** a PostgreSQL implementation. This commit does not contain the customer-maintained source-pinned PostgreSQL 16 C patch, broker service, live SASL wire implementation, protocol dispatcher guard or real PostgreSQL protocol-client tests. Therefore F-02 runtime enforcement remains unimplemented and Gate 0.6.3.2 is not implementation-accepted or production-ready. The WAL consumer/failover prototype also remains outstanding.

## Next runtime unit

Implement and independently review the source-pinned PostgreSQL 16 patch and broker described in the final design closure §9.1–§9.2.1, then run the real-protocol adversarial matrix.
