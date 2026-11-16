"use strict";
const crypto = require("node:crypto");
const { canonical, verifyModelManifest } = require("./ml-governance.js");

const REQUIRED_APPROVALS = Object.freeze(["model-risk", "security", "operations-owner"]);
function digest(value) { return crypto.createHash("sha256").update(canonical(value)).digest("hex"); }
function requiredText(value, name) { if (typeof value !== "string" || !value.trim()) throw new Error(name + " is required"); }
function createPostgresRegistry({ pool, tokenAuthority, artifactVerifier }) {
  if (!pool || typeof pool.connect !== "function") throw new Error("A PostgreSQL-compatible pool is required");
  if (!tokenAuthority || typeof tokenAuthority.authenticate !== "function") throw new Error("A server token authority is required");
  if (artifactVerifier !== undefined && typeof artifactVerifier !== "function") throw new Error("artifactVerifier must be a trusted server-side verification function");

  async function transact(token, permission, operation) {
    const identity = tokenAuthority.authorize(tokenAuthority.authenticate(token), permission);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true), set_config('app.business_unit_id', $2, true)", [identity.tenantId, identity.businessUnitId]);
      const result = await operation(client, identity);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try { await client.query("ROLLBACK"); } catch (_) { /* preserve original error */ }
      throw error;
    } finally {
      client.release();
    }
  }

  async function lockScope(client, identity) {
    // Serialize all mutations in one tenant/business-unit scope, including the first audit event.
    const scopeKey = identity.tenantId + ":" + identity.businessUnitId;
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [scopeKey]);
  }

  async function appendAudit(client, identity, eventType, payload, actorId) {
    const latest = await client.query(
      "SELECT sequence, event_hash FROM powerops_ml_audit_events WHERE tenant_id = $1 AND business_unit_id = $2 ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
      [identity.tenantId, identity.businessUnitId]
    );
    const previousHash = latest.rows.length ? latest.rows[0].event_hash : "GENESIS";
    const sequence = latest.rows.length ? Number(latest.rows[0].sequence) + 1 : 1;
    const descriptor = { sequence, tenantId: identity.tenantId, businessUnitId: identity.businessUnitId, eventType, payload, actorId, previousHash };
    const eventHash = digest(descriptor);
    await client.query(
      "INSERT INTO powerops_ml_audit_events (tenant_id, business_unit_id, sequence, event_type, payload, actor_id, previous_hash, event_hash) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8)",
      [identity.tenantId, identity.businessUnitId, sequence, eventType, JSON.stringify(payload), actorId, previousHash, eventHash]
    );
    return { ...descriptor, eventHash };
  }

  async function registerCandidate(token, input) {
    requiredText(input?.candidateId, "candidateId");
    if (!input.manifest || !verifyModelManifest(input.manifest).valid) throw new Error("A cryptographically valid model manifest is required");
    if (!/^[a-f0-9]{64}$/.test(input.artifactSha256 || "")) throw new Error("Artifact SHA-256 is required");
    if (!input.artifactReceipt) throw new Error("Signed artifact receipt is required");
    if (typeof artifactVerifier !== "function") throw new Error("Trusted server-side artifact verifier is not configured");
    return transact(token, "candidate:register", async (client, identity) => {
      await lockScope(client, identity);
      const verifiedReceipt = await artifactVerifier(input.artifactReceipt, {
        artifactSha256: input.artifactSha256, tenantId: identity.tenantId,
        businessUnitId: identity.businessUnitId, subject: identity.subject
      });
      if (!verifiedReceipt || verifiedReceipt.verified !== true || verifiedReceipt.artifactSha256 !== input.artifactSha256) throw new Error("Trusted artifact verification failed");
      requiredText(verifiedReceipt.publisherKeyId, "verified publisherKeyId");
      requiredText(verifiedReceipt.verifierVersion, "verified verifierVersion");
      const candidate = {
        candidateId: input.candidateId, modelVersion: input.manifest.modelVersion,
        manifestSha256: input.manifest.manifestSha256, artifactSha256: input.artifactSha256,
        eligibility: input.eligibility || { eligible: false, reasons: ["No promotion eligibility decision supplied"] },
        artifactVerification: { verified: true, publisherKeyId: verifiedReceipt.publisherKeyId, verifierVersion: verifiedReceipt.verifierVersion },
        createdBy: identity.subject, status: "candidate", approvals: []
      };
      const inserted = await client.query(
        "INSERT INTO powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) VALUES ($1,$2,$3,$4,$5,$6,'candidate',$7::jsonb,$8) ON CONFLICT (tenant_id,business_unit_id,candidate_id) DO NOTHING RETURNING candidate_id",
        [identity.tenantId, identity.businessUnitId, candidate.candidateId, candidate.modelVersion, candidate.manifestSha256, candidate.artifactSha256, JSON.stringify(candidate), identity.subject]
      );
      if (!inserted.rows.length) {
        const existing = await client.query(
          "SELECT candidate_data FROM powerops_ml_model_candidates WHERE tenant_id=$1 AND business_unit_id=$2 AND candidate_id=$3 FOR UPDATE",
          [identity.tenantId, identity.businessUnitId, candidate.candidateId]
        );
        const prior = existing.rows[0]?.candidate_data;
        if (prior && prior.createdBy === candidate.createdBy && prior.modelVersion === candidate.modelVersion &&
            prior.manifestSha256 === candidate.manifestSha256 && prior.artifactSha256 === candidate.artifactSha256) return prior;
        throw new Error("Candidate ID already exists with different content");
      }
      await appendAudit(client, identity, "candidate-registered", { candidateId: candidate.candidateId, manifestSha256: candidate.manifestSha256, artifactSha256: candidate.artifactSha256 }, identity.subject);
      return candidate;
    });
  }

  async function recordApproval(token, { candidateId, approvalId, role, decision = "approve", reason }) {
    requiredText(candidateId, "candidateId"); requiredText(approvalId, "approvalId"); requiredText(reason, "reason");
    if (!REQUIRED_APPROVALS.includes(role)) throw new Error("Approval role is not part of the release policy");
    if (!["approve", "reject"].includes(decision)) throw new Error("Invalid approval decision");
    return transact(token, "approval:" + role, async (client, identity) => {
      await lockScope(client, identity);
      const found = await client.query(
        "SELECT candidate_data FROM powerops_ml_model_candidates WHERE tenant_id=$1 AND business_unit_id=$2 AND candidate_id=$3 FOR UPDATE",
        [identity.tenantId, identity.businessUnitId, candidateId]
      );
      if (!found.rows.length) throw new Error("Unknown model candidate in this tenant and business unit");
      const candidate = found.rows[0].candidate_data;
      const priorId = candidate.approvals.find(a => a.approvalId === approvalId);
      if (priorId) {
        if (priorId.approverId === identity.subject && priorId.role === role && priorId.decision === decision && priorId.reason === reason) return candidate;
        throw new Error("Approval ID already exists with different content");
      }
      if (candidate.status !== "candidate") throw new Error("Candidate is not open for approval");
      if (candidate.createdBy === identity.subject) throw new Error("Model creator cannot approve their own candidate");
      if (candidate.approvals.some(a => a.approverId === identity.subject)) throw new Error("Approvers must be distinct");
      if (candidate.approvals.some(a => a.role === role)) throw new Error("An approval decision already exists for this role");
      const approval = { approvalId, approverId: identity.subject, role, decision, reason, recordedAt: new Date().toISOString() };
      candidate.approvals.push(approval);
      if (decision === "reject") candidate.status = "rejected";
      await client.query(
        "UPDATE powerops_ml_model_candidates SET candidate_data=$4::jsonb,status=$5,updated_at=now() WHERE tenant_id=$1 AND business_unit_id=$2 AND candidate_id=$3",
        [identity.tenantId, identity.businessUnitId, candidateId, JSON.stringify(candidate), candidate.status]
      );
      await appendAudit(client, identity, "release-approval-recorded", { candidateId, approvalId, role, decision, reason }, identity.subject);
      return candidate;
    });
  }

  async function activateRelease(token, { candidateId, releaseId }) {
    requiredText(candidateId, "candidateId"); requiredText(releaseId, "releaseId");
    return transact(token, "release:activate", async (client, identity) => {
      await lockScope(client, identity);
      const existingRelease = await client.query(
        "SELECT release_data, is_active FROM powerops_ml_model_releases WHERE tenant_id=$1 AND business_unit_id=$2 AND release_id=$3 FOR UPDATE",
        [identity.tenantId, identity.businessUnitId, releaseId]
      );
      if (existingRelease.rows.length) {
        const prior = existingRelease.rows[0].release_data;
        if (prior.candidateId === candidateId && existingRelease.rows[0].is_active === true) return prior;
        throw new Error("Release ID already exists with different content or is no longer active");
      }
      const found = await client.query(
        "SELECT candidate_data FROM powerops_ml_model_candidates WHERE tenant_id=$1 AND business_unit_id=$2 AND candidate_id=$3 FOR UPDATE",
        [identity.tenantId, identity.businessUnitId, candidateId]
      );
      if (!found.rows.length) throw new Error("Unknown model candidate in this tenant and business unit");
      const candidate = found.rows[0].candidate_data;
      if (candidate.status !== "candidate") throw new Error("Candidate is not promotable");
      if (candidate.eligibility?.eligible !== true) throw new Error("Promotion eligibility is blocked or missing");
      if (candidate.artifactVerification?.verified !== true) throw new Error("Artifact verification is missing");
      const approved = new Set(candidate.approvals.filter(a => a.decision === "approve").map(a => a.role));
      const missing = REQUIRED_APPROVALS.filter(role => !approved.has(role));
      if (missing.length) throw new Error("Required independent approvals missing: " + missing.join(", "));
      const previous = await client.query(
        "SELECT release_id FROM powerops_ml_model_releases WHERE tenant_id=$1 AND business_unit_id=$2 AND is_active=true FOR UPDATE",
        [identity.tenantId, identity.businessUnitId]
      );
      const previousReleaseId = previous.rows[0]?.release_id || null;
      await client.query("UPDATE powerops_ml_model_releases SET is_active=false WHERE tenant_id=$1 AND business_unit_id=$2 AND is_active=true", [identity.tenantId, identity.businessUnitId]);
      const release = { releaseId, candidateId, modelVersion: candidate.modelVersion, manifestSha256: candidate.manifestSha256, artifactSha256: candidate.artifactSha256, approvedRoles: REQUIRED_APPROVALS, releasedBy: identity.subject, previousReleaseId, status: "released" };
      await client.query(
        "INSERT INTO powerops_ml_model_releases (tenant_id,business_unit_id,release_id,candidate_id,is_active,release_data) VALUES ($1,$2,$3,$4,true,$5::jsonb)",
        [identity.tenantId, identity.businessUnitId, releaseId, candidateId, JSON.stringify(release)]
      );
      await client.query("UPDATE powerops_ml_model_candidates SET status='released',updated_at=now() WHERE tenant_id=$1 AND business_unit_id=$2 AND candidate_id=$3", [identity.tenantId, identity.businessUnitId, candidateId]);
      await appendAudit(client, identity, "model-release-activated", release, identity.subject);
      return release;
    });
  }

  async function rollback(token, { targetReleaseId, reason }) {
    requiredText(targetReleaseId, "targetReleaseId"); requiredText(reason, "reason");
    return transact(token, "release:rollback", async (client, identity) => {
      await lockScope(client, identity);
      const target = await client.query(
        "SELECT release_id, release_data FROM powerops_ml_model_releases WHERE tenant_id=$1 AND business_unit_id=$2 AND release_id=$3 FOR UPDATE",
        [identity.tenantId, identity.businessUnitId, targetReleaseId]
      );
      if (!target.rows.length) throw new Error("Rollback target is not a previously recorded release in this scope");
      const active = await client.query(
        "SELECT release_id FROM powerops_ml_model_releases WHERE tenant_id=$1 AND business_unit_id=$2 AND is_active=true FOR UPDATE",
        [identity.tenantId, identity.businessUnitId]
      );
      if (!active.rows.length || active.rows[0].release_id === targetReleaseId) throw new Error("Rollback target must differ from the active release");
      const fromReleaseId = active.rows[0].release_id;
      await client.query("UPDATE powerops_ml_model_releases SET is_active=false WHERE tenant_id=$1 AND business_unit_id=$2 AND is_active=true", [identity.tenantId, identity.businessUnitId]);
      await client.query("UPDATE powerops_ml_model_releases SET is_active=true WHERE tenant_id=$1 AND business_unit_id=$2 AND release_id=$3", [identity.tenantId, identity.businessUnitId, targetReleaseId]);
      const result = { activeReleaseId: targetReleaseId, rolledBackFrom: fromReleaseId, rolledBackTo: targetReleaseId, reason, actorId: identity.subject, requiresPostRollbackReview: true };
      await appendAudit(client, identity, "model-release-rolled-back", result, identity.subject);
      return result;
    });
  }

  async function listCandidates(token) {
    return transact(token, "registry:read", async (client, identity) => {
      const result = await client.query(
        "SELECT candidate_id, candidate_data FROM powerops_ml_model_candidates WHERE tenant_id=$1 AND business_unit_id=$2 ORDER BY created_at DESC",
        [identity.tenantId, identity.businessUnitId]
      );
      return result.rows.map(row => row.candidate_data);
    });
  }

  async function verifyAuditChain(token) {
    return transact(token, "audit:read", async (client, identity) => {
      const result = await client.query(
        "SELECT sequence, event_type, payload, actor_id, previous_hash, event_hash, tenant_id, business_unit_id FROM powerops_ml_audit_events WHERE tenant_id=$1 AND business_unit_id=$2 ORDER BY sequence",
        [identity.tenantId, identity.businessUnitId]
      );
      let previousHash = "GENESIS";
      for (let i = 0; i < result.rows.length; i++) {
        const row = result.rows[i];
        const descriptor = { sequence: Number(row.sequence), tenantId: row.tenant_id, businessUnitId: row.business_unit_id, eventType: row.event_type, payload: row.payload, actorId: row.actor_id, previousHash: row.previous_hash };
        if (descriptor.sequence !== i + 1 || descriptor.previousHash !== previousHash || digest(descriptor) !== row.event_hash) return { valid: false, failedSequence: i + 1, eventCount: result.rows.length };
        previousHash = row.event_hash;
      }
      return { valid: true, eventCount: result.rows.length, headHash: previousHash };
    });
  }

  return Object.freeze({ registerCandidate, recordApproval, activateRelease, rollback, listCandidates, verifyAuditChain });
}
module.exports = { REQUIRED_APPROVALS, createPostgresRegistry };
