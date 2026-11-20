"use strict";

const crypto = require("node:crypto");

function scopeTuple(value) {
  return JSON.stringify([value.scope_kind, value.tenant_id, value.business_unit_id]);
}

function createRegistry(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new TypeError("A non-empty event catalogue is required");
  }
  const byMutation = new Map();
  const byEvent = new Map();
  const byToken = new Map();
  for (const entry of entries) {
    for (const key of ["mutation_type", "event_type", "event_payload_schema_token"]) {
      if (typeof entry[key] !== "string" || entry[key].length === 0) {
        throw new TypeError("Invalid event catalogue entry: " + key);
      }
    }
    if (byMutation.has(entry.mutation_type) ||
        byEvent.has(entry.event_type) ||
        byToken.has(entry.event_payload_schema_token)) {
      throw new Error("Duplicate mutation/event/schema identity in registry v2");
    }
    const frozen = Object.freeze({ ...entry });
    byMutation.set(entry.mutation_type, frozen);
    byEvent.set(entry.event_type, frozen);
    byToken.set(entry.event_payload_schema_token, frozen);
  }
  return Object.freeze({
    size: byMutation.size,
    resolve(mutationType) {
      const entry = byMutation.get(mutationType);
      if (!entry) throw new Error("Unregistered registry-v2 mutation: " + mutationType);
      return entry;
    },
    assertPair(mutationType, eventType, schemaToken) {
      const entry = this.resolve(mutationType);
      if (entry.event_type !== eventType ||
          entry.event_payload_schema_token !== schemaToken) {
        throw new Error("Mutation/event/schema identity mismatch");
      }
      return entry;
    },
    has(mutationType) {
      return byMutation.has(mutationType);
    }
  });
}

function validateSemanticAssertions(mutationType, payload, assertions) {
  const matching = assertions.filter(x => x.mutation_type === mutationType);
  if (matching.length === 0) return true;
  if (matching.length !== 1) return false;
  const rule = matching[0];
  if (rule.rule === "resulting_greater_than_prior") {
    const prior = payload[rule.prior_field];
    const resulting = payload[rule.resulting_field];
    if (!Number.isSafeInteger(prior) ||
        !Number.isSafeInteger(resulting) ||
        resulting <= prior) return false;
  } else {
    return false;
  }
  if (rule.status_rule === "same_active_or_pending") {
    return payload.prior_status === payload.resulting_status &&
      ["active", "pending"].includes(payload.prior_status);
  }
  if (rule.status_rule === "active_or_pending_to_suspended") {
    return ["active", "pending"].includes(payload.prior_status) &&
      payload.resulting_status === "suspended";
  }
  return rule.status_rule === undefined;
}

function validateLifecycleTransition(mutationType, payload) {
  if (mutationType === "security_incident.reconciled" &&
      payload.prior_stream_condition === "quarantined") {
    return payload.resulting_stream_condition === "quarantined";
  }
  return true;
}

function eventMatchesManifest(event, manifest) {
  const expected = manifest.expected_events[event.mutation_event_index];
  if (!expected) return false;
  if (event.registry_version !== 2 ||
      event.registry_token !== "cephas.powerops.audit-payload-registry.v2" ||
      event.event_envelope_schema_token !== "cephas.powerops.audit-event-envelope.v2" ||
      event.mutation_schema_version !== "cephas.powerops.mutation.v1" ||
      event.manifest_schema_token !== "cephas.powerops.mutation-manifest.v1") return false;

  for (const key of [
    "mutation_id", "operation_id", "mutation_type",
    "actor_principal_id", "actor_login_binding_id",
    "actor_mapping_version", "reason_code"
  ]) {
    if (event[key] !== manifest[key]) return false;
  }
  if (event.mutation_event_count !== manifest.expected_event_count ||
      event.mutation_event_index !== expected.mutation_event_index ||
      event.event_type !== expected.event_type ||
      event.event_payload_schema_token !== expected.event_payload_schema_token) return false;

  if (scopeTuple(event) !== scopeTuple(expected) ||
      !manifest.affected_scope_keys.some(x => scopeTuple(x) === scopeTuple(expected))) return false;

  for (const key of ["affected_mapping_ids", "affected_scope_keys", "affected_object_refs"]) {
    if (JSON.stringify(event[key]) !== JSON.stringify(manifest[key])) return false;
  }
  return true;
}

function canonicalManifestDigest(manifest, canonicalize) {
  if (typeof canonicalize !== "function") throw new TypeError("Canonicalizer is required");
  const canonicalBytes = canonicalize(manifest);
  return crypto.createHash("sha256").update(canonicalBytes, "utf8").digest("hex");
}

function reconstructMutationEvents(manifest, events, options) {
  if (!options || typeof options.validateManifest !== "function" ||
      typeof options.canonicalize !== "function") {
    throw new TypeError("Manifest validator and canonicalizer are required");
  }
  if (!options.validateManifest(manifest)) return false;
  if (!Array.isArray(events) ||
      manifest.expected_event_count !== manifest.expected_events.length ||
      events.length !== manifest.expected_event_count) return false;

  const canonicalBytes = options.canonicalize(manifest);
  const digest = crypto.createHash("sha256").update(canonicalBytes, "utf8").digest("hex");
  for (let index = 0; index < events.length; index++) {
    const event = events[index];
    if (event.mutation_event_index !== index ||
        manifest.expected_events[index].mutation_event_index !== index ||
        event.mutation_event_count !== events.length ||
        event.mutation_payload_sha256 !== digest ||
        !eventMatchesManifest(event, manifest)) return false;
  }
  return true;
}

module.exports = {
  createRegistry,
  validateSemanticAssertions,
  validateLifecycleTransition,
  eventMatchesManifest,
  reconstructMutationEvents,
  canonicalManifestDigest
};
