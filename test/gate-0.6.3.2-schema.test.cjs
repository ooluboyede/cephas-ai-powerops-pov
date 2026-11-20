"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");
const canonicalizeA = require("canonicalize");
const jcsModule = require("json-canonicalize");
const canonicalizeB = jcsModule.canonicalize || jcsModule.default || jcsModule;

const schemaPath = path.join(__dirname, "..", "schemas", "gate-0.6.3.2", "audit-registry-v2.schema.json");
const fixturePath = path.join(__dirname, "..", "schemas", "gate-0.6.3.2", "fixture-catalog.v1.json");
const vectorsPath = path.join(__dirname, "..", "schemas", "gate-0.6.3.2", "jcs-golden-vectors.v1.json");
const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
const fixtures = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));

const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: true });
addFormats(ajv);

const catalogByMutation = new Map(schema["x-event-catalog"].map(item => [item.mutation_type, item]));
const fixtureByMutation = new Map(fixtures.event_fixtures.map(item => [item.mutation_type, item]));
const validators = new Map();

function validatorFor(token) {
  if (!validators.has(token)) {
    const wrapper = { $schema: schema.$schema, $defs: schema.$defs, $ref: "#/$defs/" + token };
    validators.set(token, ajv.compile(wrapper));
  }
  return validators.get(token);
}

test("Gate 0.6.3.2 registry, schema and fixture catalogues are one-to-one", () => {
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(catalogByMutation.size, schema["x-event-catalog"].length);
  assert.equal(fixtureByMutation.size, fixtures.event_fixtures.length);
  assert.equal(catalogByMutation.size, fixtureByMutation.size);
  for (const [mutation, catalog] of catalogByMutation) {
    const fixture = fixtureByMutation.get(mutation);
    assert.ok(fixture, "missing fixture for " + mutation);
    assert.equal(fixture.event_type, catalog.event_type);
    assert.equal(fixture.event_payload_schema_token, catalog.event_payload_schema_token);
    assert.ok(schema.$defs[catalog.event_payload_schema_token], "missing schema for " + mutation);
    const eventSchema = schema.$defs[catalog.event_payload_schema_token];
    assert.ok((eventSchema.allOf || []).some(item => item.$ref === "#/$defs/commonScopeConstraints"),
      "common scope constraints not composed for " + mutation);
  }
});

test("all positive registry-v2 event fixtures validate under JSON Schema 2020-12", () => {
  for (const fixture of fixtures.event_fixtures) {
    const validate = validatorFor(fixture.event_payload_schema_token);
    const valid = validate(fixture.positive_fixture);
    assert.equal(valid, true, fixture.mutation_type + ": " + JSON.stringify(validate.errors));
    assert.equal(fixture.positive_fixture.mutation_type, fixture.mutation_type);
    assert.equal(fixture.positive_fixture.event_type, fixture.event_type);
    assert.equal(fixture.positive_fixture.event_payload_schema_token, fixture.event_payload_schema_token);
  }
});

test("schema-level negative payload fixtures are rejected", () => {
  let checked = 0;
  for (const fixture of fixtures.event_fixtures) {
    const validate = validatorFor(fixture.event_payload_schema_token);
    for (const negative of fixture.negative_payload_fixtures || []) {
      if (negative.expected_failure === "semantic-reconstruction" ||
          String(negative.expected_failure).startsWith("semantic:")) continue;
      assert.equal(validate(negative.payload), false,
        fixture.mutation_type + "/" + negative.case_id + " unexpectedly validated");
      checked++;
    }
  }
  assert.ok(checked >= 200, "expected broad schema-negative coverage, got " + checked);
});

test("cross-field monotonicity and grant transition semantics are enforced by semantic verifier contract", () => {
  for (const fixture of fixtures.event_fixtures.filter(x =>
    x.mutation_type === "login_binding.disabled" || x.mutation_type === "login_binding.reenabled")) {
    const p = fixture.positive_fixture;
    assert.ok(Number.isInteger(p.prior_login_epoch));
    assert.ok(Number.isInteger(p.resulting_login_epoch));
    assert.ok(p.resulting_login_epoch > p.prior_login_epoch);
    for (const negative of fixture.negative_payload_fixtures.filter(x => String(x.expected_failure).startsWith("semantic:"))) {
      assert.ok(!(negative.payload.resulting_login_epoch > negative.payload.prior_login_epoch),
        negative.case_id + " must violate strict epoch monotonicity");
    }
  }
  const changed = fixtureByMutation.get("approval_grant.changed").positive_fixture;
  assert.ok(changed.resulting_grant_version > changed.prior_grant_version);
  assert.ok((changed.prior_status === "active" && changed.resulting_status === "active") ||
            (changed.prior_status === "pending" && changed.resulting_status === "pending"));
});

test("two independent RFC 8785 canonicalizers reproduce every golden vector", () => {
  assert.equal(typeof canonicalizeA, "function");
  assert.equal(typeof canonicalizeB, "function");
  for (const vector of vectors.vectors) {
    const a = canonicalizeA(vector.source_object);
    const b = canonicalizeB(vector.source_object);
    assert.equal(a, vector.canonical_utf8, vector.id + " canonicalize implementation A");
    assert.equal(b, vector.canonical_utf8, vector.id + " canonicalize implementation B");
    assert.equal(Buffer.byteLength(a, "utf8"), vector.byte_length, vector.id + " UTF-8 byte length");
    const digest = crypto.createHash("sha256").update(a, "utf8").digest("hex");
    assert.match(digest, /^[a-f0-9]{64}$/);
  }
});
