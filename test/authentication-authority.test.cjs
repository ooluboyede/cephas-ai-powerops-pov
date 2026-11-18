"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createAuthenticationAuthority } = require("../src/authentication-authority.js");

function fixture({ revocationStore } = {}) {
  let now = 1_800_000_000_000;
  const revoked = new Map();
  const authority = createAuthenticationAuthority({
    clock: () => now,
    signingKeys: { "key-current": "test-signing-secret-with-at-least-32-bytes-0001", "key-previous": "previous-signing-secret-with-at-least-32-bytes-0002" },
    activeKeyId: "key-current",
    assertionVerifier: async assertion => assertion === "valid-idp-assertion"
      ? { verified: true, issuer: "https://idp.example.test", subject: "user-123" }
      : { verified: false },
    principalResolver: async ({ issuer, subject }) => issuer === "https://idp.example.test" && subject === "user-123"
      ? { tenantId: "tenant-a", businessUnitId: "bu-1", roles: ["model-trainer"] }
      : null,
    revocationStore: revocationStore || {
      isRevoked: async jti => revoked.has(jti),
      revoke: async (jti, expiresAt) => { revoked.set(jti, expiresAt); }
    }
  });
  return { authority, setNow: value => { now = value; } };
}

test("external assertion must pass the injected verifier and server-side scope mapping", async () => {
  const { authority } = fixture();
  await assert.rejects(() => authority.authenticateExternalAssertion("forged"), /verification failed/);
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  const identity = await authority.verifySessionToken(token);
  assert.equal(identity.subject, "user-123");
  assert.equal(identity.tenantId, "tenant-a");
  assert.equal(identity.businessUnitId, "bu-1");
  assert.deepEqual(identity.roles, ["model-trainer"]);
});

test("session claims cannot be modified without a valid signature", async () => {
  const { authority } = fixture();
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  const [header, payload] = token.split(".");
  const altered = Buffer.from(JSON.stringify({ iss: "cephas-powerops-session", aud: "cephas-powerops-api", sub: "attacker", idp_iss: "https://idp.example.test", tenant_id: "tenant-b", business_unit_id: "bu-1", roles: ["release-manager"], iat: 1800000000, nbf: 1800000000, exp: 1800000900, jti: "forged" })).toString("base64url");
  await assert.rejects(() => authority.verifySessionToken(header + "." + altered + "." + token.split(".")[2]), /signature/);
});

test("session tokens are revoked through the required revocation adapter", async () => {
  const { authority } = fixture();
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  const result = await authority.revokeSessionToken(token);
  assert.equal(result.revoked, true);
  await assert.rejects(() => authority.verifySessionToken(token), /revoked/);
});

test("expiry, issuer, audience and maximum lifetime are enforced", async () => {
  const { authority, setNow } = fixture();
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  setNow(1_900_000_000_000);
  await assert.rejects(() => authority.verifySessionToken(token), /expired/);
});

test("authorization uses only server-mapped roles and fails closed", async () => {
  const { authority } = fixture();
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  const identity = await authority.authorize(token, "candidate:register");
  assert.equal(identity.tenantId, "tenant-a");
  await assert.rejects(() => authority.authorize(token, "release:activate"), /Forbidden/);
});

test("construction fails without durable revocation and trusted verifier adapters", () => {
  assert.throws(() => createAuthenticationAuthority({}), /assertion verifier/);
});

test("retained previous signing keys validate existing sessions during rotation", async () => {
  let now = 1_800_000_000_000;
  const revoked = new Set();
  const common = {
    clock: () => now,
    assertionVerifier: async () => ({ verified: true, issuer: "https://idp.example.test", subject: "user-123" }),
    principalResolver: async () => ({ tenantId: "tenant-a", businessUnitId: "bu-1", roles: ["model-trainer"] }),
    revocationStore: { isRevoked: async id => revoked.has(id), revoke: async id => revoked.add(id) }
  };
  const previousAuthority = createAuthenticationAuthority({
    ...common, signingKeys: { "key-previous": "previous-signing-secret-with-at-least-32-bytes-0002" },
    activeKeyId: "key-previous"
  });
  const oldSession = await previousAuthority.authenticateExternalAssertion("valid");
  const rotatedAuthority = createAuthenticationAuthority({
    ...common,
    signingKeys: {
      "key-current": "test-signing-secret-with-at-least-32-bytes-0001",
      "key-previous": "previous-signing-secret-with-at-least-32-bytes-0002"
    },
    activeKeyId: "key-current"
  });
  assert.equal((await rotatedAuthority.verifySessionToken(oldSession)).subject, "user-123");
  const newSession = await rotatedAuthority.authenticateExternalAssertion("valid");
  assert.equal((await rotatedAuthority.verifySessionToken(newSession)).subject, "user-123");
  const retiredAuthority = createAuthenticationAuthority({
    ...common, signingKeys: { "key-current": "test-signing-secret-with-at-least-32-bytes-0001" },
    activeKeyId: "key-current"
  });
  await assert.rejects(() => retiredAuthority.verifySessionToken(oldSession), /Unknown or retired signing key/);
});

function resignClaims(token, mutate) {
  const [headerPart, payloadPart] = token.split(".");
  const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
  const claims = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
  mutate(claims, header);
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") + "." +
    Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = crypto.createHmac("sha256", "test-signing-secret-with-at-least-32-bytes-0001")
    .update(input).digest("base64url");
  return input + "." + signature;
}

test("signing key lookup rejects inherited object properties and missing active keys", async () => {
  assert.throws(() => createAuthenticationAuthority({
    assertionVerifier: async () => ({ verified: true, issuer: "issuer", subject: "subject" }),
    principalResolver: async () => ({ tenantId: "tenant", businessUnitId: "bu", roles: ["model-trainer"] }),
    signingKeys: { "key-current": "test-signing-secret-with-at-least-32-bytes-0001" },
    activeKeyId: "toString",
    revocationStore: { isRevoked: async () => false, revoke: async () => {} }
  }), /active signing key id/);

  const { authority } = fixture();
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  const [header, payload, signature] = token.split(".");
  const inheritedKid = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT", kid: "toString" })).toString("base64url");
  await assert.rejects(() => authority.verifySessionToken(inheritedKid + "." + payload + "." + signature),
    /Unknown or retired signing key/);
  const inheritedConstructor = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT", kid: "constructor" })).toString("base64url");
  await assert.rejects(() => authority.verifySessionToken(inheritedConstructor + "." + payload + "." + signature),
    /Unknown or retired signing key/);
});

test("issuer, audience, future time claims, malformed jti and excessive lifetime are rejected", async () => {
  const { authority } = fixture();
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  const cases = [
    [claims => { claims.iss = "attacker"; }, /issuer or audience/],
    [claims => { claims.aud = "other-api"; }, /issuer or audience/],
    [claims => { claims.iat += 60; }, /time claims/],
    [claims => { claims.nbf += 60; }, /time claims/],
    [claims => { claims.jti = ""; }, /Incomplete session claims/],
    [claims => { claims.exp = claims.iat + 901; }, /time claims/]
  ];
  for (const [mutate, expected] of cases) {
    const altered = resignClaims(token, mutate);
    await assert.rejects(() => authority.verifySessionToken(altered), expected);
  }
});

test("unknown key identifiers are rejected without inherited-property lookup", async () => {
  const { authority } = fixture();
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  const [headerPart, payload, signature] = token.split(".");
  const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
  header.kid = "constructor";
  const alteredHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  await assert.rejects(() => authority.verifySessionToken(alteredHeader + "." + payload + "." + signature),
    /Unknown or retired signing key/);
});

test("revocation-store failure fails closed", async () => {
  const { authority } = fixture({
    revocationStore: {
      isRevoked: async () => { throw new Error("revocation backend unavailable"); },
      revoke: async () => {}
    }
  });
  const token = await authority.authenticateExternalAssertion("valid-idp-assertion");
  await assert.rejects(() => authority.verifySessionToken(token), /revocation backend unavailable/);
});

