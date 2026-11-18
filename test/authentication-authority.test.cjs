"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { createAuthenticationAuthority } = require("../src/authentication-authority.js");

function fixture() {
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
    revocationStore: {
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
