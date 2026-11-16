const test = require("node:test");
const assert = require("node:assert/strict");
const { createTokenAuthority } = require("../src/ml-registry-security.js");

function fixture() {
  let now = 1_800_000_000_000;
  const authority = createTokenAuthority({
    secret: "test-only-secret-that-is-at-least-32-bytes-long",
    clock: () => now,
    principals: {
      trainer: { tenantId: "tenant-a", businessUnitId: "bu-1", roles: ["model-trainer"] },
      risk: { tenantId: "tenant-a", businessUnitId: "bu-1", roles: ["model-risk"] },
      otherTenant: { tenantId: "tenant-b", businessUnitId: "bu-1", roles: ["registry-reader"] }
    }
  });
  return { authority, setNow: value => { now = value; } };
}

test("token roles and tenant scope come from server-side principal configuration", () => {
  const { authority } = fixture();
  const token = authority.issueToken("trainer");
  assert.deepEqual(authority.authenticate(token), {
    subject: "trainer", tenantId: "tenant-a", businessUnitId: "bu-1", roles: ["model-trainer"]
  });
});

test("client cannot alter subject, role or scope without invalidating signature", () => {
  const { authority } = fixture();
  const token = authority.issueToken("trainer");
  const [payload] = token.split(".");
  const changed = Buffer.from(JSON.stringify({ sub: "risk", exp: 1_900_000_000, roles: ["release-manager"], tenantId: "tenant-b" })).toString("base64url");
  assert.throws(() => authority.authenticate(changed + "." + token.split(".")[1]), /signature/);
  assert.equal(typeof payload, "string");
});

test("expired and unknown principals are rejected", () => {
  const { authority, setNow } = fixture();
  const token = authority.issueToken("trainer");
  setNow(1_900_000_000_000);
  assert.throws(() => authority.authenticate(token), /expired/);
  assert.throws(() => authority.issueToken("missing"), /Unknown principal/);
});

test("role permissions fail closed", () => {
  const { authority } = fixture();
  const trainer = authority.authenticate(authority.issueToken("trainer"));
  assert.doesNotThrow(() => authority.authorize(trainer, "candidate:register"));
  assert.throws(() => authority.authorize(trainer, "release:activate"), /Forbidden/);
});
