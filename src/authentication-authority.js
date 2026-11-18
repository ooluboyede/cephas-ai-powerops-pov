"use strict";
const crypto = require("node:crypto");

const PERMISSIONS = Object.freeze({
  "registry-reader": ["registry:read", "audit:read"],
  "model-trainer": ["registry:read", "candidate:register"],
  "model-risk": ["registry:read", "approval:model-risk"],
  security: ["registry:read", "approval:security", "audit:read"],
  "operations-owner": ["registry:read", "approval:operations-owner"],
  "release-manager": ["registry:read", "release:activate", "release:rollback", "audit:read"],
  auditor: ["registry:read", "audit:read"]
});
const TOKEN_ISSUER = "cephas-powerops-session";
const TOKEN_AUDIENCE = "cephas-powerops-api";

function fail(message) { throw new Error(message); }
function b64(value) { return Buffer.from(value).toString("base64url"); }
function parseSegment(segment, label) {
  try {
    const decoded = Buffer.from(segment, "base64url").toString("utf8");
    const parsed = JSON.parse(decoded);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail("Invalid " + label);
    return parsed;
  } catch (_) {
    return fail("Invalid " + label);
  }
}
function safeEqual(left, right) {
  const a = Buffer.from(left, "utf8"), b = Buffer.from(right, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function validatePrincipal(principal) {
  if (!principal || typeof principal.subject !== "string" || !principal.subject ||
      typeof principal.issuer !== "string" || !principal.issuer ||
      typeof principal.tenantId !== "string" || !principal.tenantId ||
      typeof principal.businessUnitId !== "string" || !principal.businessUnitId ||
      !Array.isArray(principal.roles) || !principal.roles.length) fail("Principal mapping is incomplete");
  const roles = [...new Set(principal.roles)];
  for (const role of roles) if (!Object.prototype.hasOwnProperty.call(PERMISSIONS, role)) fail("Unknown server-assigned role: " + role);
  return Object.freeze({
    subject: principal.subject, issuer: principal.issuer,
    tenantId: principal.tenantId, businessUnitId: principal.businessUnitId,
    roles: Object.freeze(roles)
  });
}

function createAuthenticationAuthority({ assertionVerifier, principalResolver, signingKeys, activeKeyId, revocationStore, clock = () => Date.now(), sessionTtlSeconds = 900 }) {
  if (typeof assertionVerifier !== "function") fail("A trusted external assertion verifier is required");
  if (typeof principalResolver !== "function") fail("A server-side principal resolver is required");
  if (!signingKeys || typeof signingKeys !== "object" || Array.isArray(signingKeys)) fail("A signing key ring is required");
  if (typeof activeKeyId !== "string" || !activeKeyId || !signingKeys[activeKeyId]) fail("An active signing key id is required");
  for (const [kid, key] of Object.entries(signingKeys)) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(kid) || typeof key !== "string" || Buffer.byteLength(key) < 32) fail("Every signing key must have a safe id and at least 32 bytes");
  }
  if (!revocationStore || typeof revocationStore.isRevoked !== "function" || typeof revocationStore.revoke !== "function") fail("A durable revocation store adapter is required");
  if (!Number.isInteger(sessionTtlSeconds) || sessionTtlSeconds < 60 || sessionTtlSeconds > 3600) fail("Session TTL must be between 60 and 3600 seconds");

  function sign(input, key) {
    return crypto.createHmac("sha256", key).update(input).digest("base64url");
  }
  function issueSession(principal) {
    const now = Math.floor(clock() / 1000);
    const header = b64(JSON.stringify({ alg: "HS256", typ: "JWT", kid: activeKeyId }));
    const payload = b64(JSON.stringify({
      iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE, sub: principal.subject,
      idp_iss: principal.issuer, tenant_id: principal.tenantId,
      business_unit_id: principal.businessUnitId, roles: principal.roles,
      iat: now, nbf: now, exp: now + sessionTtlSeconds, jti: crypto.randomUUID()
    }));
    const signingInput = header + "." + payload;
    return signingInput + "." + sign(signingInput, signingKeys[activeKeyId]);
  }

  async function authenticateExternalAssertion(assertion) {
    if (typeof assertion !== "string" || !assertion || assertion.length > 16384) fail("External identity assertion is required");
    const verified = await assertionVerifier(assertion);
    if (!verified || verified.verified !== true || typeof verified.issuer !== "string" || !verified.issuer ||
        typeof verified.subject !== "string" || !verified.subject) fail("External assertion verification failed");
    const mapped = await principalResolver({ issuer: verified.issuer, subject: verified.subject });
    const principal = validatePrincipal({ ...mapped, issuer: verified.issuer, subject: verified.subject });
    return issueSession(principal);
  }

  async function verifySessionToken(token) {
    if (typeof token !== "string" || token.length > 8192) fail("Session bearer token is required");
    const parts = token.split(".");
    if (parts.length !== 3) fail("Malformed session token");
    const header = parseSegment(parts[0], "session header");
    const claims = parseSegment(parts[1], "session claims");
    if (header.alg !== "HS256" || header.typ !== "JWT" || typeof header.kid !== "string") fail("Unsupported session token header");
    const key = signingKeys[header.kid];
    if (!key) fail("Unknown or retired signing key");
    const signingInput = parts[0] + "." + parts[1];
    if (!safeEqual(parts[2], sign(signingInput, key))) fail("Invalid session token signature");
    const now = Math.floor(clock() / 1000);
    if (claims.iss !== TOKEN_ISSUER || claims.aud !== TOKEN_AUDIENCE) fail("Invalid session issuer or audience");
    if (typeof claims.sub !== "string" || !claims.sub || typeof claims.idp_iss !== "string" || !claims.idp_iss) fail("Invalid session subject");
    if (!Number.isInteger(claims.iat) || !Number.isInteger(claims.nbf) || !Number.isInteger(claims.exp) ||
        claims.iat > now + 30 || claims.nbf > now + 30 || claims.exp <= now ||
        claims.exp <= claims.iat || claims.exp - claims.iat > sessionTtlSeconds) fail("Session token expired or has invalid time claims");
    if (typeof claims.jti !== "string" || !claims.jti || typeof claims.tenant_id !== "string" ||
        !claims.tenant_id || typeof claims.business_unit_id !== "string" || !claims.business_unit_id ||
        !Array.isArray(claims.roles) || !claims.roles.length) fail("Incomplete session claims");
    for (const role of claims.roles) if (!Object.prototype.hasOwnProperty.call(PERMISSIONS, role)) fail("Unknown session role");
    if (await revocationStore.isRevoked(claims.jti)) fail("Session token revoked");
    return Object.freeze({
      subject: claims.sub, issuer: claims.idp_iss, tenantId: claims.tenant_id,
      businessUnitId: claims.business_unit_id, roles: Object.freeze([...claims.roles]),
      tokenId: claims.jti, expiresAt: claims.exp
    });
  }

  async function revokeSessionToken(token) {
    const identity = await verifySessionToken(token);
    await revocationStore.revoke(identity.tokenId, identity.expiresAt);
    return Object.freeze({ revoked: true, tokenId: identity.tokenId, expiresAt: identity.expiresAt });
  }

  async function authorize(token, permission) {
    if (typeof permission !== "string" || !permission) fail("Permission is required");
    const identity = await verifySessionToken(token);
    if (!identity.roles.some(role => PERMISSIONS[role].includes(permission))) fail("Forbidden: missing permission " + permission);
    return identity;
  }

  return Object.freeze({ authenticateExternalAssertion, verifySessionToken, revokeSessionToken, authorize });
}
module.exports = { PERMISSIONS, TOKEN_ISSUER, TOKEN_AUDIENCE, createAuthenticationAuthority };
