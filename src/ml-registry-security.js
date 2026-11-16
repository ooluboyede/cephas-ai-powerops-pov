"use strict";
const crypto = require("node:crypto");

const ROLE_PERMISSIONS = Object.freeze({
  "registry-reader": ["registry:read", "audit:read"],
  "model-trainer": ["registry:read", "candidate:register"],
  "model-risk": ["registry:read", "approval:model-risk"],
  security: ["registry:read", "approval:security", "audit:read"],
  "operations-owner": ["registry:read", "approval:operations-owner"],
  "release-manager": ["registry:read", "release:activate", "release:rollback", "audit:read"],
  auditor: ["registry:read", "audit:read"]
});

function encode(value) { return Buffer.from(JSON.stringify(value)).toString("base64url"); }
function safeEqual(a, b) {
  const left = Buffer.from(a, "utf8"), right = Buffer.from(b, "utf8");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function createTokenAuthority({ secret, principals, clock = () => Date.now() }) {
  if (typeof secret !== "string" || Buffer.byteLength(secret) < 32) throw new Error("A token signing secret of at least 32 bytes is required");
  if (!principals || typeof principals !== "object") throw new Error("Server-configured principals are required");
  const configured = new Map();
  for (const [subject, p] of Object.entries(principals)) {
    if (!subject || !p || typeof p.tenantId !== "string" || !p.tenantId || typeof p.businessUnitId !== "string" || !p.businessUnitId || !Array.isArray(p.roles) || !p.roles.length) throw new Error("Every principal requires tenant, business unit and server-assigned roles");
    for (const role of p.roles) if (!ROLE_PERMISSIONS[role]) throw new Error("Unknown configured role: " + role);
    configured.set(subject, Object.freeze({ tenantId: p.tenantId, businessUnitId: p.businessUnitId, roles: Object.freeze([...new Set(p.roles)]) }));
  }
  function issueToken(subject, { ttlSeconds = 900 } = {}) {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 3600) throw new Error("Token lifetime must be between 60 and 3600 seconds");
    if (!configured.has(subject)) throw new Error("Unknown principal");
    const payload = encode({ sub: subject, exp: Math.floor(clock() / 1000) + ttlSeconds, jti: crypto.randomUUID() });
    const signature = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
    return payload + "." + signature;
  }
  function authenticate(token) {
    if (typeof token !== "string" || token.length > 4096) throw new Error("Bearer token is required");
    const parts = token.split(".");
    if (parts.length !== 2) throw new Error("Malformed bearer token");
    const expected = crypto.createHmac("sha256", secret).update(parts[0]).digest("base64url");
    if (!safeEqual(parts[1], expected)) throw new Error("Invalid bearer token signature");
    let payload;
    try { payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")); } catch { throw new Error("Malformed bearer token payload"); }
    if (!payload.sub || !Number.isInteger(payload.exp) || payload.exp <= Math.floor(clock() / 1000)) throw new Error("Bearer token expired or invalid");
    const principal = configured.get(payload.sub);
    if (!principal) throw new Error("Principal is not configured");
    return Object.freeze({ subject: payload.sub, tenantId: principal.tenantId, businessUnitId: principal.businessUnitId, roles: principal.roles });
  }
  function authorize(identity, permission) {
    if (!identity || !Array.isArray(identity.roles)) throw new Error("Authenticated identity is required");
    const allowed = identity.roles.some(role => (ROLE_PERMISSIONS[role] || []).includes(permission));
    if (!allowed) throw new Error("Forbidden: missing permission " + permission);
    return identity;
  }
  return Object.freeze({ issueToken, authenticate, authorize });
}
module.exports = { ROLE_PERMISSIONS, createTokenAuthority };
