"use strict";

const crypto = require("node:crypto");

// PostgreSQL utility statements cannot use bind parameters for role passwords.
// Send a SCRAM-SHA-256 verifier, never the plaintext credential, in CREATE/ALTER ROLE.
// A verifier may still appear in SQL logs; use high-entropy generated credentials and
// protect database logs as sensitive authentication material.
const SCRAM_ITERATIONS = 4096;

function quoteIdentifier(value) {
  if (typeof value !== "string" || !/^[a-z_][a-z0-9_]{0,62}$/.test(value)) {
    throw new Error("Invalid PostgreSQL role identifier in scope map");
  }
  return '"' + value.replace(/"/g, '""') + '"';
}

function quoteLiteral(value) {
  if (typeof value !== "string" || value.length < 24) {
    throw new Error("Scoped role credentials must be at least 24 characters");
  }
  return "'" + value.replace(/'/g, "''") + "'";
}

function createScramVerifier(password) {
  if (typeof password !== "string" || Buffer.byteLength(password, "utf8") < 24) {
    throw new Error("Scoped role credentials must be at least 24 bytes");
  }
  const salt = crypto.randomBytes(16);
  const saltedPassword = crypto.pbkdf2Sync(password, salt, SCRAM_ITERATIONS, 32, "sha256");
  const clientKey = crypto.createHmac("sha256", saltedPassword).update("Client Key").digest();
  const storedKey = crypto.createHash("sha256").update(clientKey).digest();
  const serverKey = crypto.createHmac("sha256", saltedPassword).update("Server Key").digest();
  return "SCRAM-SHA-256$" + SCRAM_ITERATIONS + ":" + salt.toString("base64") +
    "$" + storedKey.toString("base64") + ":" + serverKey.toString("base64");
}

async function provisionScopedDatabaseRoles({ admin, credentialForRole }) {
  if (!admin || typeof admin.query !== "function" || typeof credentialForRole !== "function") {
    throw new Error("admin query client and credentialForRole callback are required");
  }
  const inventory = await admin.query(
    "SELECT db_role::text AS role_name, tenant_id, business_unit_id, enabled FROM powerops_security.db_principal_scopes ORDER BY db_role"
  );
  if (inventory.rowCount < 1) throw new Error("Refusing to provision an empty scoped-role inventory");

  const provisioned = [];
  for (const item of inventory.rows) {
    if (!item.enabled) continue;
    const role = quoteIdentifier(item.role_name);
    const verifier = quoteLiteral(createScramVerifier(await credentialForRole(item.role_name)));
    const exists = await admin.query("SELECT 1 FROM pg_roles WHERE rolname=$1", [item.role_name]);
    if (exists.rowCount) {
      await admin.query(
        `ALTER ROLE ${role} WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD ${verifier}`
      );
    } else {
      await admin.query(
        `CREATE ROLE ${role} WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD ${verifier}`
      );
    }
    await admin.query(`GRANT powerops_runtime TO ${role} WITH INHERIT TRUE, SET TRUE`);
    provisioned.push({ role: item.role_name, tenantId: item.tenant_id, businessUnitId: item.business_unit_id });
  }
  return provisioned;
}

module.exports = { provisionScopedDatabaseRoles, createScramVerifier };
