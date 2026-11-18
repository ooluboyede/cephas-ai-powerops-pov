"use strict";

// Gate 0.5.10: provision scoped LOGIN identities from the restored scope map.
// Passwords must be supplied by a secret-manager-backed callback; never log them.
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
    const password = quoteLiteral(await credentialForRole(item.role_name));
    const exists = await admin.query("SELECT 1 FROM pg_roles WHERE rolname=$1", [item.role_name]);
    if (exists.rowCount) {
      await admin.query(
        `ALTER ROLE ${role} WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD ${password}`
      );
    } else {
      await admin.query(
        `CREATE ROLE ${role} WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD ${password}`
      );
    }
    await admin.query(`GRANT powerops_runtime TO ${role} WITH INHERIT TRUE, SET TRUE`);
    provisioned.push({ role: item.role_name, tenantId: item.tenant_id, businessUnitId: item.business_unit_id });
  }
  return provisioned;
}

module.exports = { provisionScopedDatabaseRoles };
