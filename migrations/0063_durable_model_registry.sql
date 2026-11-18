BEGIN;
CREATE SCHEMA IF NOT EXISTS powerops_registry;

CREATE TABLE powerops_registry.registry_scopes (
 registry_id text NOT NULL, tenant_id text NOT NULL, business_unit_id text NOT NULL,
 active_release_id uuid, next_event_sequence bigint NOT NULL DEFAULT 1 CHECK(next_event_sequence>0),
 event_head_sha256 char(64) NOT NULL DEFAULT repeat('0',64),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,business_unit_id,registry_id)
);

CREATE TABLE powerops_registry.model_candidates (
 candidate_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id text NOT NULL, business_unit_id text NOT NULL, registry_id text NOT NULL,
 model_version text NOT NULL,
 manifest_sha256 char(64) NOT NULL CHECK(manifest_sha256 ~ '^[0-9a-f]{64}$'),
 artifact_sha256 char(64) NOT NULL CHECK(artifact_sha256 ~ '^[0-9a-f]{64}$'),
 created_by_principal_id text NOT NULL,
 eligibility jsonb NOT NULL CHECK(jsonb_typeof(eligibility)='object'),
 eligibility_receipt jsonb NOT NULL CHECK(jsonb_typeof(eligibility_receipt)='object'),
 artifact_receipt jsonb NOT NULL CHECK(jsonb_typeof(artifact_receipt)='object'),
 status text NOT NULL DEFAULT 'candidate' CHECK(status IN('candidate','rejected','released','withdrawn')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,business_unit_id,registry_id,candidate_id),
 UNIQUE(tenant_id,business_unit_id,registry_id,manifest_sha256),
 FOREIGN KEY(tenant_id,business_unit_id,registry_id)
  REFERENCES powerops_registry.registry_scopes(tenant_id,business_unit_id,registry_id) ON DELETE RESTRICT
);

CREATE TABLE powerops_registry.principal_role_assignments (
 assignment_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id text NOT NULL, business_unit_id text NOT NULL, principal_id text NOT NULL,
 role_name text NOT NULL CHECK(role_name IN('model-risk','security','operations-owner')),
 granted_by_principal_id text NOT NULL,
 granted_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz,
 CHECK(revoked_at IS NULL OR revoked_at>=granted_at)
);
CREATE INDEX principal_role_active_lookup
 ON powerops_registry.principal_role_assignments(tenant_id,business_unit_id,principal_id,role_name)
 WHERE revoked_at IS NULL;

CREATE TABLE powerops_registry.model_approvals (
 approval_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id text NOT NULL, business_unit_id text NOT NULL, registry_id text NOT NULL,
 candidate_id uuid NOT NULL, principal_id text NOT NULL,
 role_name text NOT NULL CHECK(role_name IN('model-risk','security','operations-owner')),
 decision text NOT NULL CHECK(decision IN('approve','reject')),
 reason text NOT NULL CHECK(length(btrim(reason))>0),
 authorization_assignment_id uuid NOT NULL
  REFERENCES powerops_registry.principal_role_assignments(assignment_id) ON DELETE RESTRICT,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,business_unit_id,registry_id,candidate_id,role_name),
 UNIQUE(tenant_id,business_unit_id,registry_id,candidate_id,principal_id),
 FOREIGN KEY(tenant_id,business_unit_id,registry_id,candidate_id)
  REFERENCES powerops_registry.model_candidates(tenant_id,business_unit_id,registry_id,candidate_id)
  ON DELETE RESTRICT
);

CREATE TABLE powerops_registry.model_releases (
 release_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id text NOT NULL, business_unit_id text NOT NULL, registry_id text NOT NULL,
 candidate_id uuid NOT NULL, model_version text NOT NULL,
 manifest_sha256 char(64) NOT NULL CHECK(manifest_sha256 ~ '^[0-9a-f]{64}$'),
 artifact_sha256 char(64) NOT NULL CHECK(artifact_sha256 ~ '^[0-9a-f]{64}$'),
 released_by_principal_id text NOT NULL,
 previous_release_id uuid REFERENCES powerops_registry.model_releases(release_id) ON DELETE RESTRICT,
 released_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,business_unit_id,registry_id,release_id),
 FOREIGN KEY(tenant_id,business_unit_id,registry_id,candidate_id)
  REFERENCES powerops_registry.model_candidates(tenant_id,business_unit_id,registry_id,candidate_id)
  ON DELETE RESTRICT
);
ALTER TABLE powerops_registry.registry_scopes ADD CONSTRAINT registry_active_release_fk
 FOREIGN KEY(active_release_id) REFERENCES powerops_registry.model_releases(release_id) ON DELETE RESTRICT;

CREATE TABLE powerops_registry.registry_events (
 tenant_id text NOT NULL, business_unit_id text NOT NULL, registry_id text NOT NULL,
 sequence_no bigint NOT NULL CHECK(sequence_no>0), event_id uuid NOT NULL DEFAULT gen_random_uuid(),
 event_type text NOT NULL, actor_principal_id text NOT NULL,
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 previous_event_sha256 char(64) NOT NULL CHECK(previous_event_sha256 ~ '^[0-9a-f]{64}$'),
 event_sha256 char(64) NOT NULL CHECK(event_sha256 ~ '^[0-9a-f]{64}$'),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,business_unit_id,registry_id,sequence_no), UNIQUE(event_id),
 FOREIGN KEY(tenant_id,business_unit_id,registry_id)
  REFERENCES powerops_registry.registry_scopes(tenant_id,business_unit_id,registry_id) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION powerops_registry.reject_event_mutation()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,powerops_registry
AS $$
BEGIN
 RAISE EXCEPTION 'registry_events is append-only' USING ERRCODE='42501';
END;
$$;
CREATE TRIGGER registry_events_no_update BEFORE UPDATE OR DELETE
 ON powerops_registry.registry_events FOR EACH ROW
 EXECUTE FUNCTION powerops_registry.reject_event_mutation();
COMMIT;
