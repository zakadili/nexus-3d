-- DRAFT ONLY: review, test and back up before applying. Not wired into production.
-- This migration intentionally does not create an auth provider, app DB role, or user accounts.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS organization_memberships (
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  identity_subject TEXT NOT NULL CHECK (length(identity_subject) BETWEEN 1 AND 255),
  role TEXT NOT NULL CHECK (role IN ('owner','admin','analyst','viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, identity_subject)
);
CREATE TABLE IF NOT EXISTS customer_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_type TEXT NOT NULL CHECK (asset_type IN ('domain','ipv4','ipv6')),
  asset_value TEXT NOT NULL CHECK (length(asset_value) BETWEEN 1 AND 253),
  verification_status TEXT NOT NULL DEFAULT 'unverified'
    CHECK (verification_status IN ('unverified','pending','verified','expired')),
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (organization_id, asset_type, asset_value),
  UNIQUE (id, organization_id)
);
CREATE INDEX IF NOT EXISTS customer_assets_org ON customer_assets(organization_id);
CREATE TABLE IF NOT EXISTS customer_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  asset_id UUID NOT NULL,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','resolved','dismissed')),
  source_name TEXT NOT NULL,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (asset_id, organization_id) REFERENCES customer_assets(id, organization_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS customer_findings_org_created ON customer_findings(organization_id, created_at DESC);
CREATE TABLE IF NOT EXISTS customer_audit_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_subject TEXT,
  action TEXT NOT NULL,
  object_type TEXT,
  object_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS customer_audit_org_created ON customer_audit_events(organization_id, created_at DESC);

-- Defense in depth: enforce RLS even for table owners. Production app role must
-- be non-owner and lack BYPASSRLS; role privileges are not granted here.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE organization_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE customer_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_assets FORCE ROW LEVEL SECURITY;
ALTER TABLE customer_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_findings FORCE ROW LEVEL SECURITY;
ALTER TABLE customer_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_audit_events FORCE ROW LEVEL SECURITY;

-- The trusted API must set this *only after* verifying identity + membership.
-- Missing/invalid context maps to NULL and denies access.
CREATE OR REPLACE FUNCTION nexus_current_organization() RETURNS UUID
LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN current_setting('app.organization_id', true) ~*
   '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 THEN current_setting('app.organization_id', true)::uuid ELSE NULL END
$$;
CREATE POLICY org_scope ON organizations
  USING (id = nexus_current_organization())
  WITH CHECK (id = nexus_current_organization());
CREATE POLICY membership_scope ON organization_memberships
  USING (organization_id = nexus_current_organization())
  WITH CHECK (organization_id = nexus_current_organization());
CREATE POLICY asset_scope ON customer_assets
  USING (organization_id = nexus_current_organization())
  WITH CHECK (organization_id = nexus_current_organization());
CREATE POLICY finding_scope ON customer_findings
  USING (organization_id = nexus_current_organization())
  WITH CHECK (organization_id = nexus_current_organization());
CREATE POLICY audit_scope ON customer_audit_events
  USING (organization_id = nexus_current_organization())
  WITH CHECK (organization_id = nexus_current_organization());
COMMIT;
