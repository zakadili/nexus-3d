-- Isolated transaction: fixtures, app role and data are rolled back.
-- Requires 0001_saas_foundation.sql applied to the CI database first.
BEGIN;
CREATE ROLE nexus_saas_test_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO nexus_saas_test_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, organization_memberships,
  customer_assets, customer_findings, customer_audit_events TO nexus_saas_test_app;
INSERT INTO organizations(id,name) VALUES
 ('11111111-1111-4111-8111-111111111111','Tenant One'),
 ('22222222-2222-4222-8222-222222222222','Tenant Two');
INSERT INTO customer_assets(id,organization_id,asset_type,asset_value) VALUES
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','11111111-1111-4111-8111-111111111111','domain','one.example'),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','22222222-2222-4222-8222-222222222222','domain','two.example');
INSERT INTO customer_findings(organization_id,asset_id,title,source_name) VALUES
 ('11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','One finding','test'),
 ('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','Two finding','test');
SET ROLE nexus_saas_test_app;
-- Fail closed with no context.
DO $$
BEGIN
 IF (SELECT count(*) FROM organizations) <> 0 OR
    (SELECT count(*) FROM customer_assets) <> 0 OR
    (SELECT count(*) FROM customer_findings) <> 0 THEN
   RAISE EXCEPTION 'RLS leaked rows without tenant context';
 END IF;
END $$;
SELECT set_config('app.organization_id','11111111-1111-4111-8111-111111111111',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM organizations) <> 1 OR
    (SELECT count(*) FROM customer_assets) <> 1 OR
    (SELECT count(*) FROM customer_findings) <> 1 THEN
   RAISE EXCEPTION 'Tenant One read isolation failed';
 END IF;
 IF EXISTS (SELECT 1 FROM customer_assets WHERE asset_value='two.example') THEN
   RAISE EXCEPTION 'Cross-tenant asset read';
 END IF;
END $$;
-- Wrong-tenant INSERT must be blocked by RLS.
DO $$
BEGIN
 BEGIN
  INSERT INTO customer_assets(organization_id,asset_type,asset_value)
  VALUES('22222222-2222-4222-8222-222222222222','domain','escape.example');
  RAISE EXCEPTION 'Cross-tenant INSERT unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
-- Cross-tenant UPDATE must not affect rows.
DO $$
BEGIN
 UPDATE customer_assets SET asset_value='modified.example'
 WHERE organization_id='22222222-2222-4222-8222-222222222222';
 IF FOUND THEN RAISE EXCEPTION 'Cross-tenant UPDATE succeeded'; END IF;
END $$;
-- Tenant switching in the same transaction should isolate the other tenant.
SELECT set_config('app.organization_id','22222222-2222-4222-8222-222222222222',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM customer_assets) <> 1 OR
    (SELECT count(*) FROM customer_findings) <> 1 OR
    EXISTS (SELECT 1 FROM customer_assets WHERE asset_value='one.example') THEN
   RAISE EXCEPTION 'Tenant Two read isolation failed';
 END IF;
END $$;
ROLLBACK;
