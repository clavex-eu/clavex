ALTER TABLE saml_service_providers DROP COLUMN IF EXISTS idp_cert_id;
DROP TABLE IF EXISTS idp_certificates;
