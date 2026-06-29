-- OID4VP 1.0 Final: add dcql_query column to presentation_sessions.
-- DCQL (Digital Credentials Query Language) replaces presentation_definition
-- in OID4VP 1.0 Final. When set, dcql_query takes precedence over
-- presentation_definition in the authorization request.
ALTER TABLE presentation_sessions
    ADD COLUMN IF NOT EXISTS dcql_query JSONB;
