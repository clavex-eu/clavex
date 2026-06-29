-- Allow presentation_definition to be NULL when dcql_query is used (OID4VP 1.0 Final).
ALTER TABLE presentation_sessions
    ALTER COLUMN presentation_definition DROP NOT NULL,
    ADD CONSTRAINT chk_presentation_sessions_query_or_def
        CHECK (presentation_definition IS NOT NULL OR dcql_query IS NOT NULL);
