ALTER TABLE presentation_sessions
    DROP CONSTRAINT IF EXISTS chk_presentation_sessions_query_or_def,
    ALTER COLUMN presentation_definition SET NOT NULL;
