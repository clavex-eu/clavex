-- Migration: add account_center_configs table
-- This table stores the per-org Account Center widget configuration.
-- If no row exists for an org, all sections default to enabled (see
-- models.DefaultAccountCenterConfig).

CREATE TABLE account_center_configs (
    org_id           UUID        PRIMARY KEY
                                 REFERENCES organizations(id) ON DELETE CASCADE,
    -- Section visibility toggles
    show_profile     BOOLEAN     NOT NULL DEFAULT TRUE,
    show_password    BOOLEAN     NOT NULL DEFAULT TRUE,
    show_mfa         BOOLEAN     NOT NULL DEFAULT TRUE,
    show_passkeys    BOOLEAN     NOT NULL DEFAULT TRUE,
    show_sessions    BOOLEAN     NOT NULL DEFAULT TRUE,
    show_activity    BOOLEAN     NOT NULL DEFAULT TRUE,
    show_data_export BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Optional custom page title shown inside the widget
    page_title       TEXT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
