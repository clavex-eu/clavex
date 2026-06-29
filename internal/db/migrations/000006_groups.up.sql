-- groups: named groups within an organization
CREATE TABLE groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

-- group_members: many-to-many users ↔ groups
CREATE TABLE group_members (
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, user_id)
);

-- group_roles: groups can be assigned roles (all members inherit them)
CREATE TABLE group_roles (
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id)  ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX idx_group_members_user  ON group_members(user_id);
CREATE INDEX idx_group_roles_role    ON group_roles(role_id);
CREATE INDEX idx_groups_org          ON groups(org_id);
