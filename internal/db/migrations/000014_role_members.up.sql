-- 000014_role_members.up.sql
-- Composite roles: a role can include other roles as children.
-- Assigning the parent role to a user implicitly grants all child roles.
CREATE TABLE role_members (
    parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id  UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (parent_role_id, child_role_id),
    CHECK (parent_role_id <> child_role_id)
);

CREATE INDEX idx_role_members_parent ON role_members(parent_role_id);
CREATE INDEX idx_role_members_child  ON role_members(child_role_id);
