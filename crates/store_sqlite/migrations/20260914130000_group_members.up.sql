-- Omnical §17.9.2: per-member privileges inside shared groups.
-- The existing `memberships` row keeps granting collection visibility; the
-- `group_members` privilege decides WRITE access. Backfill defaults keep
-- today's behavior exactly: every existing membership becomes `edit`, every
-- `group_owners` owner becomes `admin`.
CREATE TABLE group_members (
    group_id TEXT NOT NULL,
    member_id TEXT NOT NULL,
    privilege TEXT NOT NULL CHECK (privilege IN ('view', 'edit', 'admin')),
    PRIMARY KEY (group_id, member_id),
    CONSTRAINT fk_group_members_group
    FOREIGN KEY (group_id) REFERENCES principals (id) ON DELETE CASCADE,
    CONSTRAINT fk_group_members_member
    FOREIGN KEY (member_id) REFERENCES principals (id) ON DELETE CASCADE
);

INSERT INTO group_members (group_id, member_id, privilege)
SELECT m.member_of, m.principal, 'edit'
FROM memberships m
JOIN principals p ON p.id = m.member_of
WHERE p.principal_type = 'GROUP';

INSERT INTO group_members (group_id, member_id, privilege)
SELECT group_id, owner_id, 'admin'
FROM group_owners
ON CONFLICT(group_id, member_id) DO UPDATE SET privilege = 'admin';
