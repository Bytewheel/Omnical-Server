-- Omnical §17.10: per-collection guest invites (no platform account).
-- Each row grants one guest principal DAV access to exactly one
-- collection with a specific privilege. The guest authenticates via an
-- app token (standard DAV Basic auth); the share is the ACL.
CREATE TABLE collection_shares (
    id TEXT PRIMARY KEY,
    owner_principal TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('calendar', 'addressbook')),
    privilege TEXT NOT NULL CHECK (privilege IN ('view', 'edit', 'admin')),
    guest_principal TEXT NOT NULL UNIQUE,
    target_email TEXT,
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME,
    CONSTRAINT fk_collection_shares_owner
    FOREIGN KEY (owner_principal) REFERENCES principals (id) ON DELETE CASCADE,
    CONSTRAINT fk_collection_shares_guest
    FOREIGN KEY (guest_principal) REFERENCES principals (id) ON DELETE CASCADE
);

CREATE INDEX idx_collection_shares_guest ON collection_shares (guest_principal);
CREATE INDEX idx_collection_shares_collection
    ON collection_shares (owner_principal, collection_id);