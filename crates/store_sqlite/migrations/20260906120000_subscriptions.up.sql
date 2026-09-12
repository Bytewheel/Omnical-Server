-- Omnical share-links extension: public read-only subscription tokens.
-- The token in the export URL is the only credential of the request (no
-- username is sent), so it is stored in plaintext with a unique index for
-- O(1) lookups. This grants read access to data that already sits in
-- plaintext in this database, so unlike the (write-granting, hashed) app
-- tokens there is nothing extra to protect by hashing.
CREATE TABLE subscriptions (
    id TEXT NOT NULL,
    principal TEXT NOT NULL,
    kind TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE (token),
    FOREIGN KEY (principal) REFERENCES principals (id) ON DELETE CASCADE
);

CREATE INDEX idx_subscriptions_principal ON subscriptions (principal);
