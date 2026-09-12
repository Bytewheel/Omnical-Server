-- Omnical registration extension: single-use invitation codes.
-- The code is a short human-transcribable random string that gates the public
-- /register endpoint. Redemption is atomic (single-use): a row is claimed with
-- an UPDATE that requires used_by IS NULL, so concurrent redemptions of the
-- same code yield exactly one winner. Codes are not secrets-protected the way
-- app tokens are (they are short and rate-limiting guards brute force), but an
-- unused invite is still a capability, so redemption records who used it.
CREATE TABLE invites (
    id TEXT NOT NULL,
    code TEXT NOT NULL,
    target_email TEXT,
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    used_by TEXT,
    used_at DATETIME,
    PRIMARY KEY (id),
    UNIQUE (code)
);

CREATE INDEX idx_invites_status ON invites (code, used_by);