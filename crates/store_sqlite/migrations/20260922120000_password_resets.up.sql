-- Omnical password-reset extension: single-use emailed reset tokens.
-- The 64-char random token from the emailed link is never stored — only its
-- SHA-256 hex digest (token_hash), so a database leak does not leave behind
-- working reset capabilities. Redemption is atomic (single-use): a row is
-- claimed with an UPDATE that requires used_at IS NULL, so concurrent
-- redemptions of the same link yield exactly one winner. Minting a fresh
-- token and completing a reset both supersede every other outstanding token
-- of the same principal, so at most one link per account is ever usable.
CREATE TABLE password_resets (
    id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    used_at DATETIME,
    PRIMARY KEY (id),
    UNIQUE (token_hash)
);

CREATE INDEX idx_password_resets_principal ON password_resets (principal_id, used_at);