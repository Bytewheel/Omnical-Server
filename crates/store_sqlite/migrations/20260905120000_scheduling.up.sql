-- Omnical scheduling extension: per-principal scheduling inbox objects (RFC 6638)
CREATE TABLE scheduling_inbox_objects (
    principal TEXT NOT NULL,
    id TEXT NOT NULL,
    ics TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (principal, id),
    CONSTRAINT fk_sched_inbox_principal FOREIGN KEY (principal)
        REFERENCES principals (id) ON DELETE CASCADE
);

CREATE INDEX idx_sched_inbox_principal ON scheduling_inbox_objects (principal);
