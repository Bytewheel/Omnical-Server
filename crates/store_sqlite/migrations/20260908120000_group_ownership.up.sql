CREATE TABLE group_owners (
    group_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id),
    FOREIGN KEY (group_id) REFERENCES principals (id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES principals (id) ON DELETE CASCADE
);