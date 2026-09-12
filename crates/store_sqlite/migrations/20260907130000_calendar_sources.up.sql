-- Omnical registration extension / "linked platforms": mappings of external
-- subscribe URLs materialized into a calendar. The server fetches the URL,
-- inserts the events as a copy, and uses this mapping to refresh by UID on an
-- explicit user action. The triple (principal, calendar_id, source_url) is
-- unique so the importer cannot create double mappings.
CREATE TABLE calendar_sources (
    id TEXT NOT NULL,
    principal TEXT NOT NULL,
    calendar_id TEXT NOT NULL,
    source_url TEXT NOT NULL,
    provider_host TEXT NOT NULL,
    last_fetch_at DATETIME,
    last_fetch_success INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE (principal, calendar_id, source_url),
    FOREIGN KEY (principal) REFERENCES principals (id) ON DELETE CASCADE
);

CREATE INDEX idx_calendar_sources_principal ON calendar_sources (principal);