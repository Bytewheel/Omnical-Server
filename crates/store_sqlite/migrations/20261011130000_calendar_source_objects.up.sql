-- Omnical §17.8.3: which materialized objects a linked source owns.
-- Refresh diffs BY UID, and a calendar can carry several sources at once
-- (the create-calendar modal's "add holidays" merges several sets into one
-- calendar; the linked-platforms form can point several URLs at one too).
-- Without ownership rows a refresh of ONE source treats every other set's
-- events as "vanished from the feed" and deletes them; the recorded set
-- scopes each refresh's diff to the source's own UIDs.
--
-- No FK to the objects themselves (their table keys on (principal,
-- calendar_id, id), and rows can be hard-deleted); the source_id FK keeps
-- the rows exactly as long as the source mapping they belong to.
CREATE TABLE calendar_source_objects (
    source_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    PRIMARY KEY (source_id, object_id),
    CONSTRAINT fk_calendar_source_objects_source
    FOREIGN KEY (source_id) REFERENCES calendar_sources (id) ON DELETE CASCADE
);

CREATE INDEX idx_calendar_source_objects_source ON calendar_source_objects (source_id);
