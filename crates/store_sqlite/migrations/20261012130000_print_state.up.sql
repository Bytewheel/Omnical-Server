-- Print-state tracking for the portal's print pages (PLAN_NEXT_AGENT_PRINTING.md §3):
-- "print only new" = everything not yet marked printed here. Keyed per owning
-- collection + object + (for events) the concrete instance, so a recurring
-- series printed for October is new again in November — the wall-calendar
-- semantics (plan D4). `kind` is mandatory: a calendar and an addressbook may
-- share the id "personal" under one principal (plan D9).
CREATE TABLE print_state (
    principal     TEXT NOT NULL,     -- owning principal of the collection
    collection_id TEXT NOT NULL,     -- calendar or addressbook id
    kind          TEXT NOT NULL,     -- 'calendar' | 'addressbook' (ids collide)
    object_id     TEXT NOT NULL,
    instance_key  TEXT NOT NULL,     -- '': whole object; events: start ("%Y%m%d" | "%Y%m%dT%H%M%SZ")
    printed_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    printed_by    TEXT NOT NULL,
    PRIMARY KEY (principal, collection_id, kind, object_id, instance_key)
);

CREATE INDEX idx_print_state_collection ON print_state (principal, kind, collection_id);