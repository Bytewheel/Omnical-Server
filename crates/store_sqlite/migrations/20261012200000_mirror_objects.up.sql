-- Omnical §18.41: what a [mirror] target last wrote to its remote CalDAV
-- collection (see crates/store/src/mirror_store.rs). Replace-all semantics:
-- every sync replaces the target's rows wholesale, and delete detection on
-- the next run diffs the source against them. Keyed on the config `name`
-- so removing a target orphans its rows harmlessly.
CREATE TABLE mirror_objects (
    mirror TEXT NOT NULL,
    uid    TEXT NOT NULL,
    href   TEXT NOT NULL,
    hash   TEXT NOT NULL,
    PRIMARY KEY (mirror, uid)
);

CREATE INDEX idx_mirror_objects_mirror ON mirror_objects (mirror);
