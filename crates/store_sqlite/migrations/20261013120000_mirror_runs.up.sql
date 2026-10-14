-- Omnical §18.42: the run history of each [mirror] target — one row per
-- sync attempt (success or failure), written by the engine itself so every
-- surface (background loop, cron CLI, the profile page's button) leaves the
-- same receipt. The profile page reads the newest row per target; the
-- store prunes anything beyond a small bound. Keyed on the config `name`
-- like mirror_objects, so removing a target orphans its rows harmlessly.
CREATE TABLE mirror_runs (
    mirror    TEXT NOT NULL,
    ran_at    TEXT NOT NULL,
    put       INTEGER NOT NULL,
    deleted   INTEGER NOT NULL,
    unchanged INTEGER NOT NULL,
    error     TEXT
);

CREATE INDEX idx_mirror_runs_mirror_ran_at ON mirror_runs (mirror, ran_at);
