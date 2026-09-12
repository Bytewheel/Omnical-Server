-- Deduplicate: keep the lowest rowid for each displayname, nullify others
UPDATE calendars
SET displayname = NULL
WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM calendars
    WHERE displayname IS NOT NULL
    GROUP BY displayname
)
AND displayname IS NOT NULL;

CREATE UNIQUE INDEX idx_calendars_displayname_unique ON calendars (displayname) WHERE displayname IS NOT NULL;
CREATE UNIQUE INDEX idx_addressbooks_displayname_unique ON addressbooks (displayname) WHERE displayname IS NOT NULL;