-- Trace invites back to the exact collection tile (PLAN.md §17.9.1):
-- portal-minted invites record which calendar they were generated for.
-- Own-collection invites carry no target_group, so without these columns
-- they could not be attributed to a tile. kind is 'calendar' today (invites
-- are calendar-only); the column leaves room for addressbook invites later.
ALTER TABLE invites ADD COLUMN collection_id TEXT;
ALTER TABLE invites ADD COLUMN kind TEXT;
