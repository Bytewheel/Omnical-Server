-- Add needs_password_change to principals: when set, the next portal login
-- forces a password-change page before any other portal section. Used for the
-- one-time nudge on a user's first-ever calendar/group join; cleared when the
-- password is rotated (Omnical sharing: existing users who join a shared
-- calendar for the first time must pick a password they control).
ALTER TABLE principals ADD COLUMN needs_password_change BOOLEAN NOT NULL DEFAULT 0;

-- Seed: these existing users are about to receive their first calendar invite
-- and should be prompted to change their password on next portal login.
UPDATE principals SET needs_password_change = 1
WHERE id IN ('lynscarlton@gmail.com', 'chris@carltonaudio.com');