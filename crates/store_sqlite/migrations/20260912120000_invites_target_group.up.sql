-- Add target_group to invites: when set, the redeeming user is automatically
-- added to this group on registration (grants access to shared calendars).
ALTER TABLE invites ADD COLUMN target_group TEXT;
