-- Omnical §18.42: per-principal timezone. Empty string — the default —
-- means "unset", and the consumer falls back to the deployment's
-- `[caldav]` dailyview timezone (then UTC). The reference consumer is the
-- §18.41 push mirror: a target's phone-feed instances flatten in the
-- calendar owner's zone, so users in different zones get correct local
-- times instead of everyone sharing one deployment-wide setting.
ALTER TABLE principals ADD COLUMN timezone TEXT NOT NULL DEFAULT '';
