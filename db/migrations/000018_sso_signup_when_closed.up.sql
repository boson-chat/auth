-- A provider may create accounts even while registration is closed or
-- invite-only (e.g. a community's own login, where membership there is the
-- invitation). Off by default: only providers that opt in bypass it.
ALTER TABLE identity_providers ADD COLUMN signup_when_closed boolean NOT NULL DEFAULT false;
