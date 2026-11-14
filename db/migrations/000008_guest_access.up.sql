-- Whether IRC lets people connect without an account (guests). NULL follows
-- the env default (GUEST_ACCESS).
ALTER TABLE network_settings
    ADD COLUMN guest_access boolean;
