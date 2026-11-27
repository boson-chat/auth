-- Guest-first web entry: Boson web clients open straight into chat as a
-- guest. NULL follows the env defaults (GUEST_FIRST, false;
-- GUEST_FIRST_CHANNEL, ""). guest_first needs guest_access;
-- guest_first_channel "" = the first auto-join network channel.
ALTER TABLE network_settings
    ADD COLUMN guest_first boolean,
    ADD COLUMN guest_first_channel text;
