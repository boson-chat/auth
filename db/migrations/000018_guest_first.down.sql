ALTER TABLE network_settings
    DROP COLUMN IF EXISTS guest_first,
    DROP COLUMN IF EXISTS guest_first_channel;
