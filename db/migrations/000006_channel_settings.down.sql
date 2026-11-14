ALTER TABLE network_settings
    DROP COLUMN IF EXISTS channel_expiry_days,
    DROP COLUMN IF EXISTS channel_auto_register;
