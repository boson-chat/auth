-- IRC channel lifecycle settings. NULL follows the env default
-- (CHANNEL_AUTO_REGISTER, CHANNEL_EXPIRY_DAYS).
ALTER TABLE network_settings
    ADD COLUMN channel_auto_register boolean,
    ADD COLUMN channel_expiry_days   integer CHECK (channel_expiry_days BETWEEN 0 AND 3650);
