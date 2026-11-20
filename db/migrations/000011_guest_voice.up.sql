-- Whether guests (IRC without an account) may join voice under their IRC
-- nick. NULL follows the env default (GUEST_VOICE, false). Only effective
-- together with guest_access.
ALTER TABLE network_settings
    ADD COLUMN guest_voice boolean;
