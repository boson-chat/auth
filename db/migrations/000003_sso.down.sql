DROP TABLE IF EXISTS sso_login_codes;
ALTER TABLE identity_providers
    DROP COLUMN IF EXISTS sp_cert,
    DROP COLUMN IF EXISTS sp_key_enc,
    DROP COLUMN IF EXISTS client_secret_enc;
