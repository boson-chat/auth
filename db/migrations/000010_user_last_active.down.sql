DROP INDEX IF EXISTS users_last_sign_in_at_idx;
DROP INDEX IF EXISTS users_last_active_at_idx;
ALTER TABLE users
    DROP COLUMN IF EXISTS last_active_at,
    DROP COLUMN IF EXISTS last_sign_in_ip,
    DROP COLUMN IF EXISTS last_sign_in_method,
    DROP COLUMN IF EXISTS last_sign_in_at;
