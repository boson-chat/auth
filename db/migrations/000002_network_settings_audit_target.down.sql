DROP INDEX IF EXISTS audit_log_event_at_idx;
DROP INDEX IF EXISTS audit_log_target_user_id_at_idx;
ALTER TABLE audit_log DROP COLUMN IF EXISTS target_user_id;
DROP TABLE IF EXISTS network_settings;
