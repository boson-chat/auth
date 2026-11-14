-- Runtime network settings (one row). NULL columns follow the env default
-- (REGISTRATION, REQUIRE_EMAIL_VERIFICATION, CHANNEL_CREATION,
-- VOICE_CHANNEL_CREATION), so a fresh database behaves exactly like 1.2.
CREATE TABLE network_settings (
    id                         boolean PRIMARY KEY DEFAULT true CHECK (id),
    registration               text CHECK (registration IN ('open', 'invite', 'closed')),
    require_email_verification boolean,
    channel_creation           text CHECK (channel_creation IN ('registered', 'admins')),
    voice_channel_creation     text CHECK (voice_channel_creation IN ('admins', 'founders', 'registered')),
    updated_at                 timestamptz,
    updated_by                 text REFERENCES users (id) ON DELETE SET NULL
);
INSERT INTO network_settings (id) VALUES (true);

-- The user an event is about, when it differs from the actor in user_id
-- (admin actions). Older admin events kept it in meta.user_id.
ALTER TABLE audit_log ADD COLUMN target_user_id text REFERENCES users (id) ON DELETE SET NULL;
UPDATE audit_log a SET target_user_id = a.meta->>'user_id'
WHERE a.meta ? 'user_id' AND EXISTS (SELECT 1 FROM users u WHERE u.id = a.meta->>'user_id');
CREATE INDEX audit_log_target_user_id_at_idx ON audit_log (target_user_id, at);
CREATE INDEX audit_log_event_at_idx ON audit_log (event, at);
