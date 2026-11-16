-- Durable "last signed in" / "last active" per user for the admin panel.
-- Sessions expire, get revoked and are deleted, so they are not history.
--
-- last_sign_in_at:     every new session (password, SSO cookie, SSO code exchange).
-- last_sign_in_method: the session's auth_method (password | oidc:<slug> | saml:<slug>).
-- last_sign_in_ip:     the session's ip at sign-in ('' when unknown).
-- last_active_at:      sign-in and refreshes (sessions.last_seen_at), at most
--                      one write per user every few minutes.
ALTER TABLE users
    ADD COLUMN last_sign_in_at     timestamptz,
    ADD COLUMN last_sign_in_method text,
    ADD COLUMN last_sign_in_ip     text,
    ADD COLUMN last_active_at      timestamptz;

-- Backfill from what is left of sessions and from SSO identities.
WITH last_session AS (
    SELECT DISTINCT ON (user_id) user_id, created_at, auth_method, ip
    FROM sessions
    ORDER BY user_id, created_at DESC, id DESC
), last_seen AS (
    SELECT user_id, max(last_seen_at) AS at FROM sessions GROUP BY user_id
), last_identity AS (
    SELECT DISTINCT ON (ui.user_id) ui.user_id, ui.last_login_at AS at, p.kind || ':' || p.slug AS method
    FROM user_identities ui
    JOIN identity_providers p ON p.id = ui.provider_id
    WHERE ui.last_login_at IS NOT NULL
    ORDER BY ui.user_id, ui.last_login_at DESC, ui.id DESC
), merged AS (
    SELECT u.id,
        CASE WHEN li.at IS NOT NULL AND (ls.created_at IS NULL OR li.at > ls.created_at)
             THEN li.at ELSE ls.created_at END AS sign_in_at,
        CASE WHEN li.at IS NOT NULL AND (ls.created_at IS NULL OR li.at > ls.created_at)
             THEN li.method ELSE ls.auth_method END AS sign_in_method,
        CASE WHEN li.at IS NOT NULL AND (ls.created_at IS NULL OR li.at > ls.created_at)
             THEN NULL ELSE ls.ip END AS sign_in_ip,
        seen.at AS seen_at
    FROM users u
    LEFT JOIN last_session ls ON ls.user_id = u.id
    LEFT JOIN last_seen seen ON seen.user_id = u.id
    LEFT JOIN last_identity li ON li.user_id = u.id
)
UPDATE users u SET
    last_sign_in_at     = m.sign_in_at,
    last_sign_in_method = m.sign_in_method,
    last_sign_in_ip     = m.sign_in_ip,
    last_active_at      = GREATEST(m.seen_at, m.sign_in_at) -- GREATEST skips NULLs
FROM merged m
WHERE m.id = u.id AND (m.sign_in_at IS NOT NULL OR m.seen_at IS NOT NULL);

-- Admin list sorting (?sort=last_active / last_sign_in).
CREATE INDEX users_last_active_at_idx ON users (last_active_at DESC NULLS LAST, id DESC);
CREATE INDEX users_last_sign_in_at_idx ON users (last_sign_in_at DESC NULLS LAST, id DESC);
