-- NickServ account backend (ACCOUNT_BACKEND=nickserv, docs/nickserv.md).
--
-- A local user linked to the IRC network's NickServ account of the same
-- name. The password stays with the services and is never stored here.
CREATE TABLE nickserv_accounts (
    user_id            text PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    account            text NOT NULL,        -- the services' spelling
    account_folded     text NOT NULL UNIQUE, -- RFC 1459 fold, as users.username_folded
    services_id        text NOT NULL DEFAULT '', -- Anope uniqueid / Atheme entity id; '' = unknown
    strategy           text NOT NULL,        -- the NICKSERV_STRATEGY that last verified it
    -- An opaque services session (Atheme authcookie), AES-256-GCM sealed
    -- with AUTH_KEY_ENCRYPTION_KEY (aad "nickserv_session:<user_id>").
    session_enc        bytea,
    session_expires_at timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_verified_at   timestamptz NOT NULL DEFAULT now()
);

-- Failed verification counters (lockout), shared by replicas.
-- key: "a:<folded account>" | "ip:<client ip>".
CREATE TABLE nickserv_lockouts (
    key          text PRIMARY KEY,
    failures     integer NOT NULL DEFAULT 0,
    window_start timestamptz NOT NULL,
    locked_until timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX nickserv_lockouts_updated_at_idx ON nickserv_lockouts (updated_at);
