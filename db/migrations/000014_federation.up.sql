-- Boson federated login (docs/federation.md).

-- A local account for a user of another Boson server (their home), keyed
-- by the home's issuer and the user's stable id there. The users row has
-- no password and no email: these accounts only sign in with a federation
-- assertion.
CREATE TABLE federated_accounts (
    user_id        text PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    issuer         text NOT NULL,
    subject        text NOT NULL,
    home_domain    text NOT NULL,          -- boson_domain, e.g. boson.chat
    home_username  text NOT NULL,          -- preferred_username at the home
    picture        text,                   -- absolute avatar URL, refreshed at login
    email_verified boolean NOT NULL DEFAULT false,
    -- 'ban' while a federation ban disabled the local user, so unbanning
    -- re-enables only what the ban disabled. NULL: not suspended by a ban.
    suspended_by   text CHECK (suspended_by IN ('ban')),
    -- The upload limits last pushed to the files service ("<quota>/<max>",
    -- '' = files defaults); NULL = never pushed.
    quota_applied  text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);
CREATE INDEX federated_accounts_home_domain_idx ON federated_accounts (home_domain);

-- Banned federated identities (kept when the local account is deleted, so
-- the identity can't come back by signing in again).
CREATE TABLE federation_bans (
    issuer      text NOT NULL,
    subject     text NOT NULL,
    identity    text NOT NULL,             -- "alice@boson.chat" when banned
    reason      text NOT NULL DEFAULT '',
    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject)
);

-- Seen assertion ids (jti) until they expire, shared by replicas.
-- key: sha256(issuer + " " + jti), hex.
CREATE TABLE federation_replay (
    key        text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX federation_replay_expires_at_idx ON federation_replay (expires_at);

-- Runtime overrides of the FEDERATION_* defaults (a single row), used
-- while there is no stack config file (BOSON_CONFIG auth.federation wins
-- then). NULL follows the env value.
CREATE TABLE federation_settings (
    id                  boolean PRIMARY KEY DEFAULT true CHECK (id),
    mode                text,
    allow               jsonb,
    block               jsonb,
    directory_url       text,
    remote_upload_quota text,              -- "1GB"; '' = the files service's default
    remote_voice        boolean,
    updated_at          timestamptz,
    updated_by          text
);
