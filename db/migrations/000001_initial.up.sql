-- citext is a trusted extension (PG13+): the database owner can create it.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id                text PRIMARY KEY,
    username          citext NOT NULL UNIQUE,
    -- RFC 1459 casemapping fold; IRC treats nicks with equal folds as the same.
    username_folded   text NOT NULL UNIQUE,
    email             citext UNIQUE,
    email_verified_at timestamptz,
    display_name      text NOT NULL DEFAULT '',
    role              text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    disabled_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE password_credentials (
    user_id    text PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    hash       text NOT NULL, -- argon2id PHC string
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identity_providers (
    id           text PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('oidc', 'saml')),
    slug         text NOT NULL UNIQUE,
    display_name text NOT NULL,
    config       jsonb NOT NULL DEFAULT '{}',
    enabled      boolean NOT NULL DEFAULT false,
    allow_signup boolean NOT NULL DEFAULT false,
    trust_email  boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_identities (
    id            text PRIMARY KEY,
    user_id       text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider_id   text NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    subject       text NOT NULL,
    email         citext,
    raw_claims    jsonb NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    UNIQUE (provider_id, subject)
);
CREATE INDEX user_identities_user_id_idx ON user_identities (user_id);

CREATE TABLE sessions (
    id           text PRIMARY KEY,
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    auth_method  text NOT NULL, -- password | oidc:<slug> | saml:<slug>
    ip           text NOT NULL DEFAULT '',
    user_agent   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE refresh_tokens (
    id         text PRIMARY KEY,
    session_id text NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    family_id  text NOT NULL,
    token_hash bytea NOT NULL UNIQUE, -- sha256 of the token
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_session_id_idx ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);

CREATE TABLE email_tokens (
    id         text PRIMARY KEY,
    user_id    text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose    text NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_tokens_user_purpose_idx ON email_tokens (user_id, purpose);

CREATE TABLE signing_keys (
    kid             text PRIMARY KEY,
    alg             text NOT NULL DEFAULT 'EdDSA' CHECK (alg IN ('EdDSA')),
    private_key_enc bytea NOT NULL, -- AES-256-GCM(nonce || ct), aad = kid
    public_jwk      jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Signs from activated_at; published in JWKS from created_at.
    activated_at    timestamptz NOT NULL,
    retired_at      timestamptz
);

CREATE TABLE invites (
    id         text PRIMARY KEY,
    code_hash  bytea NOT NULL UNIQUE,
    created_by text REFERENCES users (id) ON DELETE SET NULL,
    note       text NOT NULL DEFAULT '',
    max_uses   integer NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    uses       integer NOT NULL DEFAULT 0,
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id      text PRIMARY KEY,
    user_id text REFERENCES users (id) ON DELETE SET NULL,
    event   text NOT NULL,
    ip      text NOT NULL DEFAULT '',
    meta    jsonb NOT NULL DEFAULT '{}',
    at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_user_id_at_idx ON audit_log (user_id, at);
CREATE INDEX audit_log_at_idx ON audit_log (at);
