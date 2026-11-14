-- SSO (OIDC / SAML). Secrets live in their own encrypted columns
-- (AES-256-GCM with AUTH_KEY_ENCRYPTION_KEY, bound to the provider id), never
-- in config jsonb.
ALTER TABLE identity_providers
    ADD COLUMN client_secret_enc bytea,           -- OIDC client secret
    ADD COLUMN sp_key_enc        bytea,           -- SAML SP private key (PKCS#8 DER)
    ADD COLUMN sp_cert           text NOT NULL DEFAULT ''; -- SAML SP certificate (PEM)

-- One-time codes handed to native/desktop clients at the end of an SSO
-- flow (?code= on the return_to URL), exchanged at POST /v1/sso/exchange.
CREATE TABLE sso_login_codes (
    id             text PRIMARY KEY,
    code_hash      bytea NOT NULL UNIQUE, -- sha256 of the code
    user_id        text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider_id    text NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    auth_method    text NOT NULL,         -- oidc:<slug> | saml:<slug>
    code_challenge text NOT NULL DEFAULT '', -- optional client PKCE (S256)
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sso_login_codes_expires_at_idx ON sso_login_codes (expires_at);
