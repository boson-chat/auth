-- ES256 (P-256) keys of the workload issuer, <ISSUER>/workload: short-lived
-- JWTs for this stack's own services to present to outside token exchanges
-- (Google Workload Identity Federation for the push relay's FCM access).
-- Kept apart from signing_keys so the user-token keys and the main JWKS
-- never see them. Same lifecycle columns as signing_keys.
CREATE TABLE workload_signing_keys (
    kid             text PRIMARY KEY,
    alg             text NOT NULL DEFAULT 'ES256' CHECK (alg IN ('ES256')),
    private_key_enc bytea NOT NULL, -- AES-256-GCM(nonce || PKCS#8 DER), aad = kid
    public_jwk      jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    activated_at    timestamptz NOT NULL,
    retired_at      timestamptz
);
