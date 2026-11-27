# Workload identity

auth can vouch for the stack's own services to outside systems. It runs a
second, separate OIDC issuer, **`$ISSUER/workload`**, that signs short-lived
**ES256** JWTs naming one service (`sub: "service:<name>"`). An outside
token exchange that trusts this issuer swaps the JWT for its own
credentials, so the service holds no long-lived key from that system.

The use it was built for: the push relay (`boson-chat/pushrelay`) sends
Android pushes through FCM with **Google Workload Identity Federation**
instead of a Google service-account key (the Google project forbids keys).
The relay's Google client fetches a workload token from auth, Google STS
verifies it against the public JWKS and returns a federated token, and IAM
Credentials turns that into an access token for the relay's service
account.

```
pushrelay ──GET /internal/v1/workload/token (X-Workload-Token)──▶ auth :8081
    │  ◀── {"id_token": <ES256 JWT, iss=$ISSUER/workload, sub=service:pushrelay, aud=boson-pushrelay>}
    ├─▶ sts.googleapis.com  (subject_token = id_token)
    │       └─ fetches https://AUTH_HOST/workload/.well-known/openid-configuration → jwks_uri
    ├─▶ iamcredentials.googleapis.com …:generateAccessToken (impersonate the SA)
    └─▶ fcm.googleapis.com  (Bearer <SA access token>)
```

## What is separate from the user tokens

| | user tokens | workload issuer |
|---|---|---|
| issuer | `$ISSUER` | `$ISSUER/workload` |
| discovery | `/.well-known/openid-configuration` | `/workload/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` (Ed25519) | `/workload/jwks.json` (P-256 only) |
| keys | `signing_keys`, `EdDSA` | `workload_signing_keys`, `ES256` |
| minted | public API, for users | internal listener only, for configured services |

The workload keys never appear in the main JWKS and the user keys never in
the workload JWKS, so a verifier of one can't be handed a token of the
other.

## Configuration

```sh
WORKLOAD_IDENTITIES=pushrelay:boson-pushrelay   # name:audience, comma-separated
WORKLOAD_TOKEN_PUSHRELAY=$(openssl rand -hex 32) # the workload's own secret
# optional
WORKLOAD_TOKEN_TTL=5m              # ≤ 10m
WORKLOAD_KEY_ROTATION=720h
WORKLOAD_KEY_PUBLISH_LEAD=1h
```

- Only the listed `(name, audience)` pairs are minted. A name may be listed
  with several audiences; then the request must name one.
- Every name needs `WORKLOAD_TOKEN_<NAME>` (upper-case, `-` → `_`), at least
  16 characters, different from every other workload's and from
  `INTERNAL_API_TOKEN` / `INTERNAL_ACTING_TOKEN`; auth refuses to start
  otherwise. The secret decides which workload is asking: it can only get
  tokens for its own name.
- Empty `WORKLOAD_IDENTITIES` (the default): the feature is off, no key is
  created and every route below is 404.

## Endpoints

### `GET $ISSUER/workload/.well-known/openid-configuration` (public)

```json
{
  "issuer": "https://auth.example.com/workload",
  "jwks_uri": "https://auth.example.com/workload/jwks.json",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"],
  "claims_supported": ["iss", "sub", "aud", "iat", "exp", "jti"]
}
```

### `GET $ISSUER/workload/jwks.json` (public)

`{"keys": [{"kty": "EC", "crv": "P-256", "x", "y", "kid", "alg": "ES256", "use": "sig"}]}`,
`Cache-Control: public, max-age=300`.

Both are on the public listener, so a reverse proxy that routes the whole
auth host (the stack's Traefik does) serves them over HTTPS. They are built
from `ISSUER`, which must therefore be the public `https://` URL of auth.

### `GET /internal/v1/workload/token` (internal listener only)

Header `X-Workload-Token: <WORKLOAD_TOKEN_<NAME>>`. Query: `audience`
(optional when the workload has one), `format` = `json` (default) or `text`.

```json
{"id_token": "<jwt>", "token_type": "urn:ietf:params:oauth:token-type:id_token",
 "expires_in": 300, "expires_at": 1767225600}
```

`format=text` returns the bare JWT as `application/jwt`. `Cache-Control:
no-store`. Errors: 401 (no or unknown secret), 403 `audience_not_allowed`,
400 (bad `format`).

The token: header `{alg: ES256, kid, typ: JWT}`, claims `iss`
(`$ISSUER/workload`), `sub` (`service:<name>`), `aud` (one string), `iat`,
`exp` (`iat + WORKLOAD_TOKEN_TTL`), `jti`.

This is the shape of a Google `external_account` **url credential source**:

```json
"credential_source": {
  "url": "http://auth:8081/internal/v1/workload/token?audience=boson-pushrelay",
  "headers": {"X-Workload-Token": "…"},
  "format": {"type": "json", "subject_token_field_name": "id_token"}
}
```

(or `"format": {"type": "text"}` with `&format=text`). The push relay
keeps the secret out of that file and adds the header itself from a secret
file (pushrelay README, "FCM without a service-account key").

## Google Workload Identity Federation requirements

Checked against Google's [WIF with other providers](https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)
docs:

| Requirement | Here |
|---|---|
| Discovery at `<issuer>/.well-known/openid-configuration`, public | `$ISSUER/workload/.well-known/openid-configuration` on the public listener |
| `jwks_uri` over HTTPS, not self-signed | `$ISSUER/workload/jwks.json`; `ISSUER` = `https://AUTH_HOST` (Let's Encrypt via Traefik) |
| Signed `RS256` or `ES256` | `ES256` (P-256); the user keys are EdDSA, which Google doesn't accept, hence the separate key |
| `exp` in the future, `iat` in the past, `exp − iat` ≤ 24 h | `iat` = now, `exp − iat` = `WORKLOAD_TOKEN_TTL` ≤ 10 min |
| `aud` = the provider's resource URL, or a configured allowed audience | `aud` = the configured audience (`boson-pushrelay`, the provider's allowed audience) |
| `iss` = the provider's issuer URI | `$ISSUER/workload` exactly (no trailing slash) |
| `kid` selects the key | every token carries `kid`; every JWK has it |

## Keys and rotation

Like the user keys ([Signing keys](../README.md#signing-keys)): created on
first start (only with the feature on), encrypted at rest with
`AUTH_KEY_ENCRYPTION_KEY` (AES-256-GCM over the PKCS#8 key, bound to the
`kid`), one replica creates under a Postgres advisory lock and the others
reload every minute. Every `WORKLOAD_KEY_ROTATION` the successor is
published `WORKLOAD_KEY_PUBLISH_LEAD` (1 h) before it signs, so Google's
cached JWKS already has it, and the retired key stays published for the
token TTL plus the lead plus 10 minutes.

`auth keys list --workload`, `auth keys rotate --workload [--now]`.
