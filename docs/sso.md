# Single sign-on (OIDC and SAML)

Users can sign in through external identity providers (IdPs) next to, or
instead of, a password. Admins add providers at runtime through the admin API
(`/v1/admin/sso/providers`); nothing is configured in env vars except where
users may be sent back to (`SSO_RETURN_TO_ALLOWED`).

- **OIDC** (authorization code flow, PKCE S256 + nonce): Google, Authentik,
  Zitadel, Keycloak, Okta, Entra ID, Dex, GitLab, and any other
  spec-compliant issuer. Built on `coreos/go-oidc/v3` + `x/oauth2`.
- **SAML 2.0** service provider (`crewjam/saml`): Okta, Entra ID, ADFS,
  Authentik, Keycloak, Shibboleth. SP-initiated only; IdP-initiated logins
  are refused.

## The flow

```text
client ──GET /v1/sso/{slug}/start?return_to=…──▶ auth ──302──▶ IdP (login)
                         sets boson_sso (encrypted state)        │
IdP ──GET /v1/sso/{slug}/callback (OIDC) ───────────────▶ auth   │
    ──POST /v1/sso/{slug}/saml/acs (SAML) ──────────────▶ auth ◀─┘
auth: check state, verify the IdP's answer, link or create the user, then
  browser app  → set boson_at/boson_rt cookies, 303 to return_to
  native app   → 303 to return_to?code=bsc_…  → POST /v1/sso/exchange {code}
errors         → 303 to return_to?error=<code>&error_description=<text>
```

### `GET /v1/sso/{slug}/start`

| Query | |
|---|---|
| `return_to` | where to send the user afterwards. A path (`/chat`) is resolved against `APP_URL`. Default `APP_URL/`. Must be one of this site's web origins (`APP_URL`, `PUBLIC_URL`, `CORS_ALLOWED_ORIGINS`) or match `SSO_RETURN_TO_ALLOWED`, else `400 invalid_return_to`. |
| `mode` | `cookie` or `code`. Default: `cookie` for our web origins, `code` for everything else. `cookie` is refused for non-web origins. |
| `invite_code` | for sign-up while `registration` is `invite` |
| `code_challenge`, `code_challenge_method=S256` | optional client PKCE for `code` mode (recommended for native apps; see below) |

The state (random `state`, OIDC nonce and PKCE verifier, SAML request id,
`return_to`, mode, invite code, client challenge) is sealed with AES-256-GCM
under a key derived from `AUTH_KEY_ENCRYPTION_KEY` and stored in the
`boson_sso` cookie (`HttpOnly`, `Path=/v1/sso/`, `SSO_STATE_TTL` = 10 min).
It is `SameSite=Lax` for OIDC and `SameSite=None; Secure` for SAML, because
the IdP returns with a cross-site POST. The callback deletes it, so each flow
completes at most once; starting a second flow in the same browser replaces
the first. No flow state is kept on the server, so any replica can finish a
flow another started.

### Errors sent to `return_to`

Once `return_to` is known, errors come back as query parameters, so the client
can show them: `error` is one of

| `error` | |
|---|---|
| `access_denied` | the user cancelled, or the IdP refused |
| `sso_failed` | the IdP's answer didn't verify (signature, audience, nonce, expiry, code exchange) |
| `idp_unavailable` | discovery / metadata couldn't be fetched |
| `no_linked_account` | no account matches and the provider has `allow_signup: false` |
| `registration_closed`, `invite_required` | sign-up blocked by the network `registration` setting |
| `account_disabled` | the linked account is disabled |
| `unknown_provider` | no enabled provider with that slug |
| `server_error` | anything else (logged) |

Without a valid state cookie (expired, other browser, replay) the callback
answers `400 invalid_state` as JSON, since there is nowhere safe to redirect.

## Desktop and native clients (code exchange)

Native apps can't receive our cookies, and tokens must never travel in a URL.
They get a one-time code instead (RFC 8252 style):

1. Pick a redirect the app can receive: a loopback listener
   `http://127.0.0.1:<random port>/callback` (or `http://[::1]:…`), or a custom
   scheme `boson://sso/callback`. Both match the default
   `SSO_RETURN_TO_ALLOWED` (`http://127.0.0.1:*,http://[::1]:*,boson://`).
2. Make a PKCE pair: `verifier` = 43–128 random URL-safe characters,
   `challenge` = base64url(SHA-256(verifier)) without padding.
3. Open the system browser at
   `GET $PUBLIC_URL/v1/sso/{slug}/start?return_to=<redirect>&code_challenge=<challenge>&code_challenge_method=S256`
   (`start_url` from `GET /v1/config`).
4. The browser comes back to `<redirect>?code=bsc_…` (existing query
   parameters are kept), or `?error=…&error_description=…`.
5. `POST /v1/sso/exchange` with `{"code": "bsc_…", "code_verifier": "<verifier>"}`
   → the same JSON as `POST /v1/login`:
   `{token_type, access_token, expires_in, refresh_token, refresh_expires_in, session_id, user}`.
   The session (with the app's IP and user agent) is created at this point;
   refresh it with `POST /v1/token/refresh` as usual.

Codes are single use, live `SSO_CODE_TTL` (60 s) and are stored hashed. A
wrong verifier burns the code (`400 invalid_code`). `code_verifier` is only
checked when the start request carried a `code_challenge`; without one the
bare `{code}` works, but then any app that can catch the redirect (another
app registered for `boson://`, malware on the loopback port) could redeem it,
so **desktop clients should always send a challenge**. Web apps on other
origins can use `mode=code` and exchange with `{"code": …, "cookie": true}`
plus the `X-Requested-With` header to get cookies instead.

## Linking rules

Given provider `p` and the identity the IdP asserted (`subject`, `email`,
`email_verified`, username and display name):

1. `(p, subject)` is already linked → that user (refused if disabled). The
   identity's email, claims and `last_login_at` are updated. This works even
   when registration is closed.
2. Else if `p.trust_email` and the IdP says the email is verified and an
   account has that email **and that account's email is verified** → link the
   identity to it. Only enable `trust_email` for IdPs you control: otherwise
   anyone who can get `victim@example.com` asserted by a sloppy IdP takes over
   the account. An account with that address but an unverified email is never
   linked (someone could have registered it with a password they know).
3. Else if `p.allow_signup` and the network `registration` setting allows it
   (`open`, or `invite` with a valid `invite_code` from `start`) → create a
   user:
   - **username** from the configured claim/attribute, else
     `preferred_username` / `nickname` (OIDC) or `username` / `uid` (SAML),
     else the email's local part, else the display name, else `user`; made a
     valid IRC nick (`alice.smith@x` → `alice_smith`, leading digit → `u42`,
     cut to 30, reserved services nicks get `_`), then made unique with a
     numeric suffix (`alice2` …).
   - **email** set on the account (and marked verified) only if
     `trust_email` and the IdP says it's verified and no other account has it;
     otherwise it stays only on the identity.
   - no password (they can set one with "forgot password" once they have an
     email, or an admin can send a reset).
4. Else → `no_linked_account`.

SSO logins are **not** subject to `require_email_verification`: the IdP
authenticated the user. Sessions record `auth_method` `oidc:<slug>` or
`saml:<slug>`.

Users see and remove their links at `GET /v1/me/identities` and
`DELETE /v1/me/identities/{id}`; removing the last way to sign in (no password
and no other identity) is refused with `409 last_login_method`. Linking an
additional provider to an existing account from account settings (with the
session's user as target) is not implemented yet; today accounts get further
identities only through rule 2.

## Admin API

All under role `admin`. Responses never contain secrets.

| Method & path | |
|---|---|
| `GET /v1/admin/sso/providers` | `{providers: [provider]}` (enabled and disabled) |
| `POST /v1/admin/sso/providers` | create → 201 `{provider}`; `409 slug_taken` |
| `GET /v1/admin/sso/providers/{id}` | `{provider}` |
| `PATCH /v1/admin/sso/providers/{id}` | any of the create fields except `kind`; `config` is merged key by key (`null` removes a key) → `{provider}` |
| `DELETE /v1/admin/sso/providers/{id}` | 204; also deletes every identity linked through it |
| `POST /v1/admin/sso/providers/{id}/test` | OIDC: discovery + JWKS fetch; SAML: fetch/parse IdP metadata → `{ok, details}` (`details.error` when not ok). Works for disabled providers. |

Create body:

```json
{"slug": "google", "kind": "oidc", "display_name": "Google", "enabled": true,
 "allow_signup": true, "trust_email": true, "config": {…}}
```

`slug`: 1–32 of `a-z 0-9 -`; it is part of the callback URLs, so changing it
means updating the IdP. `display_name` defaults to the slug.

### OIDC `config`

```json
{"issuer": "https://accounts.google.com", "client_id": "…", "client_secret": "…",
 "scopes": ["openid", "email", "profile"],
 "username_claim": "preferred_username", "email_claim": "email", "display_name_claim": "name"}
```

`issuer` must be https (http is accepted for loopback hosts, or anywhere with
`SSO_ALLOW_HTTP=true` for dev). `scopes` defaults to `openid email profile`
and always includes `openid`. The claim names are optional overrides.
`client_secret` is **write-only**: it is encrypted with
`AUTH_KEY_ENCRYPTION_KEY` (AES-256-GCM, bound to the provider id) in its own
column and never returned; responses carry `has_client_secret` (top level and
in `config`). Omit it in a PATCH to keep it, send `""` to remove it (public
clients). Unknown keys are rejected. If the ID token lacks the email claim,
auth also asks the UserInfo endpoint.

Response (`provider`):

```json
{"id": "idp_…", "slug": "google", "kind": "oidc", "display_name": "Google", "enabled": true,
 "allow_signup": true, "trust_email": true,
 "config": {"issuer": "…", "client_id": "…", "scopes": ["openid","email","profile"], "has_client_secret": true},
 "has_client_secret": true,
 "start_url": "https://auth.example.com/v1/sso/google/start",
 "redirect_uri": "https://auth.example.com/v1/sso/google/callback",
 "created_at": "…", "updated_at": "…"}
```

Register `redirect_uri` at the IdP.

### SAML `config`

```json
{"idp_metadata_url": "https://idp.example.com/metadata",
 "entity_id": "https://auth.example.com/v1/sso/okta/saml/metadata",
 "name_id_format": "persistent",
 "attribute_map": {"email": "email", "username": "username", "display_name": "displayName"},
 "sign_requests": false}
```

- `idp_metadata_url` **or** `idp_metadata_xml` (the XML itself, up to 1 MiB).
  URL metadata is fetched on first use and refreshed daily (the last good copy
  is kept if a refresh fails). XML is validated on save.
- `entity_id`: the SP entity id; default = the SP metadata URL.
- `name_id_format`: `persistent` (recommended), `email`, `unspecified`, or a
  URN; empty sends no format (IdP default). `transient` is refused: it changes
  every login and would create a new account each time. Keycloak rejects
  requests without a format: use `unspecified` or `persistent` there.
- `attribute_map`: attribute `Name` or `FriendlyName` for each field. Defaults:
  email `email`, `mail`, `…/claims/emailaddress`, `urn:oid:0.9.2342.19200300.100.1.3`
  (falls back to an `emailAddress` NameID); username `username`, `uid`,
  `preferred_username`; display name `displayName`, `name`, `cn`,
  `…/identity/claims/displayname`.
- `sign_requests`: sign AuthnRequests with the SP key (some IdPs require it).

SAML has no `email_verified`: an asserted email counts as verified, so
`trust_email` means "this IdP's email attribute is authoritative".

On create, auth generates an SP key pair (RSA 2048, self-signed certificate
valid 10 years), stored encrypted like the JWT signing keys. The response adds
what the IdP needs:

```json
{"…": "…", "sp_entity_id": "https://auth.example.com/v1/sso/okta/saml/metadata",
 "acs_url": "https://auth.example.com/v1/sso/okta/saml/acs",
 "sp_metadata_url": "https://auth.example.com/v1/sso/okta/saml/metadata",
 "sp_certificate": "-----BEGIN CERTIFICATE-----…"}
```

`GET /v1/sso/{slug}/saml/metadata` (public, also while the provider is
disabled) serves the SP metadata: entity id, ACS (HTTP-POST), and the
certificate for signing and encryption. Upload it to the IdP or copy the
values. IdPs that encrypt assertions (recommended) encrypt to that
certificate.

Responses must be signed (response or assertion), answer our request id
(`InResponseTo`, kept in the state cookie), name our ACS as `Destination`,
our entity id as audience, and be inside their validity window.

## Configuring common IdPs

Replace `auth.example.com` with your `PUBLIC_URL` and `{slug}` with the slug.

**Google** (OIDC). Google Cloud console → APIs & Services → Credentials →
Create OAuth client ID → *Web application*; authorized redirect URI
`https://auth.example.com/v1/sso/google/callback`. Provider: `issuer`
`https://accounts.google.com`, the client id and secret. Google sends
`email_verified`; `trust_email: true` is reasonable for Google accounts
(for Workspace-only access, also restrict the OAuth consent screen to
*Internal*). Google has no `preferred_username`, so usernames come from the
email local part.

**GitHub.** GitHub is **not** an OpenID Connect provider for user sign-in:
"Sign in with GitHub" is plain OAuth 2.0 with no ID token and no discovery
document (GitHub's OIDC issuer only serves Actions workflow tokens), so it
can't be added as an `oidc` provider. Put a broker in between that speaks
OIDC to auth and OAuth to GitHub: Dex (`github` connector), Authentik,
Keycloak or Zitadel (GitHub as an external IdP), and add the broker here.

**Authentik** (OIDC). Applications → Providers → *OAuth2/OpenID Provider*,
client type *Confidential*, redirect URI `…/v1/sso/authentik/callback`,
scopes `openid email profile`; create an Application using it. `issuer` is
`https://authentik.example.com/application/o/<application-slug>/`. Authentik
sends `preferred_username` and `email_verified` (configurable in the
property mappings).

**Zitadel** (OIDC). Project → New application → *Web*, auth method *Code*
(PKCE is used in addition to the secret; *PKCE* only also works with an empty
`client_secret`), redirect URI `…/v1/sso/zitadel/callback`. `issuer` is your
instance URL, e.g. `https://<instance>.zitadel.cloud`. Zitadel leaves profile
claims out of the ID token unless *User Info inside ID Token* is ticked; auth
falls back to UserInfo either way.

**Keycloak** (OIDC). Realm → Clients → Create client, *OpenID Connect*,
*Client authentication* on, *Standard flow* on, valid redirect URI
`…/v1/sso/keycloak/callback`. `issuer` is
`https://keycloak.example.com/realms/<realm>`. Keycloak sends
`preferred_username` and `email_verified`.

**Okta** (OIDC or SAML). OIDC: Applications → Create App Integration → *OIDC –
Web Application*, sign-in redirect `…/callback`; `issuer`
`https://<org>.okta.com` (or `…/oauth2/default` for the default
authorization server). SAML: Create App Integration → *SAML 2.0*; *Single
sign-on URL* = `acs_url`, *Audience URI (SP Entity ID)* = `sp_entity_id`,
*Name ID format* = Persistent (or EmailAddress), *Application username* =
Okta username; attribute statements `email` → `user.email`, `username` →
`user.login`, `displayName` → `user.displayName`. Then copy the app's
*Metadata URL* into `idp_metadata_url`.

**Microsoft Entra ID** (OIDC or SAML). OIDC: App registrations → New
registration, *Web* redirect URI `…/callback`, create a client secret;
`issuer` `https://login.microsoftonline.com/<tenant-id>/v2.0`. Entra's
`email` claim is not verified by Microsoft for every account type; leave
`trust_email` off unless your tenant controls the domains. SAML: Enterprise
applications → New application → *Create your own* → *Non-gallery*; Single
sign-on → SAML; *Identifier (Entity ID)* = `sp_entity_id`, *Reply URL* =
`acs_url`; *Unique User Identifier* = `user.objectid` with name format
Persistent (recommended; UPNs can be renamed). Copy *App Federation Metadata
Url* into `idp_metadata_url`. Entra's default claim names
(`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`,
`…/identity/claims/displayname`) are covered by the default `attribute_map`;
for the username map `username` to e.g.
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`.

## Code layout

| Piece | Where |
|---|---|
| `identity_providers` (+ `client_secret_enc`, `sp_key_enc`, `sp_cert`), `user_identities`, `sso_login_codes` | `db/migrations/000001_initial.up.sql`, `000003_sso.up.sql` |
| Repositories | `internal/db/repositories/identity`, `…/ssocode` |
| `IdentityProvider`, `Kind`, `Registry` | `internal/services/idp` |
| OIDC kind | `internal/services/idp/oidc` |
| SAML kind | `internal/services/idp/saml` |
| Flow, linking rules, code exchange, admin, identities | `internal/services/sso` |
| HTTP | `http/handlers/sso.go` |

A provider kind implements `idp.Kind` (`Normalize` validates the stored
config, `Build` makes an `IdentityProvider` without network I/O) and is
registered in `http/server.go`. The registry keeps built providers until their
row's `updated_at` changes, so discovery documents and metadata stay cached;
every replica reloads the rows every 30 s, and on an unknown slug.

## Testing

- `test/integration/sso_oidc_test.go` runs the browser flow against
  `oauth2-proxy/mockoidc` (a real OIDC server in-process: discovery, JWKS,
  PKCE, nonce, code exchange).
- `test/integration/sso_saml_test.go` runs it against `crewjam/saml/samlidp`
  (a complete SAML IdP with a login form; signed responses, encrypted
  assertions), including tampering and cross-browser replays.
- `test/integration/sso_dex_test.go` runs it against a real **Dex**
  (`make test-dex-up`, config in `test/dex/config.yaml`; CI starts it too).

## IRC SASL

`POST /internal/v1/verify-password` (internal listener, `X-Internal-Token`)
answers `{ok, user_id, username, reason}` for SASL PLAIN. SSO-only users have
no password; a later phase can add app passwords or SASL `OAUTHBEARER` that
accepts our access tokens (verify via JWKS, `aud=boson`).
