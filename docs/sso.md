# SSO design (phases 2 and 3)

Phase 1 ships the storage, the Go interface and the registry. No concrete
provider exists yet, so `GET /v1/config` always lists `sso_providers: []`.

## What exists

| Piece | Where |
|---|---|
| `identity_providers` table: `kind` (`oidc`/`saml`), `slug`, `display_name`, `config jsonb`, `enabled`, `allow_signup`, `trust_email` | `db/migrations/000001_initial.up.sql` |
| `user_identities` table: `(provider_id, subject)` unique, `email`, `raw_claims`, `last_login_at` | same |
| Repository | `internal/db/repositories/identity` |
| `IdentityProvider` interface, `ExternalIdentity`, `Factory`, `Registry`, `IdPService` | `internal/services/idp` |
| `sessions.auth_method` | `password` now; `oidc:<slug>` / `saml:<slug>` later |

```go
type IdentityProvider interface {
    Kind() string
    Slug() string
    DisplayName() string
    BeginLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, state string) error
    CompleteLogin(ctx context.Context, r *http.Request) (ExternalIdentity, error)
}
```

## Plugging in a provider

1. Add `internal/services/idp/oidc` (or `saml`) with a `Factory`:
   `func NewFactory(...) idp.Factory`, which parses `identity_providers.config`
   into a typed struct and returns an `IdentityProvider`.
2. In `http/server.go`, register it before `idpService.Reload`:
   `registry.RegisterFactory(identity.KindOIDC, oidc.NewFactory(httpClient, cfg))`.
3. Add the HTTP routes (public listener):
   - `GET /v1/sso/{slug}/start`: create a random `state`, store it in a
     short-lived HttpOnly `SameSite=Lax` cookie (plus the PKCE verifier and
     nonce for OIDC), then call `BeginLogin`.
   - `GET /v1/sso/{slug}/callback` (OIDC) or `POST /v1/sso/{slug}/acs` (SAML):
     check `state` against the cookie in constant time, call `CompleteLogin`,
     link or create the user (below), then `session.Create(ctx, userID,
     "oidc:"+slug)` and set the same cookies as `/v1/login` in cookie mode.
     Redirect to `APP_URL`.
4. Admin CLI/API to create rows in `identity_providers`. Keep client secrets
   out of the jsonb: store the **name** of an env var (e.g.
   `"client_secret_env": "OIDC_GOOGLE_SECRET"`) and read it at factory time.

### OIDC (phase 2): `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2`

`config` jsonb: `{"issuer": "...", "client_id": "...", "client_secret_env": "...", "scopes": ["openid","email","profile"], "username_claim": "preferred_username"}`.

- Factory: `oidc.NewProvider(ctx, issuer)` (discovery), build an
  `oauth2.Config{Endpoint: provider.Endpoint(), RedirectURL: PUBLIC_URL+"/v1/sso/"+slug+"/callback"}`
  and `provider.Verifier(&oidc.Config{ClientID: clientID})`.
- `BeginLogin`: `AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))`, 302.
- `CompleteLogin`: `Exchange(ctx, code, oauth2.VerifierOption(verifier))`,
  take `id_token`, `verifier.Verify`, check `nonce`, read `sub`, `email`,
  `email_verified`, `preferred_username`, `name` into `ExternalIdentity`.
- Issuer + `sub` is the identity; never key on email.

### SAML (phase 3): `github.com/crewjam/saml`

`config` jsonb: `{"idp_metadata_url": "...", "sp_entity_id": "...", "email_attribute": "...", "username_attribute": "..."}`.
The SP signing key/cert should be generated and stored like the JWT keys
(encrypted with `AUTH_KEY_ENCRYPTION_KEY`), not in jsonb.

- Factory: fetch and parse IdP metadata (`samlsp.FetchMetadata`), build a
  `saml.ServiceProvider` with ACS URL `PUBLIC_URL+"/v1/sso/"+slug+"/acs"`.
- `BeginLogin`: `MakeAuthenticationRequest` + redirect/POST binding with
  `RelayState = state`; remember the request ID (cookie) for
  `InResponseTo` checking.
- `CompleteLogin`: `ParseResponse(r, []string{requestID})` (it validates the
  signature, audience, destination and time window); `NameID` (persistent
  format) is the subject; attributes fill email/username.
- Serve SP metadata at `GET /v1/sso/{slug}/metadata`.

## Linking rules (`IdPService.LinkOrCreate`, to build in phase 2)

Given provider `p` and `ExternalIdentity x`:

1. `user_identities (p.id, x.Subject)` exists → that user (refuse if
   disabled). Update `email`, `raw_claims`, `last_login_at`.
2. Else if `p.trust_email` and `x.EmailVerified` and a user has that email →
   link to that user. Only for IdPs you control; otherwise an attacker who
   can register `victim@example.com` at a sloppy IdP takes over the account.
3. Else if `p.allow_signup` → create a user: username from `username_claim`
   run through `nick.Validate` (on failure or collision, add a numeric
   suffix or send the user to a "pick a username" step); email set and
   marked verified only if `x.EmailVerified && p.trust_email`. No password
   credential is created (password login stays impossible until a reset).
4. Else → error "no account linked to this login".

Logged-in users can also link a provider explicitly from account settings
(same flow, with the session's user as the target), which is the safe way
to attach an untrusted IdP to an existing account.

## IRC SASL (phase 4)

`POST /internal/v1/verify-password` (internal listener, `X-Internal-Token`)
already answers `{ok, user_id, username, reason}` for SASL PLAIN. The bridge
(an Anope module or UnrealIRCd `authprompt`/external SASL agent) calls it.
SSO-only users have no password; phase 4 can add app passwords or SASL
`OAUTHBEARER` that accepts our access tokens (verify via JWKS, `aud=boson`).
