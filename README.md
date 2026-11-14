# boson auth

The account and token service for [boson](https://github.com/boson-chat/stack):
registration, email verification, password login, sessions with rotating
refresh tokens, password reset, an admin API, and Ed25519-signed JWTs that
other boson services (voice, later video and the admin panel) verify through
a public JWKS. It is ready for SSO (OIDC/SAML tables and interfaces) and for
IRC SASL (internal password-check API).

- Go 1.27, plain REST/JSON on `net/http`, Postgres via GORM, embedded
  golang-migrate migrations, zerolog, OpenTelemetry metrics (Prometheus).
- Two listeners: **public** `:8080` (behind Caddy) and **internal** `:8081`
  (`/metrics`, `/internal/v1/*`; never publish it).

## Running locally

```sh
cp .env.example .env
go run ./cmd keys gen-kek      # paste into AUTH_KEY_ENCRYPTION_KEY in .env
make setup                     # Postgres + Mailpit in Docker, migrations
make run                       # http://localhost:8080, internal on :8081
```

Mail lands in Mailpit at http://localhost:8025. Create an admin:

```sh
go run ./cmd user create --username admin --email admin@example.com --role admin
```

Everything in Docker instead: `docker compose --profile app up -d --build`.

Tests:

```sh
make test                                  # unit tests (integration tests skip)
make test-pg-up test-integration test-pg-down   # + full HTTP flows on a throwaway Postgres
```

The integration suite needs `TEST_DATABASE_URL` pointing at a Postgres
where the user may `CREATE DATABASE`; each test gets its own database.

## API

All bodies are JSON (`Content-Type: application/json` is required).
Errors are `{"error": "<code>", "message": "<text>"}`.

Clients authenticate with `Authorization: Bearer <access_token>` or, in
browsers, with the HttpOnly cookies set by cookie-mode login (see
[Browsers](#browsers-cookies-and-csrf)).

### Public listener (`HTTP_ADDR`, default `:8080`)

| Method & path | Auth | Body → response |
|---|---|---|
| `GET /healthz` | – | liveness |
| `GET /readyz` | – | DB reachable and a signing key loaded |
| `GET /version` | – | build version as `text/plain` (`1.3.0\n`) |
| `GET /.well-known/jwks.json` | – | public keys, `Cache-Control: public, max-age=300` |
| `GET /.well-known/openid-configuration` | – | `{issuer, jwks_uri, id_token_signing_alg_values_supported}` |
| `GET /v1/config` | – | `{registration, require_email_verification, channel_creation, voice_channel_creation, sso_providers}` (live [network settings](#network-settings)) |
| `POST /v1/register` | – | `{username, email, password, invite_code?}` → 201 `{user, email_verification_sent, email_verification_required}` |
| `POST /v1/email/verify` | – | `{token}` → `{user}` |
| `POST /v1/email/resend` | optional | `{email}` (or a bearer token) → 202, same response whether or not the account exists |
| `POST /v1/login` | – | `{login, password, cookie?}` (`login` = username or email) → `{token_type, access_token, expires_in, refresh_token, refresh_expires_in, session_id, user}` |
| `POST /v1/token/refresh` | – | `{refresh_token}` or the refresh cookie → same shape as login, with a **new** refresh token |
| `POST /v1/logout` | bearer, or `{refresh_token}`/cookie | revokes the session → 204 |
| `POST /v1/password/forgot` | – | `{email}` → 202, identical whether or not the account exists |
| `POST /v1/password/reset` | – | `{token, new_password}` → signs out every session |
| `POST /v1/password/change` | bearer | `{current, new}` → signs out every *other* session |
| `GET /v1/me` | bearer | `{user, session_id}` |
| `PATCH /v1/me` | bearer | `{display_name}` → `{user}` |
| `GET /v1/sessions` | bearer | `{sessions: [{id, auth_method, ip, user_agent, created_at, last_seen_at, expires_at, current}]}` |
| `DELETE /v1/sessions/{id}` | bearer | revoke one of your sessions → 204 (other users' ids are 404) |
| `POST /v1/voice/token` | bearer | `{rooms?: [string]}` → `{token, expires_in, audience: "quicvoice"}` |
| `GET /verify-email`, `GET /reset-password` | – | built-in pages for the email links (used when `APP_URL` = `PUBLIC_URL`) |

Admin (role `admin`, checked against the database on every request):

| Method & path | |
|---|---|
| `GET /v1/admin/users?q=&limit=&offset=` | search users (username/email substring) → `{users, total}` |
| `POST /v1/admin/users` | `{username, email?, role?, password? \| send_invite_email?}` → 201 `{user, invite_email_sent}`. The email is marked verified. `send_invite_email` (needs `email`; not with `password`) mails a "choose your password" link valid `ACCOUNT_SETUP_TTL`; with neither the account has no password. `409 username_taken\|email_taken`, `400 invalid_username\|weak_password\|invalid_request` |
| `GET /v1/admin/users/{id}` | one user |
| `POST /v1/admin/users/{id}/password-reset` | email the user a reset link (same link and page as forgot-password; earlier links stop working) → 202. `400 no_email`, `409 account_disabled`, `404` |
| `POST /v1/admin/users/{id}/verification` | resend the verification email → 202. `409 already_verified`, `400 no_email`, `409 account_disabled`, `404` |
| `PATCH /v1/admin/users/{id}` | `{role: "user"\|"admin"}` |
| `POST /v1/admin/users/{id}/disable` | disable and revoke every session |
| `POST /v1/admin/users/{id}/enable` | re-enable |
| `GET /v1/admin/users/{id}/sessions` | active sessions |
| `DELETE /v1/admin/sessions/{id}` | revoke any session |
| `GET /v1/admin/invites`, `POST /v1/admin/invites` `{max_uses, ttl, note}`, `DELETE /v1/admin/invites/{id}` | invite codes (the code is only in the create response) |
| `GET /v1/admin/audit?event=&actor=&target=&user_id=&since=&until=&cursor=&limit=` | audit log, newest first → `{entries, next_cursor}` ([below](#audit-log-api)) |
| `GET /v1/admin/settings` | network settings → `{registration, require_email_verification, channel_creation, voice_channel_creation, updated_at, updated_by}` |
| `PATCH /v1/admin/settings` | same fields, any subset → the updated object; `400 invalid_request` on unknown values; audit event `settings_updated` with `meta.old` / `meta.new` (changed fields only) |

### Internal listener (`INTERNAL_ADDR`, default `:8081`)

| Method & path | |
|---|---|
| `GET /healthz`, `GET /readyz`, `GET /version` | as above |
| `GET /metrics` | Prometheus exposition |
| `GET /internal/v1/settings` | header `X-Internal-Token`; the [network settings](#network-settings) object (same as `GET /v1/admin/settings`). For Ergo and quicvoiced. |
| `POST /internal/v1/verify-password` | header `X-Internal-Token: $INTERNAL_API_TOKEN`; `{username, password}` → `{ok, user_id?, username?, reason?}` (`reason`: `invalid_credentials` \| `account_disabled` \| `email_not_verified`). For IRC SASL PLAIN. Disabled (503) when `INTERNAL_API_TOKEN` is empty. |

The caller may forward the end user's address in `X-Forwarded-For` (Ergo's auth-script helper does). Because the caller is authenticated by `INTERNAL_API_TOKEN`, auth trusts that value: it is recorded in the audit log and used for an extra per-IP limit (`RATE_LIMIT_IP_*` ×2), so one IRC client can't spray many accounts. Without the header only the per-account limit applies, so the IRC server's own shared address is never limited.

### Network settings

Four settings can be changed at runtime by admins (`PATCH /v1/admin/settings`)
and are stored in `network_settings`. Until an admin sets one, it follows its
env variable, so env values are the defaults:

| Field | Values | Env default | Enforced by |
|---|---|---|---|
| `registration` | `open` \| `invite` \| `closed` | `REGISTRATION` | auth (`/v1/register`, SSO sign-up) |
| `require_email_verification` | bool | `REQUIRE_EMAIL_VERIFICATION` | auth (password login and `/internal/v1/verify-password`) |
| `channel_creation` | `registered` \| `admins` | `CHANNEL_CREATION` (`registered`) | IRC (Ergo): who may create text channels |
| `voice_channel_creation` | `admins` \| `founders` \| `registered` | `VOICE_CHANNEL_CREATION` (`founders`) | quicvoiced: admins only; the founder of an IRC channel may create voice channels under it; or any registered user |

```json
{"registration":"open","require_email_verification":true,"channel_creation":"registered",
 "voice_channel_creation":"founders","updated_at":"2026-11-13T21:04:05.123456Z","updated_by":"usr_01J…"}
```

`updated_at` / `updated_by` are `null` until the first change. Each replica
caches the row for `SETTINGS_CACHE_TTL` (5 s); the replica that handled the
PATCH sees it at once. auth only enforces the first two; the channel settings
are published for the IRC and voice services (`GET /internal/v1/settings`,
cache them a few seconds too) and for clients (`GET /v1/config`).

### Audit log API

`GET /v1/admin/audit` returns `{"entries": [...], "next_cursor": "…" | null}`,
newest first, `limit` 1–200 (default 50). Pass `next_cursor` back as `cursor`
for the next page (keyset pagination on `(at, id)`, stable while new events
arrive). Filters, all optional and combinable:

| Param | |
|---|---|
| `event` | event name, or several comma-separated (`login,login_failed`) |
| `actor` | user id or username: who did it (`user_id` column) |
| `target` | user id or username: whom an admin action was about |
| `user_id` | user id or username: either of the two (everything about one user) |
| `since`, `until` | RFC 3339 timestamps, `since <= at < until` |

An unknown username matches nothing (empty page, not an error). Each entry:

```json
{"id":"aud_…","event":"admin_user_disabled","at":"…","ip":"203.0.113.9","meta":{"user_id":"usr_B","sessions_revoked":2},
 "user_id":"usr_A","actor_user_id":"usr_A","actor_username":"alice","target_user_id":"usr_B","target_username":"bob"}
```

`user_id` = `actor_user_id` (kept for 1.2 clients). For self-service events
(login, register, password change) the actor is the user and the target is
`null`; failed logins for an existing account carry that account as the actor.
Usernames are `null` when the user was deleted or unknown.

### Errors and status codes

`400 invalid_request|invalid_username|weak_password|invalid_token|no_email`,
`401 invalid_credentials|unauthenticated|invalid_refresh_token`,
`403 email_not_verified|account_disabled|forbidden|csrf|registration_closed|invite_required|invalid_password`,
`409 username_taken|email_taken|already_verified|account_disabled` (admin actions on a disabled account), `415 unsupported_media_type`,
`429 rate_limited` (with `Retry-After`).

`account_disabled` and `email_not_verified` are only returned after the
password has been checked, so they reveal nothing to someone guessing.

## Tokens

All JWTs are signed with **EdDSA (Ed25519)** and carry a `kid` header.
Keys are published at **`$PUBLIC_URL/.well-known/jwks.json`** as
`{"kty":"OKP","crv":"Ed25519","x":"…","kid":"key_…","alg":"EdDSA","use":"sig"}`.
`aud` is always a single string.

### Access token (this service and the web/admin apps)

Header `{"alg":"EdDSA","kid":"key_…","typ":"at+jwt"}`

| Claim | Value |
|---|---|
| `iss` | `ISSUER` (defaults to `PUBLIC_URL`, e.g. `https://auth.example.com`) |
| `sub` | user id, `usr_<ULID>` |
| `aud` | `"boson"` |
| `sid` | session id, `ses_<ULID>` |
| `name` | username (= IRC nick) |
| `role` | `user` \| `admin` |
| `iat`, `nbf`, `exp` | `exp` = `iat` + `ACCESS_TOKEN_TTL` (15 min) |
| `jti` | `jti_<ULID>` |

Refresh tokens are opaque (`bsr_` + 256 random bits, base64url), never
embedded in JWTs, and stored only as SHA-256.

### Voice token (quicvoiced)

Header `{"alg":"EdDSA","kid":"key_…","typ":"JWT"}`

| Claim | Value |
|---|---|
| `iss` | same issuer |
| `sub` | user id |
| `aud` | `"quicvoice"` |
| `name` | username |
| `role` | `speaker`; `moderator` for admins (quicvoiced roles: listener < speaker < moderator < admin) |
| `rooms` | from the request body; **omitted** when empty (= any room) |
| `sid`, `iat`, `nbf`, `jti` | as above |
| `exp` | `iat` + `VOICE_TOKEN_TTL` (5 min) |

### Verifying tokens in other services

quicvoiced (and anything else) must check:

1. `alg` is exactly `EdDSA` (reject everything else, including `none`/`HS256`).
2. Look up `kid` in the JWKS from `$PUBLIC_URL/.well-known/jwks.json`
   (in the compose stack: `http://auth:8080/.well-known/jwks.json`). Cache it
   about 5 minutes; on an unknown `kid`, refetch (rate-limited) before failing.
3. `iss` equals the configured issuer, `aud` equals your audience
   (`quicvoice` for voice, `boson` for the API), `exp` is in the future
   (allow ~30 s skew), `sub` is non-empty.

The distinct audiences (plus `typ: at+jwt` on access tokens) stop a voice
token from being used against the API and vice versa. Discovery at
`/.well-known/openid-configuration` returns `issuer` and `jwks_uri`, so
standard JWKS libraries work (e.g. `github.com/MicahParks/keyfunc/v3` with
`github.com/golang-jwt/jwt/v5`).

Access tokens are stateless for other services: a revoked session stays
valid there until `exp` (≤ 15 min). This service itself checks the session
and the user's disabled flag on every request.

### Signing keys

- Created on first start, encrypted at rest (AES-256-GCM with
  `AUTH_KEY_ENCRYPTION_KEY`, bound to the `kid`).
- Rotated every `KEY_ROTATION` (30 days). The successor is published in the
  JWKS `KEY_PUBLISH_LEAD` (15 min) **before** it starts signing, so cached
  JWKS copies already contain it.
- Retired keys stay in the JWKS for the longest token TTL plus 10 minutes.
- Replicas coordinate through a Postgres advisory lock; only one creates a
  key, the others reload every minute (and on an unknown `kid`).
- `auth keys rotate` schedules a rotation; `auth keys rotate --now` signs
  with a new key immediately (after a suspected compromise). Losing
  `AUTH_KEY_ENCRYPTION_KEY` makes the stored keys unusable: the service
  refuses to start rather than silently minting new ones.

## Browsers: cookies and CSRF

- `POST /v1/login` with `"cookie": true` (and `POST /v1/token/refresh`
  without a body token) set `boson_at` (access, `Path=/`) and `boson_rt`
  (refresh, `Path=/v1`) as `HttpOnly; SameSite=Lax; Secure` cookies and leave
  the tokens out of the JSON body.
- Any state-changing request that relies on cookies must send an
  `X-Requested-With` header (any value). Cross-site forms can't set it, and
  cross-origin scripts can't either unless the origin is in
  `CORS_ALLOWED_ORIGINS`. Bearer-token requests don't need it.
- JSON-only bodies are a second CSRF barrier: HTML forms can't send
  `application/json`.

## Configuration

Everything is an environment variable. Durations use Go syntax (`15m`,
`720h`); there is no `d` unit, so 30 days is `720h`.

| Variable | Default | |
|---|---|---|
| `ENV` | `development` | `development` = console logs; anything else = JSON |
| `VERSION` | `dev` | reported in logs and metrics (set by the image) |
| `LOG_LEVEL` | `info` | zerolog level |
| `SITE_NAME` | `boson` | product name in emails |
| `HTTP_ADDR` | `:8080` | public listener |
| `INTERNAL_ADDR` | `:8081` | internal listener (`/metrics`, `/internal/v1`) |
| `PUBLIC_URL` | `http://localhost:8080` | external URL of this service; `jwks_uri` is built from it |
| `APP_URL` | `PUBLIC_URL` | base of email links: `$APP_URL/verify-email#token=…`, `$APP_URL/reset-password#token=…` |
| `TRUSTED_PROXIES` | – | comma-separated CIDRs/IPs whose `X-Forwarded-For` is honoured (e.g. the Caddy container network) |
| `CORS_ALLOWED_ORIGINS` | origin of `APP_URL` | comma-separated origins allowed to make credentialed requests |
| `COOKIE_SECURE` | `true` | set `false` only for plain-http dev |
| `COOKIE_DOMAIN` | – | cookie `Domain`; empty = host-only |
| `DATABASE_URL` | – | `postgres://…`; wins over the `DB_*` parts |
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` / `DB_SSLMODE` | `localhost` / `5432` / `auth` / – / `auth` / `disable` | used when `DATABASE_URL` is empty |
| `DB_MAX_CONNS` | `20` | pool size |
| `AUTO_MIGRATE` | `true` | run migrations on `serve` |
| `ISSUER` | `PUBLIC_URL` | `iss` claim; keep equal to `PUBLIC_URL` so OIDC discovery works |
| `ACCESS_TOKEN_TTL` | `15m` | |
| `REFRESH_TOKEN_TTL` | `720h` | idle lifetime; each refresh issues a new token |
| `SESSION_MAX_AGE` | `2160h` | absolute session lifetime (90 days) |
| `VOICE_TOKEN_TTL` | `5m` | |
| `KEY_ROTATION` | `720h` | signing-key lifetime |
| `KEY_PUBLISH_LEAD` | `15m` | publish new keys this long before they sign (keep above JWKS cache time) |
| `AUTH_KEY_ENCRYPTION_KEY` | **required** | 32 random bytes, base64 (`auth keys gen-kek`) |
| `REGISTRATION` | `open` | default for the `registration` network setting: `open` \| `invite` \| `closed` |
| `REQUIRE_EMAIL_VERIFICATION` | `true` | default for `require_email_verification`: block password login (and SASL) until the email is verified |
| `CHANNEL_CREATION` | `registered` | default for `channel_creation`: `registered` \| `admins` |
| `VOICE_CHANNEL_CREATION` | `founders` | default for `voice_channel_creation`: `admins` \| `founders` \| `registered` |
| `SETTINGS_CACHE_TTL` | `5s` | how long a replica caches the network settings |
| `ACCOUNT_SETUP_TTL` | `72h` | lifetime of the "choose your password" link for admin-created accounts |
| `EMAIL_VERIFY_TTL` | `24h` | |
| `PASSWORD_RESET_TTL` | `30m` | |
| `ARGON2_MEMORY_KIB` / `ARGON2_ITERATIONS` / `ARGON2_PARALLELISM` | `65536` / `3` / `2` | argon2id cost for new hashes; old hashes upgrade on next login |
| `SMTP_HOST` | – | empty = log links instead of sending (dev only) |
| `SMTP_PORT` | `587` | |
| `SMTP_USER` / `SMTP_PASSWORD` | – | auth is used when `SMTP_USER` is set |
| `SMTP_FROM` | `boson <no-reply@localhost>` | |
| `SMTP_TLS` | `starttls` | `starttls` (required) \| `tls` (implicit, 465) \| `none` (dev, e.g. Mailpit) |
| `INTERNAL_API_TOKEN` | – | shared secret for `/internal/v1/*`; empty disables it |
| `RATE_LIMIT_ENABLED` | `true` | |
| `RATE_LIMIT_IP_BURST` / `RATE_LIMIT_IP_PER_MINUTE` | `20` / `10` | per client IP, per endpoint group |
| `RATE_LIMIT_ACCOUNT_BURST` / `RATE_LIMIT_ACCOUNT_PER_MINUTE` | `5` / `2` | per username/email, per endpoint group (internal API: double) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | – | enable OTLP push in addition to Prometheus |
| `OTEL_EXPORTER_OTLP_PROTOCOL` / `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` | `http/protobuf` | or `grpc` |
| `OTEL_METRICS_EXPORTER` | – | `none` disables OTLP push |
| `TEST_DATABASE_URL` | – | tests only: enables the integration suite |

Rate-limited endpoint groups: login (and password change), register,
forgot, reset, verify/resend, internal verify-password.

### Per-account login limit (for admins)

Every login is checked against two token buckets: one per client IP and one
per account (the lower-cased email or RFC 1459-folded username that was
typed). The account bucket allows `RATE_LIMIT_ACCOUNT_BURST` (5) attempts at
once, refilling at `RATE_LIMIT_ACCOUNT_PER_MINUTE` (2) per minute, and counts
attempts whether or not the password was right. A user who sees
`429 rate_limited` waits the `Retry-After` seconds (at most about 30 s with the
defaults); nothing is stored, there is no lockout to clear, and restarting
the service resets every bucket. Admin actions (password reset, disable)
don't touch the buckets. Because anyone can spend a known account's bucket,
an attacker can slow that user's logins down but never lock them out for
longer than the refill time. The IRC SASL check (`/internal/v1/verify-password`)
has its own bucket with twice the limits.

## CLI

```text
auth serve                                   run both listeners
auth migrate up | down [--steps N | --all]
auth user create --username U [--email E] [--role admin] [--password-stdin | --no-password]
auth user list [query] | set-role <user> <role> | disable <user> | enable <user> | revoke-sessions <user>
auth keys list | rotate [--now] | gen-kek
auth invite create [--uses N] [--ttl 168h] [--note ..] | list | revoke <id>
```

In the container: `docker compose exec auth ./auth user create --username admin --role admin`.

## Metrics

On the internal listener's `/metrics` (and OTLP if configured), plus Go runtime metrics:

| Metric | Labels |
|---|---|
| `auth_login_attempts_total` | `method` (`password`, `internal`), `outcome` (`success`, `invalid_credentials`, `disabled`, `unverified`) |
| `auth_registrations_total` | `outcome` (`success`, `rejected`, `error`) |
| `auth_token_refreshes_total` | `outcome` (`success`, `invalid`, `expired`, `reuse`, `disabled`, `error`) |
| `auth_token_refresh_reuse_total` | – |
| `auth_emails_sent_total` | `purpose` (`verify_email`, `reset_password`), `outcome` |
| `auth_rate_limit_hits_total` | `bucket` |
| `auth_password_resets_total` | `outcome` |

## Security notes

- **Passwords:** argon2id (64 MiB, t=3, p=2) in PHC strings; 10–256
  characters; must not equal the username or email. Unknown accounts get a
  dummy hash so timing matches; failures all return `invalid_credentials`.
- **Refresh tokens** rotate on every use. Presenting a used token revokes the
  whole token family and the session (theft detection). Two tabs racing to
  refresh the same token will trip this; browser clients should serialise
  refreshes. Concurrent refreshes are serialised with row locks.
- **Email tokens** (verify 24 h, reset 30 min) are single use, stored hashed,
  and carried in the URL **fragment**, which never reaches server logs or
  `Referer`. A new reset link invalidates older ones; a successful reset
  revokes every session and marks the email verified.
- **Password reset** looks the account up by email and sends only to the
  stored address. `forgot` and `resend` answer identically for unknown
  accounts and send mail in the background so timing doesn't differ.
  Registration does say `email_taken` / `username_taken` (usernames are
  public IRC nicks anyway); both are rate-limited.
- **Lookups never return empty structs:** repositories return `ErrNotFound`,
  tokens without `sub`/`sid` are rejected, and sessions are checked for every
  authenticated request.
- **Usernames** follow IRC nick rules and are unique under RFC 1459
  casemapping (`[Bot]` and `{bot}` collide). Services nicks (`NickServ`,
  `ChanServ`, …) are reserved.
- **Client IPs** come from `X-Forwarded-For` only when the peer is in
  `TRUSTED_PROXIES`, using the rightmost untrusted hop.
- **Rate limits** are in memory per replica. Per-account limits also let
  someone slow down logins for a known username (by design, to stop
  password guessing).
- **Internal API** compares its token in constant time and lives on a
  separate listener; don't publish `INTERNAL_ADDR`.
- **Audit log** (`audit_log`): registrations, logins, failed logins (reason
  only, never the attempted password or login string), reuse detections,
  resets, password changes, session revocations, admin actions (with the
  target user in `target_user_id`), settings changes (old and new values).
- **Network settings** are only writable by admins, validated against fixed
  value sets, and audit-logged. A stale replica serves the old value for at
  most `SETTINGS_CACHE_TTL`.
- **Admin-created accounts** get a verified email (the admin vouches for it).
  The "choose your password" email is an ordinary single-use reset token
  (`ACCOUNT_SETUP_TTL`), so passwords never travel by email, and the admin
  never learns one unless they set it.

## Layout

```text
cmd/main.go                  → internal/commands (cobra)
config/                      env-tag config (configor)
db/                          embedded migrations (golang-migrate)
http/server.go               dependency wiring + listeners
http/handlers, http/middleware
internal/services/*          business logic (*ServiceImpl interfaces)
internal/db/repositories/*   data access (*RepositoryImpl), used only by services
internal/{nick,password,keycrypt,ratelimit,opaque,ids,mailer,...}
metrics/                     OpenTelemetry instruments + Prometheus exporter
test/integration/            HTTP flows against real Postgres
docs/sso.md                  how OIDC / SAML / SASL plug in
```

## Roadmap

- **Phase 2, OIDC:** providers via `coreos/go-oidc/v3` + `x/oauth2`, account linking rules, `/v1/sso/{slug}/start|callback`.
- **Phase 3, SAML:** `crewjam/saml` service provider.
- **Phase 4, IRC SASL:** Anope/UnrealIRCd bridge calling `/internal/v1/verify-password`.

See [docs/sso.md](docs/sso.md).
