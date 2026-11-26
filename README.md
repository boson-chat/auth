# boson auth

The account and token service for [boson](https://github.com/boson-chat/stack):
registration, email verification, password login, sessions with rotating
refresh tokens, password reset, sign-in through OIDC and SAML identity
providers, runtime network settings, network roles and permissions (mapped
to IRC oper classes and vhosts), an admin API, and Ed25519-signed JWTs
that other boson services (voice, later video and the admin panel) verify
through a public JWKS. IRC SASL uses the internal password-check API.
On an existing IRC network, accounts can instead be the network's NickServ
accounts ([NickServ backend](docs/nickserv.md), `ACCOUNT_BACKEND=nickserv`).
Users of other Boson servers can sign in with their home account
([federated login](docs/federation.md)): auth issues assertions for its
own users and accepts them from trusted servers.

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

Mail lands in Mailpit at http://localhost:8025. Create the network Owner:

```sh
go run ./cmd user create --username admin --email admin@example.com --role owner
```

Everything in Docker instead: `docker compose --profile app up -d --build`.

Tests:

```sh
make test                                  # unit tests (integration tests skip)
make test-pg-up test-integration test-pg-down   # + full HTTP flows on a throwaway Postgres
make test-dex-up                           # optional: a real OIDC IdP (Dex) for TestOIDCAgainstDex
make test-nickserv                         # NickServ strategies vs real Anope/Atheme/InspIRCd/ngircd in Docker
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
| `GET /v1/config` | – | `{registration, require_email_verification, channel_creation, voice_channel_creation, channel_auto_register, channel_expiry_days, guest_access, guest_voice, sso_providers: [{slug, kind, display_name, start_url}], branding_url, files_url, channels: [{name, topic, autojoin, restricted?}]}` (live [network settings](#network-settings); `guest_voice` here is `guest_access && guest_voice`; enabled [SSO providers](#single-sign-on); `branding_url` is `GET /v1/branding`'s URL, or `null` without branding; `files_url` is the network's [files (uploads) service](#configuration), `FILES_PUBLIC_URL`, or `null` when it has none or uploads are off; `channels` are the [network channels](docs/roles.md#network-channels) from `irc.channels`, `[]` when none (treat a missing field, older auth, as `[]`); `restricted: true` on a channel only some roles may join, which roles isn't public; `accounts: {backend: "local"\|"nickserv", signup, signup_message, password_reset}`: where accounts live and whether sign-up and password reset work here ([NickServ backend](docs/nickserv.md#sign-up)); treat a missing field as the local backend) |
| `GET /v1/branding` | – | the network theme (boson-theme/1) with absolute image URLs; CORS `*`, `ETag`/`If-None-Match` → 304; 404 `no_branding` when not configured ([branding](docs/branding.md)) |
| `GET /v1/branding/assets/{file}` | – | a branding image (only files the branding names); `?v=<hash>` → cached for a year; `nosniff`, strict CSP for SVG |
| `GET /.well-known/boson-federation.json` | – | the `federation` section for boson.json `{version, issuer, jwks_uri, assertion_endpoint, login_endpoint, accepts}`; CORS `*` ([federation](docs/federation.md#discovery-bosonjson)) |
| `POST /v1/federation/assertions` | bearer | `{audience}` → `{assertion, expires_in}`: a signed assertion (`typ boson-fed+jwt`, 5 min) about the caller for another Boson server; CORS `*` ([details](docs/federation.md#home-post-v1federationassertions)) |
| `POST /v1/federation/login` | – | `{assertion, cookie?}` → the `/v1/login` response plus `{federated: true, identity, handle}`: sign in a user of another Boson server; CORS `*` ([details](docs/federation.md#remote-post-v1federationlogin)) |
| `GET /v1/users/{handle}/identity`, `POST /v1/users/identities` `{handles}` | – | whether handles are [federated accounts](docs/federation.md#identity-lookup) and whose: `{handle, federated, identity, home_domain}` (batch: `{identities: {handle: …}}`, ≤ 200); unknown = local; CORS `*`, rate-limited per IP |
| `POST /v1/register` | – | `{username, email, password, invite_code?, return_to?}` → 201 `{user, email_verification_sent, email_verification_required}` (NickServ backend: registers a NickServ account and adds `verification: "nickserv_code"\|""`, `message`, or `403 registration_unavailable`; [details](docs/nickserv.md#sign-up)) |
| `POST /v1/register/confirm` | – | `{username, password, code}` → 200: confirm a NickServ registration with the code the services emailed ([NickServ backend](docs/nickserv.md#sign-up)); `400 invalid_code`; `404` on the local backend |
| `POST /v1/email/verify` | – | `{token, return_to?}` → `{user, redirect_to?}`: where the verify page sends the user next (see below) |
| `POST /v1/email/resend` | optional | `{email, return_to?}` (or a bearer token) → 202, same response whether or not the account exists |
| `POST /v1/login` | – | `{login, password, cookie?}` (`login` = username or email) → `{token_type, access_token, expires_in, refresh_token, refresh_expires_in, session_id, user}` |
| `POST /v1/token/refresh` | – | `{refresh_token}` or the refresh cookie → same shape as login, with a **new** refresh token |
| `POST /v1/logout` | bearer, or `{refresh_token}`/cookie | revokes the session → 204 |
| `POST /v1/password/forgot` | – | `{email}` → 202, identical whether or not the account exists |
| `POST /v1/password/reset` | – | `{token, new_password}` → signs out every session |
| `POST /v1/password/change` | bearer | `{current, new}` → signs out every *other* session |
| `GET /v1/me` | bearer | `{user, session_id, roles: [{id, name, color, position}], permissions: [id], federation}` ([roles](docs/roles.md)); `federation` is `{identity, home_domain, issuer}` for a [federated account](docs/federation.md#federated-accounts), else `null` |
| `PATCH /v1/me` | bearer | `{display_name}` → `{user}` |
| `GET /v1/sessions` | bearer | `{sessions: [{id, auth_method, ip, user_agent, created_at, last_seen_at, expires_at, current}]}` |
| `DELETE /v1/sessions/{id}` | bearer | revoke one of your sessions → 204 (other users' ids are 404) |
| `GET /v1/me/identities` | bearer | `{identities: [{id, provider_id, provider_slug, provider_kind, provider_display_name, subject, email, created_at, last_login_at}], has_password}` |
| `GET /v1/me/channels` | bearer | `{channels: [{channel, private, autojoin, via: [role names]}]}`: the channels the caller's roles give ([role channels](docs/roles.md#public-api-1)) |
| `DELETE /v1/me/identities/{id}` | bearer | unlink → 204; `409 last_login_method` if it's the only way to sign in |
| `GET /v1/sso/{slug}/start` | – | `?return_to=&mode=&invite_code=&code_challenge=&code_challenge_method=S256` → 302 to the IdP ([SSO](#single-sign-on)) |
| `GET /v1/sso/{slug}/callback` | state cookie | OIDC redirect URI → 303 to `return_to` (cookies, `?code=` or `?error=`) |
| `POST /v1/sso/{slug}/saml/acs` | state cookie | SAML assertion consumer (HTTP-POST) → 303 as above |
| `GET /v1/sso/{slug}/saml/metadata` | – | SP metadata XML (`application/samlmetadata+xml`) |
| `POST /v1/sso/exchange` | – | `{code, code_verifier?, cookie?}` → same as `/v1/login`; `400 invalid_code` |
| `POST /v1/voice/token` | bearer | `{rooms?: [string]}` → `{token, expires_in, audience: "quicvoice"}`; private call rooms (`call:…`) are refused here (`400`), they come from the calls API |
| `POST /v1/voice/guest-token` | – | `{nick, guest_id, rooms?: [string]}` → `{token, expires_in, audience: "quicvoice"}`: a [guest voice token](#guest-voice-token-quicvoiced) for someone on IRC without an account, under their (unverified) IRC nick. `403 guest_voice_disabled` unless `guest_access` and `guest_voice` are both on; `400 invalid_request` (with `field`) for a nick that isn't a valid IRC nick (1–30 chars), a `guest_id` that isn't 16–64 of `[A-Za-z0-9_-]`, or bad rooms (as `/v1/voice/token`); `409 nick_registered` when the nick (RFC 1459 fold) is an account's username (disabled accounts included) or a reserved services name. 20 per client IP per minute (burst 20) |
| Friends, blocks, privacy, private calls | bearer | `GET /v1/friends`, `POST /v1/friends/requests`, `POST /v1/blocks`, `GET/PATCH /v1/me/privacy`, `GET /v1/users/{username}/relation`, `POST /v1/calls` (+ `/{id}/accept\|decline\|cancel\|end\|token`), `GET /v1/calls/missed`, `GET /v1/events` (long-poll event feed that rings open apps): see [docs/friends-calls.md](docs/friends-calls.md) |
| `GET /v1/roles` | – | `{roles: [{id, name, color, position, hoist, mentionable}]}`; `ETag`/`If-None-Match`, cacheable, rate-limited ([roles](docs/roles.md#public-api)) |
| `GET /v1/users/roles?username=a&username=b` | – | ≤ 100 names → `{users: {"a": ["rol_…"]}}` (visible roles only) |
| `GET /verify-email`, `GET /reset-password` | – | built-in pages for the email links (used when `APP_URL` = `PUBLIC_URL`) |

**After verifying.** A client may send `return_to` with `POST /v1/register`
or `/v1/email/resend`: where the user should land once the link is opened
(the web client's URL, or a `boson://…` link for the desktop app). It must
pass the same check as SSO's `return_to` (this site's web origins, i.e.
`APP_URL`, `PUBLIC_URL`, `CORS_ALLOWED_ORIGINS`, or an
`SSO_RETURN_TO_ALLOWED` pattern); otherwise it is silently dropped. An
allowed one rides in the link (`/verify-email?return_to=…#token=…`; email
templates need no change, it is part of `{{link}}`), and the page posts it
back with the token, where it is checked again. On success the response's
`redirect_to` is that `return_to`, else `WEB_CLIENT_URL`, else absent; the
built-in page shows a Continue button and goes there after 2.5 s, or, with no
target, offers an "Open the Boson app" (`boson://open`) button.

Admin: each endpoint needs a [permission](docs/roles.md#admin-endpoint--permission)
(any one of those listed), checked against the database on every request.
Actions on a user (disable, enable, session revoke, role changes) also need
the caller to outrank that user ([hierarchy](docs/roles.md#hierarchy)).

| Method & path | Permission | |
|---|---|---|
| `GET /v1/admin/users?q=&sort=&limit=&offset=` | `users.view` | search users (username/email substring) → `{users, total}`; each user has `roles: [{id, name, color, position}]` and the [sign-in / activity fields](#last-sign-in-and-last-active). `sort`: `created` (default, newest first) \| `last_active` \| `last_sign_in` (newest first, never-seen users last); anything else `400 invalid_request` |
| `POST /v1/admin/users` | `users.manage` | `{username, email?, role?, password? \| send_invite_email?}` → 201 `{user, invite_email_sent}`. `role`: `user` (default) \| `admin` \| `owner` (gives the Admin/Owner role; needs `roles.manage` and the hierarchy, so only Owners create Admins). The email is marked verified. `send_invite_email` (needs `email`; not with `password`) mails a "choose your password" link valid `ACCOUNT_SETUP_TTL`; with neither the account has no password. `409 username_taken\|email_taken`, `400 invalid_username\|weak_password\|invalid_request`, `403 role_hierarchy` |
| `GET /v1/admin/users/{id}` | `users.view` | `{user` (with the [sign-in / activity fields](#last-sign-in-and-last-active))`, identities: [{id, provider_id, provider_slug, provider_kind, provider_display_name, subject, email, created_at, last_login_at}], has_password, roles: [{id, name, color, position}], permissions: [id]}` |
| `POST /v1/admin/users/{id}/password-reset` | `users.manage` | email the user a reset link (same link and page as forgot-password; earlier links stop working) → 202. `400 no_email`, `409 account_disabled`, `404` |
| `POST /v1/admin/users/{id}/verification` | `users.manage` | resend the verification email → 202. `409 already_verified`, `400 no_email`, `409 account_disabled`, `404` |
| `PATCH /v1/admin/users/{id}` | `roles.manage` | 1.x `{role: "user"\|"admin"\|"owner"}`, mapped onto roles ([details](docs/roles.md#migrating-from-1x)) |
| `PUT /v1/admin/users/{id}/roles` | `roles.manage` | `{role_ids: [id]}` replaces the user's roles → `{roles: [{id, name, color, position}]}` |
| `POST /v1/admin/users/{id}/disable` | `users.moderate` \| `users.manage` | disable and revoke every session |
| `POST /v1/admin/users/{id}/enable` | `users.moderate` \| `users.manage` | re-enable |
| `GET /v1/admin/users/{id}/sessions` | `users.view` | active sessions |
| `DELETE /v1/admin/sessions/{id}` | `users.moderate` \| `users.manage` | revoke any session |
| `GET /v1/admin/invites`, `POST /v1/admin/invites` `{max_uses, ttl, note}`, `DELETE /v1/admin/invites/{id}` | `invites.manage` | invite codes (the code is only in the create response) |
| `GET /v1/admin/audit?event=&actor=&target=&user_id=&since=&until=&cursor=&limit=` | `audit.view` | audit log, newest first → `{entries, next_cursor}` ([below](#audit-log-api)) |
| `GET /v1/admin/sso/providers`, `POST` (create), `GET/PATCH/DELETE /v1/admin/sso/providers/{id}`, `POST /v1/admin/sso/providers/{id}/test` | `sso.manage` | SSO providers, see [docs/sso.md](docs/sso.md#admin-api); `client_secret` is write-only (`has_client_secret`) |
| `GET /v1/admin/settings` | `admin.panel` \| `settings.manage` | network settings → `{registration, require_email_verification, channel_creation, voice_channel_creation, channel_auto_register, channel_expiry_days, guest_access, guest_voice, updated_at, updated_by, source}`; `source` is `file` (stack config file) or `db` |
| `PATCH /v1/admin/settings` | `settings.manage` | same fields, any subset → the updated object; `400 invalid_request` on unknown values, wrong JSON types or `channel_expiry_days` outside 0–3650; `409 managed_by_config_file` while the [stack config file](#stack-config-file) is in use; audit event `settings_updated` with `meta.old` / `meta.new` (changed fields only) |
| `GET /v1/admin/permissions` | `admin.panel` | the permission catalog → `{permissions: [{id, group, label, description}]}` |
| `GET /v1/admin/roles`, `GET /v1/admin/roles/{id}` | `admin.panel` | `{roles: [role]}` most senior first (with `member_count`) / `{role}` |
| `POST /v1/admin/roles`, `PATCH /v1/admin/roles/{id}` | `roles.manage` | `{name, color?, position?, permissions?, irc?: {whois_line?, vhost?, oper?}, hoist?, mentionable?}` → 201 / 200 `{role}` |
| `DELETE /v1/admin/roles/{id}` | `roles.manage` | → 204; `409 builtin_role` |
| `POST /v1/admin/roles/reorder` | `roles.manage` | `{order: [id]}` (most senior first) → `{roles}` |
| `GET /v1/admin/roles/{id}/members?cursor=&limit=` | `admin.panel` | `{users: [{id, username, display_name, disabled, assigned_at, assigned_by}], next_cursor}` |
| `GET`, `PUT /v1/admin/roles/{id}/channels` | `admin.panel` \| `roles.manage` / `roles.manage` | a role's channels `{channels: [{channel, autojoin, private}]}` (`{id}` may be `everyone`) ([role channels](docs/roles.md#role-channels-channel-access-and-auto-join)) |
| `GET`, `PATCH /v1/admin/federation`, `/v1/admin/federation/users[/{id}]`, `POST`/`DELETE …/users/{id}/ban`, `POST /v1/admin/federation/domains/{domain}/revoke-sessions`, `GET …/bans` | `settings.manage` / `users.view` / `users.moderate` | federation settings (`auth.federation` in the stack config file, else PATCH), remote users, bans, ending a home domain's sessions: see [docs/federation.md](docs/federation.md#admin-api) |
| `GET`, `PUT /v1/admin/channel-access` | `admin.panel` \| `roles.manage` / `roles.manage` | private channels `{channels: [{channel, private, roles}]}`; PUT replaces the list ([role channels](docs/roles.md#role-channels-channel-access-and-auto-join)) |

### Internal listener (`INTERNAL_ADDR`, default `:8081`)

| Method & path | |
|---|---|
| `GET /healthz`, `GET /readyz`, `GET /version` | as above |
| `GET /metrics` | Prometheus exposition |
| `GET /internal/v1/settings` | header `X-Internal-Token`; the [network settings](#network-settings) object (same as `GET /v1/admin/settings`). For Ergo and quicvoiced. |
| `GET /internal/config/status` | no token; the [stack config file](#stack-config-file) status → `{path, loaded_at, file_mtime, ok, error?, error_line?, error_column?, restart_required: []}` plus `enabled` (false without `BOSON_CONFIG`) and `present`; `loaded_at` is null while the file has been invalid since start-up, `file_mtime` null while it is missing. For the admin panel. |
| `POST /internal/v1/verify-password` | header `X-Internal-Token: $INTERNAL_API_TOKEN`; `{username, password}` → `{ok, user_id?, username?, reason?, irc?: {oper_class, whois_line, vhost}, roles?, permissions?}` (`reason`: `invalid_credentials` \| `account_disabled` \| `email_not_verified`; `irc`/`roles`/`permissions` on success). For IRC SASL PLAIN. Disabled (503) when `INTERNAL_API_TOKEN` is empty. |
| `GET /internal/v1/calls/check?from=&to=` | header `X-Internal-Token`; user ids → `{result: ok \| friends_only \| calls_off \| you_blocked \| unavailable}`: may `from` ring `to` ([friends and calls](docs/friends-calls.md)) |
| `GET /internal/v1/roles` | every role with its Ergo oper class, WHOIS line, vhost template and capabilities → `{version, roles}`; `ETag` = version, `If-None-Match` → 304 ([Ergo integration](docs/roles.md#ergo-integration)) |
| `GET /internal/v1/users/{username}/irc` | `{user_id, username, disabled, irc: {oper_class, whois_line, vhost}, roles, permissions}` for logins without a password (OAUTHBEARER/SSO); 404 for unknown accounts |
| `GET /internal/v1/roles/{id}/members?cursor=&limit=` | the admin API's members list (`{users, next_cursor}`), for RoleServ |
| `GET /internal/v1/irc/grants` | `{version, users: [{username, oper_class, whois_line, vhost}]}`: every enabled account with an oper class or vhost; `ETag` = version, `If-None-Match` → 304 ([grants feed](docs/roles.md#get-internalv1ircgrants-live-changes)) |
| `GET /internal/v1/irc/channel-access` | `{version, autojoin, rejoin, channels: [{channel, private, everyone, accounts}], network: {founder, autojoin_guests, channels: [{channel, name, topic, autojoin}]}}` for RoleServ; `ETag`/`If-None-Match` ([role channels](docs/roles.md#internal-api-roleserv)) |
| `GET /internal/v1/irc/autojoin?account=`, `POST /internal/v1/irc/autojoin` `{account, channels}` | one account's auto-join channels `{account, enabled, rejoin, channels, pending, network, network_pending}` / record what RoleServ joined (`rejoin: once`, and network channels) |
| `GET /internal/v1/irc/accounts/removed?since=&limit=` | `{accounts: [{username, reason: "deleted"\|"disabled", at}], next}`: deleted and disabled accounts in commit order after the cursor `since`, for IRC to drop; `limit` 1–1000 (500) ([removed-accounts feed](docs/roles.md#get-internalv1ircaccountsremoved-deleted-and-disabled-accounts)) |
| `POST /internal/email/preview` | bearer with `settings.manage`; `{template, subject?, body?, email?: {sender_name?, accent?, footer?, logo?}, layout_html?, html?}` → `{subject, html, text, from, warnings}`, live preview with unsaved settings and unsaved compiled MJML (`layout_html` with `{{content}}`, `html` with `{{link}}`, ≤ 512 KB each; field-tagged 400s) ([emails](docs/branding.md#admin-endpoints-internal-listener)) |
| `GET /internal/email/default-mjml?part=layout\|verification\|password_reset\|account_setup\|invite` | bearer with `settings.manage`; `{mjml}`: Boson's default MJML source (the layout, or a whole email built on it) for the admin panel's MJML editor ([custom MJML](docs/branding.md#custom-mjml-layout-and-whole-emails)) |
| `POST /internal/email/test` | bearer with `settings.manage`; `{template, to}` → `{status: "sent"\|"logged", to, subject}`; rate-limited, audited `email_test_sent` |
| `/internal/v1/acting/…` | the admin roles API on behalf of `X-Acting-Account`, authenticated by `X-Internal-Token: $INTERNAL_ACTING_TOKEN` (never `INTERNAL_API_TOKEN`); 404 when that is unset ([acting API](docs/roles.md#acting-api-roleserv)) |

The caller may forward the end user's address in `X-Forwarded-For` (Ergo's auth-script helper does). Because the caller is authenticated by `INTERNAL_API_TOKEN`, auth trusts that value: it is recorded in the audit log and used for an extra per-IP limit (`RATE_LIMIT_IP_*` ×2), so one IRC client can't spray many accounts. Without the header only the per-account limit applies, so the IRC server's own shared address is never limited.

### Network settings

Eight settings can be changed at runtime by admins (`PATCH /v1/admin/settings`)
and are stored in `network_settings`. Until an admin sets one, it follows its
env variable, so env values are the defaults:

| Field | Values | Env default | Enforced by |
|---|---|---|---|
| `registration` | `open` \| `invite` \| `closed` | `REGISTRATION` | auth (`/v1/register`, SSO sign-up) |
| `require_email_verification` | bool | `REQUIRE_EMAIL_VERIFICATION` | auth (password login and `/internal/v1/verify-password`) |
| `channel_creation` | `registered` \| `admins` | `CHANNEL_CREATION` (`registered`) | IRC (Ergo): who may create text channels: `registered` = holders of `channel.create` (Member has it), `admins` = holders of `admin.panel` |
| `voice_channel_creation` | `admins` \| `founders` \| `registered` | `VOICE_CHANNEL_CREATION` (`founders`) | quicvoiced: `admins` = holders of `voice.manage_any`; `founders` = the IRC channel's founder (with `voice.create`) or `voice.manage_any`; `registered` = holders of `voice.create` (Member has it) |
| `channel_auto_register` | bool | `CHANNEL_AUTO_REGISTER` (`true`) | IRC (Ergo): a logged-in user who creates a new channel by joining it gets it registered to their account |
| `channel_expiry_days` | integer 0–3650 | `CHANNEL_EXPIRY_DAYS` (`0`) | IRC (Ergo): registered channels with no joins or messages for this many days are unregistered; `0` = never expire |
| `guest_access` | bool | `GUEST_ACCESS` (`true`) | IRC (Ergo): `true` = people may connect without an account (guests can chat but can't register channels or use voice or roles); `false` = IRC requires SASL login. Clients read it from `GET /v1/config`; treat a missing field (older auth) as `true` |
| `guest_voice` | bool | `GUEST_VOICE` (`false`) | auth (`POST /v1/voice/guest-token`): guests may join voice (and so video) under their unverified IRC nick, with a guest badge; only effective with `guest_access`. `GET /v1/config` reports `guest_access && guest_voice`; treat a missing field (older auth) as `false` |

```json
{"registration":"open","require_email_verification":true,"channel_creation":"registered",
 "voice_channel_creation":"founders","channel_auto_register":true,"channel_expiry_days":0,
 "guest_access":true,"guest_voice":false,
 "updated_at":"2026-11-13T21:04:05.123456Z","updated_by":"usr_01J…"}
```

`updated_at` / `updated_by` are `null` until the first change. Each replica
caches the row for `SETTINGS_CACHE_TTL` (5 s); the replica that handled the
PATCH sees it at once. auth enforces the first two and `guest_voice`; the others
are published for the IRC and voice services (`GET /internal/v1/settings`,
cache them a few seconds too) and for clients (`GET /v1/config`).

With the [stack config file](#stack-config-file) the same eight settings come
from its `auth:` section instead (`source: "file"`, `updated_at` / `updated_by`
`null`), `network_settings` is ignored and `PATCH` answers `409`.

### Stack config file

`BOSON_CONFIG=/config/boson.yaml` points at the boson stack's shared,
non-secret config file. auth reads its `network:` and `auth:` sections and
`files.enabled` (other sections and keys are ignored) and, while the file exists, they are the source of
truth: **file > env > built-in default**. A key that is absent (or `null`)
falls back to the env value, so removing a key resets it. Without
`BOSON_CONFIG`, or while the file does not exist, auth behaves exactly as
without it (env + `network_settings`).

```yaml
version: 1
network:
  name: Boson                       # SITE_NAME: product name in emails
auth:
  registration: open                # open | invite | closed
  require_email_verification: true
  guest_access: true
  guest_voice: false                # guests may join voice (needs guest_access)
  channel_creation: registered      # registered | admins
  voice_channel_creation: founders  # admins | founders | registered
  channel_auto_register: true
  channel_expiry_days: 0            # 0..3650, 0 = never
  cors_allowed_origins: [https://app.example.com]   # CORS_ALLOWED_ORIGINS ([] = none)
  smtp: { host: smtp.example.com, port: 587, from: "Boson <hi@example.com>", tls: starttls }
  email:                            # branded emails ([details](docs/branding.md))
    sender_name: Example Chat
    accent: "#7c3aed"
    footer: Example Chat · example.com
    logo: true
    templates:
      verification: { subject: "Confirm your {{network}} account", body: "Hi {{username}},\n\n{{link}}" }
      invite: { mjml: emails/invite-7a8b.mjml, html: emails/invite-7a8b.html }   # whole-email override
    layout: { mjml: emails/layout-5e6f.mjml, html: emails/layout-5e6f.html }    # custom MJML layout, files in BOSON_EMAILS_DIR
  federation:                       # FEDERATION_* ([federated login](docs/federation.md#settings))
    mode: directory                 # off | allowlist | directory | open
    allow: [boson.chat]
    block: [spam.example]
    directory_url: https://directory.boson.chat
    remote_upload_quota: 1GB        # "" = the account quota
    remote_voice: true
branding:                           # GET /v1/branding ([details](docs/branding.md))
  theme: { base: dark, colors: { accent: "#7c3aed" } }
  images: { logo: logo-3f2a.svg }   # files in BOSON_BRANDING_DIR (config/branding)
files:                              # the files service's section; auth reads only:
  enabled: true                     # FILES_ENABLED: files_url in /v1/config, else null
roles:
  channels:                         # role channels ([details](docs/roles.md#role-channels-channel-access-and-auto-join))
    autojoin: false                 # ROLE_CHANNELS_AUTOJOIN: RoleServ auto-joins members
    rejoin: login                   # ROLE_CHANNELS_REJOIN: login | once
irc:                                # the boson-ergo helper's section; auth reads only:
  channels:                         # network channels ([details](docs/roles.md#network-channels)), ≤ 100
    - name: "#lobby"
      topic: Welcome to Boson       # optional, ≤ 300 characters
      autojoin: true                # default false: joined once on first login (and guests on connect)
    - name: "#opers"
      roles: [Admin, Owner]         # optional: only these roles may join (Member = any account; empty = everyone, guests too)
  channel_founder: thelion          # IRC_CHANNEL_FOUNDER; default: the earliest-assigned Owner
  autojoin_guests: true             # IRC_AUTOJOIN_GUESTS (true)
```

`SMTP_USER` / `SMTP_PASSWORD` stay in the env (`auth.smtp.user` / `password`
in the file are rejected). auth watches the file's directory (fsnotify, so an
atomic tmp-file + rename write is seen) and polls its mtime every
`BOSON_CONFIG_POLL` (10 s). Mount the **directory** (`./config:/config:ro`),
not the single file: a bind-mounted file keeps pointing at the old inode
after a rename. Every key applies live, without a restart, including
CORS origins (and the SSO `return_to` web origins derived from them) and the
SMTP mailer; `restart_required` is always empty. A reload that changes auth's
keys is audited as `config_reloaded` (`meta: {actor: "config file", changed:
[keys]}`; switching between file and database mode also sets `meta.mode`).

An invalid file (YAML error, unknown value, wrong type) is logged with its line
and column and reported by `GET /internal/config/status`; the last good config
stays in use. At start-up there is no last good config: auth then runs on
the env values and `network_settings` (as without the file), the status shows
the error with `loaded_at: null`, and the first valid version is applied live. Unknown keys in `network:` / `auth:` are logged and
ignored.

Moving an existing install to the file: `auth export-config` prints the
`network:` and `auth:` sections built from the env and `network_settings`;
merge them into `config/boson.yaml`.

### Last sign-in and last active

Admin user objects (list, detail, and the `user` returned by the other
`/v1/admin/users` endpoints) carry four extra fields, `null` until the user
first signs in. `/v1/me` doesn't show them.

| Field | Set when |
|---|---|
| `last_sign_in_at` | a session is created: password login, SSO cookie mode, SSO code exchange (`POST /v1/sso/exchange`) |
| `last_sign_in_method` | with it: the session's `auth_method` (`password` \| `oidc:<slug>` \| `saml:<slug>` \| `nickserv` \| `federation`) |
| `last_sign_in_ip` | with it: the client IP the session records (`""` when unknown) |
| `last_active_at` | a sign-in, and a token refresh (when the session's `last_seen_at` moves), written at most once per 5 minutes per user. Clients refresh about every `ACCESS_TOKEN_TTL`, so it is accurate to roughly that |

They live on the user, so they outlast sessions (which expire and are
deleted). Migration 10 backfilled them from the sessions and SSO identities
still in the database at the time. IRC SASL password checks
(`/internal/v1/verify-password`) don't create a session and don't count.

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

### Roles and permissions

Network roles (built-in Owner, Admin, Moderator, Member, plus custom ones)
carry permissions from a closed catalog (`admin.*`, network `channel.*` /
`voice.*`, and `irc.*` = Ergo oper capabilities), an Ergo oper class
(WHOIS line) and an optional vhost template that Ergo applies at login.
Positions form a Discord-style hierarchy with Owner on top. See
[docs/roles.md](docs/roles.md) for the model, the permission → endpoint
table, the API, token claims, the Ergo/quicvoiced contract and how 1.x
admins were migrated.

### Single sign-on

Admins add OIDC and SAML providers at runtime (`/v1/admin/sso/providers`);
enabled ones appear in `GET /v1/config` with their `start_url`. A login
starts at `GET /v1/sso/{slug}/start?return_to=…`:

- **Browser apps** on this site's origins (`APP_URL`, `PUBLIC_URL`,
  `CORS_ALLOWED_ORIGINS`) get the usual `boson_at`/`boson_rt` cookies and a
  303 back to `return_to`.
- **Desktop/native apps** use a loopback (`http://127.0.0.1:<port>/…`) or
  `boson://…` `return_to` (`SSO_RETURN_TO_ALLOWED`), get `?code=bsc_…` and
  exchange it once, within 60 s, at `POST /v1/sso/exchange {code, code_verifier}`
  for the normal login response. Send `code_challenge` (S256) at start.
- Failures come back as `?error=<code>&error_description=…` on `return_to`.

Accounts are matched by provider + subject; by email only for providers with
`trust_email` whose IdP asserts the email verified (and the existing
account's email is verified); new accounts only with `allow_signup` and when
the `registration` setting allows (invite codes pass through `start`).
[docs/sso.md](docs/sso.md) has the flow, linking rules, admin API shapes, and
setup notes for Google, GitHub (not OIDC; needs a broker), Authentik, Zitadel,
Keycloak, Okta and Entra ID.

### Errors and status codes

`400 invalid_request|invalid_username|weak_password|invalid_token|no_email`,
`400 invalid_return_to|invalid_code|invalid_state` (SSO),
`401 invalid_credentials|unauthenticated|invalid_refresh_token`,
`403 email_not_verified|account_disabled|forbidden|csrf|registration_closed|invite_required|invalid_password`,
`403 role_hierarchy|permission_not_held` (roles),
`409 username_taken|email_taken|already_verified|slug_taken|last_login_method|account_disabled` (the last for admin actions on a disabled account),
`409 role_name_taken|builtin_role|last_owner` (roles), `412 precondition_failed` (`If-Match` on a role edit),
`415 unsupported_media_type`, `429 rate_limited` (with `Retry-After`).
Federated login ([details](docs/federation.md#errors)): `403 federation_off|domain_not_trusted|domain_blocked|identity_banned|federated_account|remote_voice_disabled`,
`401 bad_assertion|replayed`, `502 discovery_failed`, `409 federated_account` (password reset of a federated account), `409 settings_managed` (federation PATCH in file mode).
NickServ backend ([details](docs/nickserv.md#sign-in)): `403 account_suspended|nickserv_refused|registration_unavailable`,
`409 password_managed_by_nickserv|account_name_conflict|account_name_unsupported|account_reregistered`,
`400 registration_rejected|invalid_code`, `429 account_locked` (with `Retry-After`), `503 accounts_unavailable`.

Error bodies are `{"error": code, "message": text, "code": code}` (`code`
repeats `error` for clients that read it from there).

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
| `role` | `user` \| `admin` (1.x: `admin` iff `perms` has `admin.panel`) |
| `roles` | assigned [role](docs/roles.md) names, most senior first, ≤ 20; omitted when none (Member is implicit) |
| `perms` | effective permission ids |
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
| `role` | `speaker`; `moderator` with `voice.manage_any` (Owner, Admin, Moderator by default; quicvoiced roles: listener < speaker < moderator < admin) |
| `roles` | as in the access token |
| `perms` | the network permissions only: `channel.create`, `voice.create`, `voice.manage_any`, `voice.bypass_locks` |
| `rooms` | from the request body; **omitted** when empty (= any room) |
| `sid`, `iat`, `nbf`, `jti` | as above |
| `exp` | `iat` + `VOICE_TOKEN_TTL` (5 min) |

### Guest voice token (quicvoiced)

From `POST /v1/voice/guest-token`; same header, key, audience and lifetime
as the voice token:

| Claim | Value |
|---|---|
| `iss`, `aud`, `iat`, `nbf`, `exp`, `jti` | as the voice token |
| `sub` | `"guest:" + guest_id` (never a user id) |
| `name` | the IRC nick: **unverified**, only checked not to belong to an account |
| `guest` | `true` |
| `role` | `speaker` |
| `roles`, `perms` | `[]`: always present and empty (no create / manage / bypass) |
| `rooms` | from the request body; omitted when empty |

There is no `sid`. quicvoiced must treat it as a guest (no account, no
standing lookup) and reject a `guest: true` token whose `sub` doesn't start
with `guest:`.

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
| `BOSON_CONFIG` | – | path of the [stack config file](#stack-config-file); its values win over the env variables marked *file* below |
| `BOSON_CONFIG_POLL` | `10s` | mtime poll interval for the config file (besides fsnotify) |
| `BOSON_BRANDING_DIR` | `branding` next to `BOSON_CONFIG` | directory of the images named in `branding.images` ([branding](docs/branding.md)) |
| `BOSON_EMAILS_DIR` | `emails` next to `BOSON_CONFIG` | directory of the MJML / HTML files named in `auth.email.layout` and `auth.email.templates.<name>` ([custom MJML](docs/branding.md#custom-mjml-layout-and-whole-emails)) |
| `SITE_NAME` | `boson` | product name in emails (*file*: `network.name`) |
| `FILES_PUBLIC_URL` | – | the network's files (uploads) service, e.g. `https://files.example.com`; `GET /v1/config` `files_url` while uploads are on |
| `ROLE_CHANNELS_AUTOJOIN` | `false` | RoleServ auto-joins members to their roles' channels (*file*: `roles.channels.autojoin`) |
| `ROLE_CHANNELS_REJOIN` | `login` | `login` \| `once` (*file*: `roles.channels.rejoin`) |
| `IRC_CHANNEL_FOUNDER` | – | account that founds the network channels; empty = the enabled account that has held Owner longest (*file*: `irc.channel_founder`) |
| `IRC_AUTOJOIN_GUESTS` | `true` | RoleServ joins guests to the auto-join network channels on connect (*file*: `irc.autojoin_guests`) |
| `FILES_ENABLED` | `false` | uploads are on: `files_url` is published (*file*: `files.enabled`) |
| `HTTP_ADDR` | `:8080` | public listener |
| `INTERNAL_ADDR` | `:8081` | internal listener (`/metrics`, `/internal/v1`) |
| `PUBLIC_URL` | `http://localhost:8080` | external URL of this service; `jwks_uri` is built from it |
| `APP_URL` | `PUBLIC_URL` | base of email links: `$APP_URL/verify-email#token=…`, `$APP_URL/reset-password#token=…` |
| `WEB_CLIENT_URL` | – | where `/verify-email` sends the user after verifying when the request had no (allowed) `return_to`, e.g. `https://chat.example.com/`. Unset: the page offers an "Open the Boson app" (`boson://open`) button |
| `TRUSTED_PROXIES` | – | comma-separated CIDRs/IPs whose `X-Forwarded-For` is honoured (e.g. the Caddy container network) |
| `CORS_ALLOWED_ORIGINS` | origin of `APP_URL` | comma-separated origins allowed to make credentialed requests (*file*: `auth.cors_allowed_origins`) |
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
| `REGISTRATION` | `open` | default for the `registration` network setting: `open` \| `invite` \| `closed` (*file*: `auth.registration`) |
| `REQUIRE_EMAIL_VERIFICATION` | `true` | default for `require_email_verification`: block password login (and SASL) until the email is verified (*file*: `auth.require_email_verification`) |
| `CHANNEL_CREATION` | `registered` | default for `channel_creation`: `registered` \| `admins` (*file*: `auth.channel_creation`) |
| `VOICE_CHANNEL_CREATION` | `founders` | default for `voice_channel_creation`: `admins` \| `founders` \| `registered` (*file*: `auth.voice_channel_creation`) |
| `CHANNEL_AUTO_REGISTER` | `true` | default for `channel_auto_register`: IRC registers new channels to their creator (*file*: `auth.channel_auto_register`) |
| `CHANNEL_EXPIRY_DAYS` | `0` | default for `channel_expiry_days`: 0–3650, days of inactivity before IRC unregisters a channel (`0` = never) (*file*: `auth.channel_expiry_days`) |
| `GUEST_ACCESS` | `true` | default for `guest_access`: IRC lets people connect without an account; `false` = SASL login required (*file*: `auth.guest_access`) |
| `GUEST_VOICE` | `false` | default for `guest_voice`: guests may get voice tokens (`POST /v1/voice/guest-token`); needs `guest_access` (*file*: `auth.guest_voice`) |
| `SETTINGS_CACHE_TTL` | `5s` | how long a replica caches the network settings |
| `ACCOUNT_SETUP_TTL` | `72h` | lifetime of the "choose your password" link for admin-created accounts |
| `EMAIL_VERIFY_TTL` | `24h` | |
| `PASSWORD_RESET_TTL` | `30m` | |
| `ARGON2_MEMORY_KIB` / `ARGON2_ITERATIONS` / `ARGON2_PARALLELISM` | `65536` / `3` / `2` | argon2id cost for new hashes; old hashes upgrade on next login |
| `SMTP_HOST` | – | empty = log links instead of sending (dev only) (*file*: `auth.smtp.host`; likewise `SMTP_PORT`, `SMTP_FROM`, `SMTP_TLS` → `auth.smtp.port` / `from` / `tls`) |
| `SMTP_PORT` | `587` | |
| `SMTP_USER` / `SMTP_PASSWORD` | – | auth is used when `SMTP_USER` is set; env only, never in the config file |
| `SMTP_FROM` | `boson <no-reply@localhost>` | |
| `SMTP_TLS` | `starttls` | `starttls` (required) \| `tls` (implicit, 465) \| `none` (dev, e.g. Mailpit) |
| `INTERNAL_API_TOKEN` | – | shared secret for `/internal/v1/*`; empty disables it |
| `INTERNAL_ACTING_TOKEN` | – | separate secret for `/internal/v1/acting/*` (RoleServ acting as an account); must differ from `INTERNAL_API_TOKEN`; empty = the acting API doesn't exist (404) |
| `SSO_RETURN_TO_ALLOWED` | `http://127.0.0.1:*,http://[::1]:*,boson://` | extra SSO `return_to` targets (code mode), besides this site's web origins. Patterns `scheme://host[:port\|:*][/path-prefix]`; `boson://` = any URL of that scheme |
| `SSO_STATE_TTL` | `10m` | lifetime of the encrypted SSO state cookie (time allowed at the IdP) |
| `SSO_CODE_TTL` | `1m` | lifetime of one-time codes for native clients |
| `SSO_HTTP_TIMEOUT` | `10s` | timeout for calls to IdPs |
| `SSO_ALLOW_HTTP` | `false` | accept `http://` issuers / metadata URLs on non-loopback hosts (dev only) |
| `RATE_LIMIT_ENABLED` | `true` | |
| `RATE_LIMIT_IP_BURST` / `RATE_LIMIT_IP_PER_MINUTE` | `20` / `10` | per client IP, per endpoint group |
| `RATE_LIMIT_ACCOUNT_BURST` / `RATE_LIMIT_ACCOUNT_PER_MINUTE` | `5` / `2` | per username/email, per endpoint group (internal API: double) |
| `RATE_LIMIT_PUBLIC_BURST` / `RATE_LIMIT_PUBLIC_PER_MINUTE` | `60` / `120` | per client IP for the public role lookups (`GET /v1/roles`, `GET /v1/users/roles`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | – | enable OTLP push in addition to Prometheus |
| `OTEL_EXPORTER_OTLP_PROTOCOL` / `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` | `http/protobuf` | or `grpc` |
| `OTEL_METRICS_EXPORTER` | – | `none` disables OTLP push |
| `ACCOUNT_BACKEND` | `local` | `local` (auth's own accounts) \| `nickserv` (the IRC network's NickServ accounts; `NICKSERV_*` settings in [docs/nickserv.md](docs/nickserv.md#configuration)) |
| `FEDERATION_MODE` | `directory` | federated login: `off` \| `allowlist` \| `directory` \| `open`; `FEDERATION_ALLOW`, `FEDERATION_BLOCK`, `FEDERATION_DIRECTORY_URL`, `FEDERATION_DOMAIN`, `FEDERATION_REMOTE_ROLE`, `FEDERATION_REMOTE_UPLOAD_QUOTA`, `FEDERATION_REMOTE_MAX_FILE`, `FEDERATION_REMOTE_VOICE`, `FILES_INTERNAL_URL` / `FILES_INTERNAL_TOKEN` and the rest in [docs/federation.md](docs/federation.md#configuration) |
| `TEST_DATABASE_URL` | – | tests only: enables the integration suite |
| `TEST_NICKSERV` | – | tests only: `1` runs `test/nickserv` against the real services from `make test-nickserv-up` |
| `TEST_DEX_ISSUER` | – | tests only: run the OIDC flow against a real Dex (`make test-dex-up`) |

Rate-limited endpoint groups: login (and password change), register,
forgot, reset, verify/resend, internal verify-password, SSO browser
endpoints (start/callback/ACS, per IP), SSO code exchange (per IP), public
role lookups (per IP), federated login (per IP), federation assertions (per
user, `FEDERATION_ASSERT_*`).

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
auth user create --username U [--email E] [--role user|admin|owner] [--password-stdin | --no-password]
auth user list [query] | set-role <user> <user|admin|owner> | disable <user> | enable <user> | revoke-sessions <user>
auth user set-roles <user> [role name or id ...]   replace a user's roles (none = Member only)
auth role list
auth keys list | rotate [--now] | gen-kek
auth invite create [--uses N] [--ttl 168h] [--note ..] | list | revoke <id>
auth export-config                           print network:/auth: YAML for config/boson.yaml from env + database
```

In the container: `docker compose exec auth ./auth user create --username admin --role owner`.
The CLI acts as the system: it bypasses the role hierarchy but never removes the last Owner.

## Metrics

On the internal listener's `/metrics` (and OTLP if configured), plus Go runtime metrics:

| Metric | Labels |
|---|---|
| `auth_login_attempts_total` | `method` (`password`, `nickserv`, `internal`, `oidc`, `saml`, `federation`), `outcome` (`success`, `invalid_credentials`, `disabled`, `unverified`, `rejected`) |
| `auth_registrations_total` | `outcome` (`success`, `rejected`, `error`) |
| `auth_token_refreshes_total` | `outcome` (`success`, `invalid`, `expired`, `reuse`, `disabled`, `error`) |
| `auth_token_refresh_reuse_total` | – |
| `auth_emails_sent_total` | `purpose` (`verify_email`, `reset_password`), `outcome` |
| `auth_rate_limit_hits_total` | `bucket` |
| `auth_password_resets_total` | `outcome` |
| `auth_nickserv_checks_total` | `strategy`, `outcome` (`success`, `invalid_credentials`, `suspended`, `refused`, `unavailable`, `locked`, `rate_limited`, `rejected`) ([NickServ backend](docs/nickserv.md#security)) |
| `auth_voice_guest_tokens_total` | `outcome` (`success`, `rejected` (disabled), `invalid`, `taken` (registered / reserved nick), `error`) |

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
  target user in `target_user_id`), settings changes (old and new values),
  role changes (`role_created|role_updated|role_deleted`, old/new), role
  assignments (`user_roles_changed`, old/new role ids) and test emails
  (`email_test_sent`, template and recipient).
- **Branding** is public by design. Images are only the files the config
  names, read through `os.Root` and served from memory with their sniffed
  type and `nosniff`; SVGs get a CSP that disables scripts. Email templates
  are plain text: everything is escaped, only http(s) URLs become links.
- **Roles** are checked against the database on every admin request, never
  taken from the token. The hierarchy stops anyone acting on roles or users
  at or above their own rank or granting permissions they lack; Owners bypass
  it, and the last Owner can't be removed (role writes are serialised by a
  row lock).
- **Network settings** are only writable with `settings.manage`, validated against fixed
  value sets, and audit-logged. A stale replica serves the old value for at
  most `SETTINGS_CACHE_TTL`.
- **SSO state** lives in an AES-256-GCM-sealed cookie (key derived from
  `AUTH_KEY_ENCRYPTION_KEY` with HKDF), bound to the browser, single use and
  short-lived; `state` is compared in constant time. OIDC uses PKCE (S256)
  and a nonce; SAML responses must be signed, answer our request id, and
  match our ACS, audience and time window; IdP-initiated SAML is refused.
- **Provider secrets** (OIDC client secrets, SAML SP private keys) are
  encrypted at rest like signing keys and never returned by the API.
- **No tokens in URLs:** native clients get a 60-second single-use code
  (stored hashed, optionally PKCE-bound) and exchange it over POST.
  `return_to` must be one of our origins or match `SSO_RETURN_TO_ALLOWED`;
  userinfo, protocol-relative and opaque URLs are refused.
- **Account linking by email** needs `trust_email` on the provider, a
  verified email from the IdP *and* a verified email on the existing account,
  so an unverified pre-registration can't capture a later SSO user.
  Transient SAML NameIDs are refused (they'd mint a new account per login).
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
internal/services/idp/*      SSO provider kinds (oidc, saml) and registry
internal/services/sso        SSO flow, linking, code exchange, provider admin
internal/services/roles      roles, permissions, hierarchy, IRC oper class / vhost
internal/services/ircaccounts removed-accounts feed for IRC (deleted / disabled)
internal/services/stackconfig applies the stack config file live (BOSON_CONFIG)
internal/services/nickserv   NickServ password checks: Anope/Atheme RPC, SASL, IDENTIFY; TLS pins; lockouts
internal/services/nsaccount  NickServ account backend: sign-in, linking, sign-up (ACCOUNT_BACKEND=nickserv)
internal/services/federation federated login: assertions, discovery/JWKS/directory, trust policy, remote users
internal/services/branding   GET /v1/branding: theme + images from the config file
internal/services/email      built-in and branded emails, preview / test
internal/theme               boson-theme/1 rules (shared with directory and client)
internal/configfile          config file parsing (line/column errors) + watcher
internal/perm                the permission catalog
internal/{nick,password,keycrypt,ratelimit,opaque,ids,mailer,...}
metrics/                     OpenTelemetry instruments + Prometheus exporter
test/integration/            HTTP flows against real Postgres
test/nickserv/               real Anope 2.1 + InspIRCd 4, Atheme 7.2 + ngircd 27 (compose) for the NickServ strategies
docs/sso.md                  SSO flow, linking rules, admin API, IdP setup
docs/roles.md                roles, permissions, hierarchy, Ergo/quicvoiced contract
docs/branding.md             network theme, branding images, email templates
docs/nickserv.md             NickServ account backend: strategies, config keys, security
docs/federation.md           federated login: flow, trust policy, admin API, stack contract
```

## Roadmap

- **Done:** phase 2 (OIDC) and phase 3 (SAML), see [docs/sso.md](docs/sso.md);
  network roles and permissions, see [docs/roles.md](docs/roles.md).
- **Next for SSO:** linking an extra provider from account settings; SAML single logout.
- **Phase 4, IRC SASL:** Anope/UnrealIRCd bridge calling `/internal/v1/verify-password`.

See [docs/sso.md](docs/sso.md).

## License

Copyright (C) 2026 bludot / the boson authors

Licensed under the [GNU Affero General Public License v3.0](LICENSE) only (`AGPL-3.0-only`).

In plain English: if you run a modified version of this software as a network service, you must offer its source code to the people who use that service.
