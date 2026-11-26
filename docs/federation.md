# Federated login (Boson federation v1)

A user with an account on their **home** Boson server (`alice@boson.chat`)
can use any other Boson server (the **remote**, `chat.example.org`) without
signing up there. No password or chat data crosses servers: the home signs
a short-lived **assertion**, the remote checks it and signs the user in to
a local **federated account**. From then on the remote's own tokens work for
everything (IRC, voice, video, uploads) under the remote's rules.

auth is both sides: every install issues assertions for its users (home)
and, unless `FEDERATION_MODE=off`, accepts them (remote). It works with the
default local account backend; with `ACCOUNT_BACKEND=nickserv` federated
accounts are local records too (see [NickServ](#nickserv-backend)).

- [Flow](#flow) · [Discovery (boson.json)](#discovery-bosonjson) · [Home: assertions](#home-post-v1federationassertions)
- [Remote: login](#remote-post-v1federationlogin) · [Trust policy](#trust-policy) · [Federated accounts](#federated-accounts)
- [Admin API](#admin-api) · [Domain blocks](#domain-blocks) · [Configuration](#configuration) · [IRC, voice, files](#irc-voice-and-files)
- [What the stack needs](#what-the-stack-needs) · [Errors](#errors)

## Flow

```
app ──(home access token)──▶ home  POST /v1/federation/assertions {audience: <remote issuer>}
app ◀── {assertion, expires_in: 300}
app ──▶ remote POST /v1/federation/login {assertion}
          remote → https://<boson_domain>/.well-known/boson.json   (federation.issuer == iss)
          remote → <jwks_uri>                                       (signature)
          remote → directory (directory mode)                       (verified listing)
app ◀── the normal login response + {federated: true, identity: "alice@boson.chat", handle: "alice"}
```

The app keeps the returned session as its account on that server, marked
federated with `identity`, and refreshes it with `POST /v1/token/refresh`
like any other session. When it expires, it asks the home for a new
assertion.

## Discovery (boson.json)

Every install serves `https://<domain>/.well-known/boson.json` (the stack's
`wellknown` service). Its `federation` section is what auth serves at:

`GET /.well-known/boson-federation.json` (public, CORS `*`, `Cache-Control: public, max-age=60`)

```json
{
  "version": 1,
  "issuer": "https://auth.boson.chat",
  "jwks_uri": "https://auth.boson.chat/.well-known/jwks.json",
  "assertion_endpoint": "https://auth.boson.chat/v1/federation/assertions",
  "login_endpoint": "https://auth.boson.chat/v1/federation/login",
  "accepts": "directory"
}
```

`issuer` is `ISSUER` (the `iss` of every token auth signs); the URLs are
built from `PUBLIC_URL`. `accepts` is the live `mode` setting (`off`,
`allowlist`, `directory`, `open`), so it changes when an admin changes it.
With `accepts: "off"` the server neither issues nor accepts assertions, and
remotes refuse assertions from a home that says `off`.

`boson_domain` in assertions is `FEDERATION_DOMAIN` (default: the issuer's
host without a leading `auth.`, so `https://auth.boson.chat` → `boson.chat`).
It must be the domain whose boson.json carries this section.

## Home: `POST /v1/federation/assertions`

Bearer (the user's normal access token), body `{"audience": "<remote issuer URL>"}`
→ `200 {"assertion": "<JWT>", "expires_in": 300}`, `Cache-Control: no-store`.

The JWT is signed with the usual signing keys (EdDSA, `kid` in
`/.well-known/jwks.json`), header `typ: "boson-fed+jwt"`:

| claim | value |
|---|---|
| `iss` | this issuer |
| `sub` | the user id (`usr_…`, stable) |
| `aud` | `audience`, exactly as requested |
| `iat`, `exp` | `exp - iat` = 300 s |
| `jti` | random, single use |
| `boson_domain` | `FEDERATION_DOMAIN` |
| `preferred_username` | the username |
| `name` | the display name (username when empty) |
| `email_verified` | bool; the email itself is never sent |

`picture` is optional in the spec; auth has no avatars yet, so it is never
set. Refused: `403 federation_off` (mode `off`), `401 unauthenticated` (no
or bad token; disabled accounts can't authenticate), `403 federated_account`
(a federated account can only federate from its own home),
`400 invalid_request` (`field: audience`: not an https URL, or this server),
`429 rate_limited` (per user, `FEDERATION_ASSERT_BURST` / `_PER_MINUTE`).
Guests have no access token, so they can't ask. Each assertion is logged
with its audience and audited as `federation_assertion_issued`
(`meta.audience`).

The assertion can't be used as a token anywhere else: its `typ` and `aud`
differ from access and voice tokens, which every verifier checks.

## Remote: `POST /v1/federation/login`

Public (CORS `*`), body `{"assertion": "<JWT>", "cookie"?: bool}`, rate-limited
per client IP (`RATE_LIMIT_IP_*`). `cookie: true` sets the session cookies
instead of returning tokens (same-origin web apps only; needs
`X-Requested-With`).

The remote:

1. Reads `iss` and `boson_domain` without trusting them. `typ` must be
   `boson-fed+jwt`, `boson_domain` a DNS name, `iss` an https URL other than
   its own issuer. Blocked domains and (allowlist mode) unlisted ones are
   refused here, before any network request.
2. Fetches `https://<boson_domain>/.well-known/boson.json` (cached 15 min,
   failures 1 min) and requires `federation.version == 1`,
   `federation.issuer == iss`, https `jwks_uri`, and `accepts != "off"`.
3. Fetches `jwks_uri` (cached 1 h; an unknown `kid` refetches it, at most
   every 10 s; if the home is unreachable the cached keys keep working),
   then verifies the EdDSA signature, `aud` == its own issuer, `exp`
   and `iat` (60 s skew, `iat` required, `exp - iat` ≤ 5 min), `sub`, `jti`
   and `preferred_username`, and that `jti` hasn't been seen (the replay
   cache is the `federation_replay` table, shared by replicas, kept until
   `exp`).
4. Applies the [trust policy](#trust-policy) and refuses banned identities.
5. Finds or creates the [federated account](#federated-accounts) and
   refreshes its profile.
6. Signs it in (session `auth_method: "federation"`) and answers like
   `POST /v1/login`:

```json
{"token_type": "Bearer", "access_token": "…", "expires_in": 900, "refresh_token": "…",
 "refresh_expires_in": 2592000, "session_id": "ses_…",
 "user": {"id": "usr_…", "username": "alice", "email": null, "email_verified": false,
          "display_name": "Alice", "role": "user", "created_at": "…"},
 "federated": true, "identity": "alice@boson.chat", "handle": "alice"}
```

Outgoing requests (discovery, JWKS, directory) have a timeout
(`FEDERATION_HTTP_TIMEOUT`), follow at most 3 redirects and never to plain
http, and refuse to connect to loopback, private, link-local and CGNAT
addresses, so a hostile boson.json can't point auth at internal services
(`FEDERATION_ALLOW_HTTP=true` lifts both for development).

`GET /v1/me` has `"federation": {"identity", "home_domain", "issuer"}` for a
federated account and `null` for a local one.

## Trust policy

`mode` (env `FEDERATION_MODE`, default `directory`):

| mode | a home domain is accepted when |
|---|---|
| `off` | never (and this server issues no assertions) |
| `allowlist` | it matches `allow` (`FEDERATION_ALLOW`) |
| `directory` | it has a **verified** listing in the directory (`directory_url`, `FEDERATION_DIRECTORY_URL`, default `https://directory.boson.chat`) |
| `open` | it has valid discovery |

In every mode domains matching `block` (`FEDERATION_BLOCK`, see [domain blocks](#domain-blocks)) and banned
identities are refused. List entries are domains (`boson.chat`, matching
only that domain) or `*.example.org` (example.org and every subdomain);
they are lower-cased and de-duplicated.

**Directory check.** auth calls the directory's public lookup,
`GET {directory_url}/v1/networks/lookup?hostname=<h>`, which only shows
verified listings to anonymous callers (404 otherwise), and requires
`network.status == "verified"` and `network.hostname == h`. Listings are by
IRC hostname, so `h` is tried as `boson_domain` and then as the home's
boson.json `irc.host` when that is `boson_domain` or one of its subdomains
(`irc.boson.chat`); another domain's IRC host never counts. Answers are
cached 15 min (not listed / errors: 2 min). When the directory is down a
listing already seen as verified stays trusted; otherwise the sign-in fails
with `502 discovery_failed` ("couldn't check the directory").

## Federated accounts

A `federated_accounts` row keyed by `(issuer, subject)` links to an ordinary
`users` row, so roles, profiles, friends, sessions and admin tools work as
usual.

- **Identity** `preferred_username@boson_domain` (`alice@boson.chat`), shown to
  people; `name` is the display name and is refreshed (with `picture` and
  `email_verified`) at every sign-in.
- **Handle** = the local username = the IRC account name and nick. The first
  free of: `preferred_username` (made a valid IRC nick the way SSO does:
  `9lives.cat` → `u9lives_cat`); that plus `-` and the home domain's label
  (letters and digits, at most 16: `alice-bosonchat`); that with a number
  (`alice-bosonchat2` … `20`); then a random 5-digit suffix. Always 1–30
  characters and never a services name. It doesn't change later (the user
  can change their IRC nick).
- **Role**: new accounts get `FEDERATION_REMOTE_ROLE` (default `Remote`;
  created with no permissions at position 1 when no role of that name
  exists; empty = none). They also hold Member, like everyone. Admins grant
  more as usual; renaming the role means setting the env to the new name.
- **No password, no email.** Password sign-in (`/v1/login`, IRC SASL
  PLAIN) always fails for them (`invalid_credentials`, audited
  `login_failed` reason `federated_account`); password reset doesn't apply
  (`POST /v1/admin/users/{id}/password-reset` → `409 federated_account`).
- Disabling one (`/v1/admin/users/{id}/disable`) stops its sign-ins
  (`403 account_disabled`).

## Identity lookup

Other users' home domains aren't on the IRC wire (account-tag and WHOIS
carry only the local handle), so apps ask auth. Public, no auth, CORS `*`,
rate-limited per client IP (`RATE_LIMIT_PUBLIC_*`):

- `GET /v1/users/{handle}/identity` → `{"handle": "alice-bosonchat", "federated": true, "identity": "alice@boson.chat", "home_domain": "boson.chat"}`
  (`Cache-Control: public, max-age=60`)
- `POST /v1/users/identities` `{"handles": ["alice-bosonchat", "carol"]}` (at most 200)
  → `{"identities": {"alice-bosonchat": {…}, "carol": {"handle": "carol", "federated": false, "identity": null, "home_domain": null}}}`;
  keys are the handles as sent (duplicates once); more than 200 → `400 invalid_request`.

Handles match case-insensitively (RFC 1459 fold); `handle` echoes the
request. Only these four fields are exposed (no ids, emails or times), and
local accounts and unknown handles give the same `federated: false`
answer, so the lookup doesn't reveal whether a handle exists.

## Admin API

All under the public listener with a bearer token; permissions are checked
against the database on every request. The admin panel's Federation page
(boson-chat/admin) uses exactly these.

| Method & path | Permission | |
|---|---|---|
| `GET /v1/admin/federation` | `admin.panel` \| `settings.manage` | [Settings](#settings) |
| `PATCH /v1/admin/federation` | `settings.manage` | any subset of `mode`, `allow`, `block`, `directory_url`, `remote_upload_quota`, `remote_voice` → Settings; `null` resets a field to its env value; `409 settings_managed` while the stack config file is in use; `400 invalid_request` with `field` for bad values or read-only / unknown fields; audit `federation_settings_updated` (`meta.old` / `meta.new`, changed fields only) |
| `GET /v1/admin/federation/users?q=&domain=&cursor=&limit=` | `users.view` \| `settings.manage` | remote users, most recently seen first → `{users: [RemoteUser], next_cursor: string\|null, total}`; `q` matches handle, home username, home domain or display name (substring, case-insensitive); `domain` an exact home domain; `limit` 1–200 (50); `cursor` is the previous page's `next_cursor` (opaque) |
| `GET /v1/admin/federation/users/{id}` | `users.view` \| `settings.manage` | RemoteUser; `404` for a local user |
| `POST /v1/admin/federation/users/{id}/ban` | `users.moderate` \| `users.manage` | `{reason?}` (≤ 500 chars) → RemoteUser: bans the identity (iss, sub); it can't sign in again, its sessions end, and its local account is disabled so IRC drops it (removed-accounts feed); audit `federation_identity_banned` (`meta: identity, reason, sessions_revoked`) |
| `DELETE /v1/admin/federation/users/{id}/ban` | `users.moderate` \| `users.manage` | → RemoteUser: lifts the ban and re-enables the account if the ban disabled it; audit `federation_identity_unbanned` |
| `POST /v1/admin/federation/domains/{domain}/revoke-sessions` | `settings.manage` \| `users.moderate` \| `users.manage` | → `{domain, revoked}`: ends every session of the remote users from that home domain (`*.domain`: and its subdomains) and drops them from IRC (removed-accounts feed, `cause: sessions_revoked`, until they sign in again); audit `federation_domain_sessions_revoked` (`meta: domain, revoked`). Blocking a domain is putting it in `block` (PATCH or the config file), which does all of this by itself ([domain blocks](#domain-blocks)); the panel still calls this right after, which is harmless (`revoked: 0`) |
| `GET /v1/admin/federation/bans` | `users.view` \| `settings.manage` | `{bans: [{identity, issuer, subject, reason, created_by, created_at}]}` newest first |

**RemoteUser:**

```json
{"id": "usr_…", "identity": "alice@boson.chat", "handle": "alice-bosonchat",
 "home_domain": "boson.chat", "home_username": "alice",
 "issuer": "https://auth.boson.chat", "subject": "usr_01J…",
 "display_name": "Alice", "picture": null, "email_verified": true,
 "first_seen_at": "…", "last_login_at": "…", "last_seen_at": "…",
 "banned": true, "banned_at": "…", "ban_reason": "spam",
 "domain_blocked": false, "disabled": true, "sessions": 0}
```

`id` is the local user id (the usual `/v1/admin/users/{id}` endpoints work
on it). `last_seen_at` is the later of the last sign-in and the last
activity. `banned_at` / `ban_reason` only appear while banned.
`domain_blocked`: the home domain matches the effective block list.
`sessions`: active sessions. An account an admin disabled by hand stays
disabled through ban and unban.

Other audit events: `federation_login` (a federated sign-in; `meta:
identity, domain, created, session_id`), `federation_login_failed`
(`meta: reason, domain`), `federation_assertion_issued` (home side;
`meta: audience`), `federation_domain_blocked` (a block list change
caught signed-in accounts; no actor; `meta: domains` = the blocked home
domains with accounts, `accounts` = how many were newly blocked,
`sessions_revoked`).

### Domain blocks

A home domain is blocked while it matches the effective `block` list,
whatever set it (PATCH, the stack config file, `FEDERATION_BLOCK`). Then:

- its sign-ins are refused (`403 domain_blocked`);
- each of its federated accounts, the moment the block is applied, loses
  every session (refresh tokens stop working) and gets an entry on the
  removed-accounts feed (`GET /internal/v1/irc/accounts/removed`, `reason:
  "disabled"`, `cause: "domain_blocked"`), so the stack's boson-ergo helper
  disconnects its IRC clients at its next poll exactly as for a banned
  identity;
- `GET /internal/v1/users/{handle}/irc` answers `disabled: true` for those
  accounts, so the IRC auth-script refuses their OAUTHBEARER /
  IRCV3BEARER logins even with an access token that hasn't expired yet
  (SASL PLAIN never works for federated accounts).

The local accounts are **not** disabled (`disabled` stays `false` in
RemoteUser and the admin user APIs) and nothing is deleted. When the
domain leaves the list its feed entries stop applying, the lookup says
`disabled: false` again and the users simply sign in again; blocking the
domain once more drops them again. Local accounts are never affected, and
a ban stays a ban (its own `disabled` entry) whether or not the domain is
blocked.

"Applied" means: right away after a PATCH; within a second or so of a
config file change (the file watcher); at startup for `FEDERATION_BLOCK`;
and every minute in any case (other replicas, retries). Each account is
handled once per block (`federated_accounts.domain_blocked_at`), so
re-applying is free.

### Settings

`GET /v1/admin/federation`:

```json
{"mode": "directory", "allow": [], "block": [], "directory_url": "https://directory.boson.chat",
 "remote_upload_quota": "", "remote_voice": true,
 "sources": {"mode": "default", "allow": "default", "block": "env", "directory_url": "default",
             "remote_upload_quota": "file", "remote_voice": "database"},
 "editable": true, "issuer": "https://auth.boson.chat", "domain": "boson.chat",
 "remote_users": 12, "remote_role": "Remote", "updated_at": null, "updated_by": null}
```

| field | |
|---|---|
| `mode` | `off` \| `allowlist` \| `directory` \| `open` |
| `allow`, `block` | home domains (`example.org`, or `*.example.org` = it and its subdomains; ≤ 1000 each, lower-cased, de-duplicated) |
| `directory_url` | https URL (trailing `/` dropped) |
| `remote_upload_quota` | remote users' upload quota per rolling window, a size like `1GB` / `500MB` / `2GiB`; `""` = the files service's account quota |
| `remote_voice` | remote users may get voice (and video) tokens; `false` → `POST /v1/voice/token` and call tokens answer `403 remote_voice_disabled` |
| `sources` | per field: `file` (stack config file), `database` (PATCH), `env` (`FEDERATION_*` set), `default` |
| `editable` | PATCH works: no stack config file |
| `issuer`, `domain`, `remote_users`, `remote_role` | read-only: `ISSUER`, `FEDERATION_DOMAIN`, the number of federated accounts, `FEDERATION_REMOTE_ROLE` |

**Where they come from.** With the stack config file (`BOSON_CONFIG`)
present, the `auth.federation` keys win over the env (file > env >
default), are applied live on reload, the database row is ignored and
PATCH answers `409 settings_managed`, exactly like the network settings:

```yaml
auth:
  federation:
    mode: directory            # FEDERATION_MODE
    allow: [boson.chat]        # FEDERATION_ALLOW
    block: [spam.example]      # FEDERATION_BLOCK
    directory_url: https://directory.boson.chat   # FEDERATION_DIRECTORY_URL
    remote_upload_quota: 1GB   # FEDERATION_REMOTE_UPLOAD_QUOTA ("" = account quota)
    remote_voice: true         # FEDERATION_REMOTE_VOICE
```

Invalid values are reported with their line and column (the file then
keeps its last good version). Without the file, PATCH stores overrides in
`federation_settings` over the env defaults; each replica caches them for
`SETTINGS_CACHE_TTL`.

Guests are unaffected by federation (they have no account); remote users
are never guests, so `guest_access` / `guest_voice` don't apply to them.

## Configuration

| Env | Default | |
|---|---|---|
| `FEDERATION_MODE` | `directory` | trust mode (above); also `accepts` in the metadata; `off` stops issuing too |
| `FEDERATION_ALLOW` | – | comma-separated domains / `*.domain` for allowlist mode |
| `FEDERATION_BLOCK` | – | domains refused in every mode |
| `FEDERATION_DIRECTORY_URL` | `https://directory.boson.chat` | directory for directory mode |
| `FEDERATION_DOMAIN` | issuer host minus `auth.` | this install's `boson_domain` |
| `FEDERATION_REMOTE_ROLE` | `Remote` | role new federated accounts get (by name; created when missing); empty = none |
| `FEDERATION_REMOTE_UPLOAD_QUOTA` | – | upload quota per window for remote users (`500MB`, `2GiB`); empty = files default |
| `FEDERATION_REMOTE_MAX_FILE` | – | largest file for remote users; empty = files default (env only) |
| `FEDERATION_REMOTE_VOICE` | `true` | remote users may get voice tokens |
| `FEDERATION_HTTP_TIMEOUT` | `10s` | discovery, JWKS and directory requests |
| `FEDERATION_ALLOW_HTTP` | `false` | dev only: http URLs and private addresses for those requests |
| `FEDERATION_ASSERT_BURST` / `FEDERATION_ASSERT_PER_MINUTE` | `10` / `10` | assertions per user |
| `FILES_INTERNAL_URL` | – | the files service's internal API, e.g. `http://files:3001` (for the remote upload quota) |
| `FILES_INTERNAL_TOKEN` | – | its `INTERNAL_TOKEN` |

## IRC, voice and files

**IRC (Ergo).** The remote's access token for a federated user is an
ordinary access token (`typ at+jwt`, `aud boson`, the remote's `iss`,
`name` = the handle), so the stack's Ergo auth-script accepts it for SASL
OAUTHBEARER / IRCV3BEARER exactly like a local user's, and Ergo
auto-creates the account (`oauth2.autocreate: true`). Grants, vhost and
oper class come from `GET /internal/v1/users/{handle}/irc` and the grants
feed as for any account. Federated users have no password, so SASL PLAIN
fails for them: clients must use the token mechanisms (`IRC_OAUTHBEARER`,
on by default). A ban disables the account, so it shows up in
`/internal/v1/irc/accounts/removed` (`reason: disabled`) and Ergo drops it.
A [domain block](#domain-blocks) does the same for every account of that
domain without disabling them (`reason: disabled`, `cause:
domain_blocked`), and revoke-sessions too (`cause: sessions_revoked`), so
connected IRC clients are dropped at the helper's next poll and their
reconnects are refused while the domain stays blocked. The helper needs no
change for this: it already disconnects (`POST /v1/account_disconnect`)
and keeps the account for `disabled` entries, and its auth-script already
refuses token logins when the user lookup says `disabled`. (With
`IRC_ROLES=false` the auth-script doesn't ask auth, so a still-valid access
token, at most `ACCESS_TOKEN_TTL` old, could reconnect until it expires;
the sessions are gone, so it can't be refreshed.)

**Voice and video.** `POST /v1/voice/token` and call tokens work as for
local users (the token's `name` is the handle), unless `remote_voice` is
off.

**Uploads.** The files service doesn't read roles: it identifies the user
by the access token's `sub` and takes limits from its per-user overrides.
So for remote users auth sets an override through the files internal API,
`PUT {FILES_INTERNAL_URL}/internal/quota/{user_id}` with
`{"quota_bytes": n|null, "max_file_bytes": n|null}` (`DELETE` when both are
back to defaults), at sign-in whenever the configured values differ from
what was last pushed for that account (`federated_accounts.quota_applied`).
A change to the settings reaches each remote user at their next sign-in.
Failures are logged and retried at the next sign-in; they never block the
sign-in. Without `FILES_INTERNAL_URL` / `FILES_INTERNAL_TOKEN` nothing is
pushed and remote users get the account default.

## What the stack needs

- **wellknown** (`images/wellknown/serve.sh`): add a `federation` section
  to boson.json from auth's `GET http://auth:8080/.well-known/boson-federation.json`
  (inside the compose network). The response is the section verbatim:
  `"federation": <body>`. Because `accepts` follows the admin
  setting, refresh it periodically (e.g. every 60 s) rather than once at
  start; if auth is unreachable keep the last good value, and omit the
  section if it was never fetched. boson.json must be served at
  `https://${DOMAIN}/.well-known/boson.json` where `DOMAIN` equals auth's
  `FEDERATION_DOMAIN`.
- **auth** service env: `FEDERATION_DOMAIN: ${DOMAIN}` (when `AUTH_HOST`
  isn't `auth.${DOMAIN}`), optional `FEDERATION_MODE`, `FEDERATION_ALLOW`,
  `FEDERATION_BLOCK`, `FEDERATION_DIRECTORY_URL`,
  `FEDERATION_REMOTE_UPLOAD_QUOTA`, `FEDERATION_REMOTE_MAX_FILE`, and for the
  quota `FILES_INTERNAL_URL: http://files:3001` plus
  `FILES_INTERNAL_TOKEN: ${FILES_INTERNAL_TOKEN:-}` (the token the files
  service already has as `INTERNAL_TOKEN`).
- **Traefik**: nothing new; the endpoints are on the auth host.
- **Ergo**: nothing; keep `IRC_OAUTHBEARER` on. The boson-ergo helper's
  removed-accounts handling (disconnect on `disabled`, patched Ergo's
  `POST /v1/account_disconnect`) covers bans and domain blocks alike; it
  may read `cause` for a nicer QUIT message but doesn't have to.
- **files**: nothing (per-user overrides already exist). A role-based quota
  would need files to read the token's `roles` claim; not required.

## NickServ backend

With `ACCOUNT_BACKEND=nickserv` a federated account is a local record like
the ones NickServ sign-ins create, with no NickServ account behind it. A
NickServ account of the same name never adopts it, whatever
`NICKSERV_LINK_EXISTING` says (the NickServ sign-in gets `409
account_name_conflict`). Handles are only checked against local records,
not against NickServ accounts that never signed in to Boson; v1 federation
targets Ergo networks, where Boson owns the account names.

## Errors

| status | code | when |
|---|---|---|
| 403 | `federation_off` | this server's mode is `off` (login and assertions) |
| 403 | `domain_not_trusted` | allowlist miss, or not verified in the directory ("this server only accepts accounts from verified servers") |
| 403 | `domain_blocked` | the home domain is blocked |
| 403 | `identity_banned` | the identity is banned here |
| 502 | `discovery_failed` | the home's boson.json or JWKS couldn't be fetched or is invalid, the home has federation off, or the directory couldn't be checked |
| 401 | `bad_assertion` | malformed, wrong `typ`, bad signature or unknown key, wrong `aud`, expired, lifetime over 5 min, missing claims, `iss` not the one the domain's boson.json lists |
| 401 | `replayed` | the `jti` was used before |
| 403 | `account_disabled` | the federated account is disabled here |
| 403 | `federated_account` | a federated account asked for an assertion |
| 403 | `remote_voice_disabled` | voice is off for remote users |
| 429 | `rate_limited` | |

Refused sign-ins are audited as `federation_login_failed` with
`meta.reason` (`not_in_directory`, `expired`, `wrong_audience`,
`issuer_mismatch`, …) and `meta.domain`, and counted in
`auth_login_attempts_total{method="federation"}`.
