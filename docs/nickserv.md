# NickServ accounts (existing IRC networks)

When Boson is added to an IRC network that already has services (Anope,
Atheme), its users already have NickServ accounts. With
`ACCOUNT_BACKEND=nickserv`, auth uses **those** accounts: people sign in to
Boson with their NickServ account name and password, and the Boson tokens
(voice, files, ...) are issued to that account. There is one identity.

- auth **never stores** a NickServ password. It checks it with the services
  on every sign-in, using one of the [strategies](#strategies) below.
- On the first sign-in auth creates (or [links](#linking-existing-accounts))
  a **local record** keyed by the account name, without a password, so
  roles, profiles, friends and admin tools work as usual.
- Passwords are NickServ's: password change and reset endpoints answer
  `409 password_managed_by_nickserv`.
- Sign-up registers a NickServ account where the services' API allows it
  (Atheme); otherwise it is off and tells people to register on IRC.

The default stays `ACCOUNT_BACKEND=local` (auth's own accounts, as before):
nothing changes for existing installs.

## Strategies

| `NICKSERV_STRATEGY` | Talks to | Checks with | Sign-up | Email / verified | Works with |
|---|---|---|---|---|---|
| `anope_rpc` | Anope's `httpd` + `jsonrpc` | `anope.checkCredentials` (`rpc_user`), `anope.account` (`rpc_data`) for the email | no (see below) | yes / yes (`confirmed`) | Anope 2.1 on any IRCd |
| `atheme_jsonrpc` | Atheme's `misc/httpd` + `transport/jsonrpc` | `atheme.login`, then `NickServ INFO` through `atheme.command` | yes (`NickServ REGISTER`, `VERIFY REGISTER`) | yes / yes | Atheme 7.2+ on any IRCd |
| `atheme_xmlrpc` | Atheme's `misc/httpd` + `transport/xmlrpc` | as above, over XML-RPC | yes | yes / yes | Atheme 7.2+ |
| `sasl` | the IRC server | SASL PLAIN on a connection that never finishes registering, then quits | no | no / no | IRCds with SASL linked to services: InspIRCd 4, UnrealIRCd 6 (Anope or Atheme) |
| `identify` | the IRC server | registers a short-lived client and sends `IDENTIFY <account> <password>` to NickServ, reading its reply notices | no | no / no | last resort, e.g. ngircd (no SASL) with Anope or Atheme |

Prefer the services' RPC (it also gives the email and the verification
state, and the canonical account id); then `sasl`; `identify` only where
neither exists.

**Anope can't register through RPC.** Anope 2.1's RPC has
`anope.checkCredentials`, `anope.identify` (log an *online* user in),
`anope.account`, `anope.listAccounts` and `anope.command`. `NickServ
REGISTER` registers the *calling* nick, which over `anope.command` is
`RPC` (or an existing account): there is no way to register a chosen name.
So with `anope_rpc` sign-up is off.

### What each strategy needs on the network

**Anope 2.1** (`modules.conf` / `anope.conf`):

```
module { name = "httpd"  httpd { name = "httpd/main"  ip = "127.0.0.1"  port = 8080  timeout = 30 } }
module {
	name = "jsonrpc"
	server = "httpd/main"
	token { token = "<NICKSERV_RPC_TOKEN>"  methods = "anope.checkCredentials anope.account" }
}
module { name = "rpc_user" }   # anope.checkCredentials
module { name = "rpc_data" }   # anope.account (email); optional
```

Give the token only those two methods. Anope's `httpd` can serve TLS
(`ssl = yes`); otherwise keep it on loopback or a private network.

**Atheme 7.2+** (`atheme.conf`):

```
loadmodule "modules/misc/httpd";
loadmodule "modules/transport/jsonrpc";     # or transport/xmlrpc
httpd { host = "127.0.0.1"; port = 8080; };
```

Atheme's RPC has no token: whoever reaches it can try passwords (as on
IRC) and register accounts. Keep it on loopback / a private network that
only auth reaches. With `serverinfo::auth = email;` new registrations need
the emailed key; auth handles that (see [Sign-up](#sign-up)).

**SASL / IDENTIFY**: nothing on the services. Every check is a connection
from auth's address, so exempt it from connect throttling and clone limits
(UnrealIRCd `except throttle` / `except connect-flood`, InspIRCd a
`<connect>` class with a high `localmax`/`threshold`, ngircd
`MaxConnectionsIP = 0` or a separate listener). If the server wants a
password for that, set `NICKSERV_IRC_PASSWORD`.

### SASL details

`CAP LS 302` → `CAP REQ :sasl` → `AUTHENTICATE PLAIN` → base64
`\0account\0password` (400-byte chunks) → `903` success / `904` failure /
`902` locked. `CAP END` is never sent, so the check never becomes a user on
the network; `900 RPL_LOGGEDIN` gives the services' spelling of the
account. A server that registers the client at once, answers `421 CAP`, or
offers no `sasl` (or no `PLAIN`) gives `503 accounts_unavailable` with
"not supported" in the log.

### IDENTIFY details and reply patterns

The check registers as `<NICKSERV_IRC_NICK_PREFIX><6 hex>` (default
`bsn123abc`: ngircd's default `NICKLEN` is 9), waits for `001`, sends
`PRIVMSG <target> :IDENTIFY <account> <password>`, and matches notices
**from `NICKSERV_SERVICE_NICK` to its own nick** (formatting stripped)
against three pattern lists. `900 RPL_LOGGEDIN` also counts as success.

| List | Meaning | Anope 2.x default | Atheme 7.x default |
|---|---|---|---|
| success | logged in | `^Password accepted - you are now recognized\.` | `^You are now (?:identified for\|logged in as) (?P<account>[^\s.]\S*?)\.$` |
| failure | wrong password or no such account (counts towards the lockout) | `^Password incorrect\.`, `^Nick \S+ isn't registered\.` | `^Invalid password for \S+\.`, `^\S+ is not a registered nickname\.` |
| refused | the services said no without saying the password is wrong (not counted) | `^Nick \S+ is currently suspended\.`, `has already reached the maximum number of simultaneous logins`, `^Access denied\.` | `because the account has been frozen`, `because the server configuration disallows it`, `^Password authentication is disabled`, `sessions logged in to` |

`NICKSERV_SERVICES` (`anope` \| `atheme`) picks the defaults. Override a
list with `NICKSERV_IDENTIFY_SUCCESS` / `_FAILURE` / `_REFUSED`: Go regular
expressions, one per line or a JSON array (`["^OK$", "^Fine$"]`); a list
left unset keeps its default. A success or failure pattern may capture the
account's canonical name in a group named `account`. A translated NickServ
(non-English `language`) needs its own patterns.

On a network where anyone could hold the nick `NickServ` while services
are down (ngircd without `ServiceMask`, for instance), set
`NICKSERV_SERVICES_SERVER` to the services' server name: the check WHOISes
NickServ and sends the password only if it is on that server. You can also
message `NickServ@services.example.org` with `NICKSERV_SERVICE_TARGET`
where the IRCd supports `nick@server` targets.

## Sign-in

`POST /v1/login {login, password}` (and cookie mode, SSO and everything else
as before) takes the NickServ account name; an email address is `400
invalid_request` (`field: login`). In order:

1. `login` must be a plausible account name (1-64 bytes, no spaces, `@`,
   control characters, leading `:#&`) and the password non-empty, ≤ 512
   bytes, without CR / LF / NUL (which would inject IRC lines); else
   `401 invalid_credentials`.
2. **Lockout** (database, shared by replicas): `429 account_locked` with
   `Retry-After` while the account or the client IP is locked. Locked
   attempts never reach the services.
3. **Rate limit** per account and per IP (in memory): `429 rate_limited`.
   These come on top of the login endpoint's own limits.
4. **Verify** with the strategy, at most `NICKSERV_MAX_CONCURRENT` at once,
   each within `NICKSERV_TIMEOUT`:
   wrong password / unknown account → `401 invalid_credentials` and one
   failure counted for the account and the IP;
   suspended / frozen → `403 account_suspended`;
   refused (IDENTIFY refused pattern) → `403 nickserv_refused` with the
   services' text;
   unreachable, timed out, misconfigured, unsupported → `503
   accounts_unavailable` (logged with the cause, never counted).
5. **Link**: find or create the local record (next section). The services'
   email is copied to the record (verified if the services say the account
   is confirmed) unless another local account has that address.
6. A disabled local account → `403 account_disabled`. An account the
   services report as unconfirmed, while `require_email_verification` is
   on → `403 email_not_verified`.
7. A session with `auth_method: "nickserv"` and the usual tokens.

`/internal/v1/verify-password` (IRC SASL bridge) goes through the same
steps, so a bridge (evrd) can check NickServ credentials through auth.

### The local record

`nickserv_accounts` links a local user to `account` (the services'
spelling), `account_folded` (RFC 1459, unique) and `services_id` (Anope's
`uniqueid`, Atheme's entity id; empty when the strategy can't tell). It may
hold a sealed services session (below) and never a password.

- The local username is the account name. An account name that isn't a
  valid IRC nick (e.g. longer than 30 characters) can't sign in: `409
  account_name_unsupported`.
- `[a]` and `{a}` are the same nick under RFC 1459 but can be different
  NickServ accounts (Anope's default `casemap = "ascii"`). Only the same
  name ignoring ASCII case counts as the same account; the other gets
  `409 account_name_conflict`.
- When the services report another `services_id` than the stored one, the
  name was dropped and registered again by someone, who doesn't get the
  old Boson account: `409 account_reregistered`, audit
  `nickserv_account_reregistered`. An admin resolves it (e.g. deletes or
  renames the old account).

### Linking existing accounts

`NICKSERV_LINK_EXISTING` decides what a first NickServ sign-in does with an
existing local account of the same name that isn't linked yet:

| Value | Links |
|---|---|
| `unclaimed` (default) | only accounts nobody can sign in to: no Boson password, no SSO identity. This is how you give someone a role before they first sign in: `auth user create --username thelion --no-password --role owner`, then `thelion` signs in with NickServ. |
| `all` | also accounts with a Boson password or SSO identity: for a network moving its own Boson accounts to NickServ that trusts the same name is the same person. |
| `none` | never: `409 account_name_conflict`. |

In this backend `auth user create` / `POST /v1/admin/users` refuse a
password (`409 password_managed_by_nickserv`); create accounts without one.

### Services sessions

Atheme's `atheme.login` returns an authcookie. With
`NICKSERV_STORE_SESSION=true` (default) auth keeps it, sealed with
`AUTH_KEY_ENCRYPTION_KEY` (AES-256-GCM, bound to the user id), for up to
55 minutes, and ends it with `atheme.logout` when the Boson session logs
out. With `false` auth logs out of Atheme right after the check. The other
strategies have no session to keep.

## Sign-up

`GET /v1/config` tells clients what to show:

```json
"accounts": {"backend": "nickserv", "signup": false, "password_reset": false,
             "signup_message": "Accounts on this network are NickServ accounts. Register on IRC with /msg NickServ REGISTER <password> <email>, then sign in here with that account name and password."}
```

(`backend: "local"`, `signup: true`, `password_reset: true` and
`signup_message: null` on the local backend.)

- **Atheme** (`atheme_jsonrpc` / `atheme_xmlrpc`, `NICKSERV_REGISTRATION=true`):
  `POST /v1/register {username, email, password, invite_code?}` follows the
  `registration` setting (`closed`, `invite`: the invite is only used up if
  the registration succeeds), then runs `NickServ REGISTER` and creates the
  local record. → `201 {user, verification, message,
  email_verification_sent, email_verification_required}`.
  - `verification: "nickserv_code"`: the network requires email
    verification (`auth = email`) and Atheme has mailed a key. The client
    asks for it and sends `POST /v1/register/confirm {username, password,
    code}` → `200`, or `400 invalid_code`. Atheme 7.2 accepts `VERIFY
    REGISTER` only from the account itself, so auth logs in with the
    password first (and out again); this counts like a sign-in for the rate
    limits and lockout (`401 invalid_credentials` for a wrong password).
    Atheme 7.3+ also takes it without the password. (Running `/msg NickServ VERIFY REGISTER
    <account> <key>` on IRC works too.) Until then sign-in gives `403
    email_not_verified` while `require_email_verification` is on.
  - `verification: ""`: nothing to verify; sign in.
  - `409 username_taken` (registered already, or a local account has the
    name), `400 registration_rejected` with Atheme's reason (bad email,
    too many accounts for that email, ...).
  Auth sends no email of its own here.
- **Everything else** (and `NICKSERV_REGISTRATION=false`): `POST
  /v1/register` → `403 registration_unavailable` with `signup_message`
  (`NICKSERV_SIGNUP_MESSAGE` overrides it, e.g. to link a web registration
  page).

## Security

- **Passwords** go only to the services (RPC body or IRC connection). They
  are never logged, stored, put into errors, or sent through an HTTP proxy
  from the environment; RPC redirects aren't followed. CR / LF / NUL in
  passwords or account names are refused before anything is sent.
- **Rate limits**: per account and per client IP token buckets
  (`NICKSERV_RATE_*`) before any check, on top of the endpoint limits.
- **Lockout**: `NICKSERV_LOCKOUT_THRESHOLD` (10) failures for an account,
  or `NICKSERV_LOCKOUT_IP_THRESHOLD` (30) from one IP, within
  `NICKSERV_LOCKOUT_WINDOW` (15 m) lock it for `NICKSERV_LOCKOUT_DURATION`
  (15 m). Stored in `nickserv_lockouts`, so all replicas see it and a
  restart doesn't clear it. A successful sign-in clears the account's
  count. Anyone can lock a known account for the lock duration by guessing
  (by design, the price of stopping password guessing through Boson); the
  IP threshold is higher so a shared NAT isn't locked out by one person.
  Services and IRC outages don't count.
- **Timeouts**: every check (dial, TLS, IRC registration, the reply, RPC
  calls) ends within `NICKSERV_TIMEOUT` (10 s); a cancelled request aborts
  its connection.
- **TLS**: `NICKSERV_IRC_TLS=true` by default. `NICKSERV_TLS_CA_FILE`
  replaces the system roots with your CA(s); `NICKSERV_TLS_PIN_SHA256` pins
  the server's public key (SHA-256 of the SubjectPublicKeyInfo, hex or
  base64, comma-separated for rotation). A pin without a CA file accepts a
  self-signed certificate with that key and nothing else; with both, the
  chain, name and pin must all match. Get a pin with
  `openssl s_client -connect irc.example.org:6697 </dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256`.
  The same settings apply to an `https://` RPC URL.
- **Plain text**: an `http://` RPC URL or `NICKSERV_IRC_TLS=false` is only
  accepted for loopback hosts, or with `NICKSERV_ALLOW_PLAINTEXT=true` (a
  private Docker network, say); auth refuses to start otherwise.
- **Audit**: `login` / `login_failed` with `method: "nickserv"` (reasons
  `wrong_password`, `locked`, `suspended`, `refused`, `invalid_input`,
  `disabled`), `nickserv_account_linked` (`account`, `existing`,
  `registered`), `nickserv_account_reregistered`. Metric
  `auth_nickserv_checks_total{strategy, outcome}` (`success`,
  `invalid_credentials`, `suspended`, `refused`, `unavailable`, `locked`,
  `rate_limited`, `rejected`).

## Configuration

All environment variables (restart to change). The setup wizard writes
them to `.env` / the auth service's environment.

| Variable | Default | |
|---|---|---|
| `ACCOUNT_BACKEND` | `local` | `local` \| `nickserv` |
| `NICKSERV_STRATEGY` | – | **required** with `nickserv`: `anope_rpc` \| `atheme_jsonrpc` \| `atheme_xmlrpc` \| `sasl` \| `identify` |
| `NICKSERV_SERVICES` | from the strategy (`atheme` for `atheme_*`, else `anope`) | `anope` \| `atheme`: IDENTIFY reply defaults |
| `NICKSERV_RPC_URL` | – | RPC strategies: `http(s)://host:port/jsonrpc` (or `/xmlrpc`) |
| `NICKSERV_RPC_TOKEN` | – | `anope_rpc`: the jsonrpc `token` (sent as `Bearer base64(token)`); secret |
| `NICKSERV_IRC_ADDR` | – | `sasl` / `identify`: `host:port` |
| `NICKSERV_IRC_TLS` | `true` | TLS to the IRC server |
| `NICKSERV_IRC_PASSWORD` | – | server password (`PASS`) for the check connections; secret |
| `NICKSERV_IRC_NICK_PREFIX` | `bsn` | check nick = prefix + 6 hex (letters/digits, starts with a letter) |
| `NICKSERV_ALLOW_PLAINTEXT` | `false` | allow `http://` RPC / IRC without TLS to non-loopback hosts |
| `NICKSERV_TLS_CA_FILE` | – | PEM CA(s) instead of the system roots |
| `NICKSERV_TLS_PIN_SHA256` | – | SPKI SHA-256 pins, hex or base64, comma-separated |
| `NICKSERV_TLS_SERVER_NAME` | the dialled host | name the certificate must have |
| `NICKSERV_TIMEOUT` | `10s` | deadline of one check (max `2m`) |
| `NICKSERV_MAX_CONCURRENT` | `8` | checks in flight at once |
| `NICKSERV_SERVICE_NICK` | `NickServ` | who answers IDENTIFY |
| `NICKSERV_SERVICE_TARGET` | `NICKSERV_SERVICE_NICK` | IDENTIFY's PRIVMSG target (e.g. `NickServ@services.example.org`) |
| `NICKSERV_SERVICES_SERVER` | – | send IDENTIFY only if NickServ is on this server (WHOIS) |
| `NICKSERV_IDENTIFY_SUCCESS` / `_FAILURE` / `_REFUSED` | per `NICKSERV_SERVICES` | regexps, one per line or a JSON array |
| `NICKSERV_REGISTRATION` | `true` | Boson sign-up registers NickServ accounts when the strategy can |
| `NICKSERV_SIGNUP_MESSAGE` | register on IRC (see above) | shown when sign-up is off |
| `NICKSERV_LINK_EXISTING` | `unclaimed` | `unclaimed` \| `all` \| `none` ([above](#linking-existing-accounts)) |
| `NICKSERV_STORE_SESSION` | `true` | keep (sealed) and end Atheme's authcookie |
| `NICKSERV_RATE_ACCOUNT_BURST` / `_PER_MINUTE` | `5` / `2` | checks per account |
| `NICKSERV_RATE_IP_BURST` / `_PER_MINUTE` | `10` / `5` | checks per client IP |
| `NICKSERV_LOCKOUT_THRESHOLD` | `10` | failures per account before a lock (`0` = off) |
| `NICKSERV_LOCKOUT_IP_THRESHOLD` | `30` | failures per IP before a lock (`0` = off) |
| `NICKSERV_LOCKOUT_WINDOW` / `_DURATION` | `15m` / `15m` | counting window / lock length |

Examples:

```sh
# Anope 2.1, RPC on the services host's loopback (auth on the same host)
ACCOUNT_BACKEND=nickserv
NICKSERV_STRATEGY=anope_rpc
NICKSERV_RPC_URL=http://127.0.0.1:8080/jsonrpc
NICKSERV_RPC_TOKEN=...

# Atheme on a private Docker network, with Boson sign-up
ACCOUNT_BACKEND=nickserv
NICKSERV_STRATEGY=atheme_jsonrpc
NICKSERV_RPC_URL=http://atheme:8080/jsonrpc
NICKSERV_ALLOW_PLAINTEXT=true

# UnrealIRCd 6 / InspIRCd 4 with SASL, self-signed certificate pinned
ACCOUNT_BACKEND=nickserv
NICKSERV_STRATEGY=sasl
NICKSERV_IRC_ADDR=irc.example.org:6697
NICKSERV_TLS_PIN_SHA256=3f1c...e9

# ngircd + Anope, no SASL
ACCOUNT_BACKEND=nickserv
NICKSERV_STRATEGY=identify
NICKSERV_SERVICES=anope
NICKSERV_IRC_ADDR=irc.example.org:6697
NICKSERV_SERVICES_SERVER=services.example.org
```

### Choosing a strategy (for the setup wizard)

1. Services API reachable from auth? Anope 2.1 with `jsonrpc` → `anope_rpc`;
   Atheme with `transport/jsonrpc` → `atheme_jsonrpc` (`transport/xmlrpc`
   → `atheme_xmlrpc`).
2. Else, does the IRCd offer `sasl` with `PLAIN` in `CAP LS 302` while the
   services are linked? → `sasl`.
3. Else → `identify`, with `NICKSERV_SERVICES` set to the services package
   and `NICKSERV_SERVICES_SERVER` to its server name.

## Tests

- `go test ./internal/services/nickserv/`: every strategy against fake
  servers (JSON-RPC / XML-RPC Anope and Atheme, a scripted IRC server with
  TLS), including timeouts, line injection, pins, CA files and impostor
  NickServs.
- `test/integration/nickserv_test.go` (with `TEST_DATABASE_URL`): the HTTP
  flows (sign-in, linking, conflicts, lockout across restarts, sign-up and
  confirmation, logout ending the Atheme session) with fake services RPC.
- `make test-nickserv`: `test/nickserv/compose.yaml` starts **Anope 2.1.28
  behind InspIRCd 4.12** and **Atheme 7.2.12 behind ngircd 27** (TLS with
  a generated test CA), then `go test ./test/nickserv/` runs `anope_rpc`,
  `sasl` and `identify` against the first, `atheme_jsonrpc`,
  `atheme_xmlrpc`, `identify` and the "ngircd has no SASL" case against
  the second, and Atheme sign-up with the mailed key. CI runs it as the
  `nickserv` job. `make test-nickserv-clean` removes the containers,
  volumes and images (project `auth-nickserv-test`, label
  `auth-nickserv-test=1`).

The fixture Dockerfiles and configs are meant to move to boson-chat/stack's
`test/ircds/` once that exists (one pinned set per IRCd and services
package for the setup probe and for these tests); `TEST_NICKSERV_*`
variables already let the tests point at other addresses.

## Later: evrd

Where a network lacks IRCv3, Boson fronts it with an evrd bridge. evrd's
managed mode will get a provisioning API; auth will then create the evrd
user for a NickServ account when it signs in. The hook is
`nsaccount.Provisioner` (`AccountSignedIn(ctx, user, account)`), called after
every successful NickServ sign-in; errors are logged and never block the
sign-in. Nothing implements it yet.

## Limitations

- Sessions don't follow NickServ: a password change or a dropped account
  on IRC doesn't end existing Boson sessions (refresh tokens live
  `REFRESH_TOKEN_TTL`). Disable the local account to cut someone off.
- `sasl` and `identify` learn no email and no stable account id, so the
  "registered again" check and email sync need an RPC strategy.
- `identify` depends on English (or configured) reply texts.
- Anope sign-up isn't possible through its RPC (see above).
- No email login in this backend.
