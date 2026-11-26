# Bridge accounts (evrd managed mode)

When Boson is added to an existing IRC server (boson-chat/stack's
"Add Boson to my existing IRC server" path, the `bridge` profile, stack
`docs/bridge.md`), Boson apps connect through an invisible
[evrd](https://github.com/4evrd/evrd) bridge in **managed mode** (evrd
`docs/managed.md`). Every Boson account needs an account on that bridge.
With `BRIDGE_API_URL` and `BRIDGE_TOKEN` set, auth creates and maintains
those accounts itself through evrd's managed API:

```
PUT/GET/DELETE  $BRIDGE_API_URL/api/managed/users/{username}
GET             $BRIDGE_API_URL/api/managed/users
Authorization:  Bearer $BRIDGE_TOKEN
```

Without them nothing happens: no calls, nothing queued, no endpoints.

This replaces the stack's stopgap `bridge-sync` service (`images/bridgesync`),
which read auth's `users` table and could not pass NickServ logins. **Once this
auth version is deployed with `BRIDGE_API_URL` and `BRIDGE_TOKEN`,
`bridge-sync` can be removed from the stack.** Running both for a while does no
harm: they produce the same accounts, and bridge-sync never sends `auth`.

## Configuration

| Variable | Default | |
|---|---|---|
| `BRIDGE_API_URL` | – | evrd's managed API, e.g. `http://evrd-links:8098`. Use the internal Docker network only: NickServ passwords cross it. |
| `BRIDGE_TOKEN` | – | evrd's `managed_token` (`EVRD_MANAGED_TOKEN`); the stack's `BRIDGE_TOKEN` |
| `BRIDGE_NICKSERV_METHOD` | `nickserv` with `NICKSERV_STRATEGY=identify`, else `sasl` | how the bridge logs NickServ accounts in to the services: `sasl` \| `nickserv` (IDENTIFY once connected) \| `auto` (SASL when offered, else IDENTIFY). Set `nickserv` (or `auto`) when the IRC server has no SASL but auth checks passwords over the services RPC (e.g. Atheme behind ngIRCd). |
| `BRIDGE_POLL_INTERVAL` | `1s` | how often the outbox is checked |
| `BRIDGE_RECONCILE_INTERVAL` | `10m` | a full sync this often (and at startup); `0`: only at startup and on demand |
| `BRIDGE_RETRY_MIN` / `BRIDGE_RETRY_MAX` | `2s` / `5m` | retry backoff for failed pushes (doubling) |
| `BRIDGE_TIMEOUT` | `10s` | deadline for one managed API call |

Setting only one of `BRIDGE_API_URL` / `BRIDGE_TOKEN` is a startup error.

### What the stack must set

On auth's service in the `bridge` profile:

```yaml
BRIDGE_API_URL: http://evrd-links:8098
BRIDGE_TOKEN: ${BRIDGE_TOKEN}
# with NickServ accounts over the services RPC and an IRC server without SASL:
# BRIDGE_NICKSERV_METHOD: nickserv
```

auth must be able to reach `evrd-links:8098` on the compose network. Then
the `bridge-sync` service (and its image) can go. The setup wizard already
knows whether the server has SASL (`pkg/probe`), so it can write
`BRIDGE_NICKSERV_METHOD` when it picks an RPC strategy for a server without
SASL. The stack's own docs/bridge.md "Not yet: NickServ identification on
the bridge" item is then done.

## The accounts

The mapping is bridge-sync's, so the accounts it made are kept, not
duplicated:

| Bridge field | From |
|---|---|
| `{username}` | the Boson username in lower case. A username evrd can't use (`^[A-Za-z][A-Za-z0-9_-]{1,31}$`) is skipped. |
| `subject` | the user id (the access token's `sub`) |
| `email` | the account's email, or `""` |
| `nick` / `altNick` | the username (a NickServ account: the services' spelling; a federated account: its handle, which carries the home domain here, `alice-bosonchat`, [federation.md](federation.md)) / that plus `_` |
| `ident` | the username lower-cased, only `a-z0-9`, at most 10 characters; `boson` if nothing is left |
| `realname` | the display name, or the username |
| `disabled` | the account is disabled (by an admin or a federation ban) |
| `auth` | see below |

**Logins (`auth`).** Local and federated accounts have no password auth
could hand on, so they get `{"method": "none"}` (evrd checks the Boson token
when a client connects either way; federated users sign in to the bridge
with their token like everyone else). Accounts without a login are kept
off nicks someone registered with NickServ on the network by evrd's nick
guard (evrd `docs/managed.md`, `managed_nick_guard`, on by default): on
services' notice, a forced rename or a kill it moves to `altNick`, then
`altNick2`…, and never identifies. An existing bridge account with
evrd's default login (`auto`, no password, which is what bridge-sync made)
is left as it is, since changing it would reconnect every connected user
once for nothing. A NickServ account's login is only ever set by its
sign-in (below); other pushes leave out `auth`, so evrd keeps the saved
login.

### NickServ sign-in

After each successful NickServ sign-in (`POST /v1/login`, and the IRC SASL
bridge's `POST /internal/v1/verify-password`), auth's
`nsaccount.Provisioner` hook PUTs the account with
`auth: {method, account, password}`: `method` from `BRIDGE_NICKSERV_METHOD`,
`account` the NickServ account, `password` the password that was just
verified. evrd keeps it encrypted with its secret key and logs the user in
to NickServ on connect. Because it's sent on every sign-in, a password
changed on IRC reaches the bridge with the next Boson sign-in.

The password:

- is sent only to `BRIDGE_API_URL` (keep it on the internal network);
- is never stored by auth: not in the outbox, not in the audit log, not in
  error texts. The push runs in the background with the password in memory
  only; if the bridge is down it's retried for about two minutes (2 s, 5 s,
  15 s, 30 s, 1 min) and then dropped (metric outcome `dropped`), and the
  next sign-in sends it again;
- is never logged. Error answers from the bridge are cut short and have
  the password replaced by `[redacted]` should evrd ever echo it.

The sign-in itself never waits for or fails on the bridge.

## Lifecycle and reliability

Database triggers on `users` (insert, delete, and updates of `username`,
`email`, `display_name`, `disabled_at`) and on `nickserv_accounts` queue a
row in `bridge_outbox` in the same transaction as the change (migration 15).
So every path that changes an account (the API, the admin panel, the CLI,
federated sign-ins and bans, plain SQL) reaches the bridge, and a bridge
outage loses nothing. The triggers only queue while bridge provisioning is on
(`bridge_state.enabled`, set at startup); turning it off empties the outbox.

| Boson | Bridge |
|---|---|
| account created (sign-up, admin, invite, SSO, first NickServ or federated sign-in) | `PUT`: created |
| display name, email, NickServ link changed | `PUT`: updated |
| renamed | the old name's account is deleted (only if its `subject` is this user's), then `PUT` under the new name |
| disabled / banned, enabled | `PUT` with `disabled: true` / `false` |
| deleted | `DELETE` (only if the account's `subject` is this user's: a freed name can belong to a newer account) |

A worker (every replica runs one) claims due rows (for a lease, so
replicas don't push the same user at once), pushes the user's state as it is
now, and deletes the rows. A failure keeps the rows with `attempts`,
`last_error` and the next attempt after `BRIDGE_RETRY_MIN` doubling up to
`BRIDGE_RETRY_MAX`; retries never give up.

**Full sync.** At startup, every `BRIDGE_RECONCILE_INTERVAL` and on
`POST /internal/v1/bridge/reconcile`, auth makes the bridge's accounts match
its own, as bridge-sync's periodic full sync did: every account is created or
corrected, renamed accounts lose their old bridge account, and bridge
accounts no Boson account has are deleted. One replica runs it at a time (a
lease in `bridge_state`). The first full sync after an upgrade takes over the
accounts bridge-sync made.

### Internal API

| Endpoint | |
|---|---|
| `POST /internal/v1/bridge/reconcile` | `X-Internal-Token`; runs a full sync now → `{ok, result: {users, put, deleted, unchanged, skipped, failed}}`; `502` with `error` when the bridge failed part of it, `409 reconcile_running` while another runs |
| `GET /internal/v1/bridge/status` | `X-Internal-Token`; `{enabled, pending, failing, oldest_pending, last_error, last_reconcile_at, last_reconcile_error}` |

Both are 404 when bridge provisioning is off.

### Metrics and logs

- `auth.bridge.pushes{op, outcome}` (Prometheus `auth_bridge_pushes_total`):
  `op` `put` \| `delete` \| `credentials` (a NickServ login) \| `reconcile`;
  `outcome` `success` \| `error` \| `dropped`.
- `auth.bridge.outbox.pending` (`auth_bridge_outbox_pending`): changes not
  yet pushed. Alert when it stays above zero.
- Logs: `bridge: push failed, will retry` (with `user_id`, `attempts`,
  `retry_in`), `bridge: full sync failed`, `bridge: handing the bridge the
  NickServ login failed`, and an Info line per created or removed account.
