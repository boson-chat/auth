# Network roles and permissions

Roles are **network-wide and IRC-native**. Each role carries a set of
permissions from a closed catalog, and maps to an **Ergo oper class** (its
WHOIS line and IRC oper capabilities) and optionally a **vhost**, which Ergo
applies at login. auth is the store; Ergo, quicvoiced, the admin panel and
clients read from it. Channel-level ranks (op, voice, founder) stay IRC
ranks managed by ChanServ (AMODE) and are not roles.

- [Model](#model) · [Built-in roles](#built-in-roles) · [Permissions](#permissions)
- [Hierarchy](#hierarchy) · [Admin API](#admin-api) · [Public API](#public-api)
- [Tokens](#tokens) · [Ergo integration](#ergo-integration) · [quicvoiced](#quicvoiced)
- [Channel creation settings](#channel-creation-settings) · [Channel lifecycle settings](#channel-lifecycle-settings) · [Migrating from 1.x](#migrating-from-1x)

## Model

```json
{
  "id": "rol_01JD…", "name": "Chat Helper", "slug": "chat-helper",
  "color": "#1abc9c", "position": 300, "builtin": null,
  "permissions": ["users.view", "irc.samode"],
  "irc": {"whois_line": null, "vhost": "{username}.helpers.boson.chat", "oper": true},
  "hoist": true, "mentionable": false, "member_count": 4,
  "created_at": "2026-11-13T21:04:05Z", "updated_at": "2026-11-13T21:04:05Z"
}
```

| Field | |
|---|---|
| `id` | `rol_<ULID>`; built-ins have fixed ids (below) |
| `name` | 1–32 characters: ASCII letters, digits, space, `-`, `_`. Unique case-insensitively |
| `slug` | lower-cased name with spaces as `-`: the **Ergo oper class name**. Also unique (so `Mod Team` and `mod-team` can't both exist) |
| `color` | `#rrggbb` (stored lower-case) or `null` |
| `position` | higher = more senior. Owner `1000`, Member `0`, every other role `1`–`999` (default `1`). Ties are allowed; lists sort by position desc, then creation |
| `builtin` | `owner` \| `admin` \| `moderator` \| `member` \| `null` |
| `permissions` | catalog ids, de-duplicated, in catalog order. For Owner always the whole catalog |
| `irc.whois_line` | stored line or `null` = default `is a <name>` (`is an` before a vowel) |
| `irc.vhost` | vhost **template** or `null` ([rules](#vhosts)) |
| `irc.oper` | effective: `true` if set explicitly **or** the role has any `irc.*` permission |
| `hoist` | show holders separately in member lists |
| `mentionable` | clients may offer `@role` mentions |
| `member_count` | holders; for Member every account |

Assignments live in `user_roles (user_id, role_id, assigned_by, assigned_at)`.
**Member is implicit**: every account holds it, it is never stored, it can't
be assigned, removed or deleted, and it is not listed in a user's `roles`
(its permissions are in their `permissions`). A user's effective permissions
are the union over Member and their roles.

## Built-in roles

Seeded by migration 4. Not deletable or renamable; Owner and Member keep
their positions; Owner's permissions are fixed (always everything). Colour,
WHOIS line, vhost, hoist and mentionable are editable on all four, and so are
the permissions of Admin, Moderator and Member.

| Role | id | Position | Permissions |
|---|---|---|---|
| Owner | `rol_00000000000000000000000001` | 1000 | everything (including permissions added in later versions) |
| Admin | `rol_00000000000000000000000002` | 900 | everything except `roles.owner` |
| Moderator | `rol_00000000000000000000000003` | 500 | `users.view users.moderate invites.manage audit.view channel.create voice.create voice.manage_any voice.bypass_locks irc.kill irc.ban irc.nofakelag irc.vhosts irc.sajoin irc.samode irc.history` |
| Member | `rol_00000000000000000000000004` | 0 | `channel.create voice.create` |

Owner, Admin and Moderator are hoisted and coloured (`#f1c40f`, `#e74c3c`,
`#3498db`). Moderator has no `admin.panel`: moderators work on IRC and in
voice; give a role `admin.panel` to let them open the panel.

## Permissions

`GET /v1/admin/permissions` (needs `admin.panel`) returns the catalog:
`{"permissions": [{"id", "group": "admin"|"network"|"irc", "label", "description"}]}`.
Unknown ids are rejected with `400 invalid_request`.

### admin

| id | Grants |
|---|---|
| `admin.panel` | open the admin panel; read roles, permissions and settings. Also makes the 1.x `role` claim `admin` |
| `users.view` | list/search users, see a user, their sessions and roles |
| `users.manage` | create users, send password resets / verification emails, disable/enable, revoke sessions |
| `users.moderate` | disable/enable users and revoke their sessions (only) |
| `invites.manage` | list, create, revoke invite codes |
| `settings.manage` | change the network settings |
| `sso.manage` | manage SSO identity providers |
| `services.view`, `services.manage` | for the admin panel's service pages (not checked by auth) |
| `audit.view` | read the audit log |
| `roles.manage` | create/edit/delete/reorder roles and assign them, within the [hierarchy](#hierarchy) |
| `roles.owner` | edit the Owner role and give/remove it (ownership transfer) |
| `directory.manage` | for the admin panel's channel directory (not checked by auth) |

### network (enforced by Ergo and quicvoiced)

| id | Grants |
|---|---|
| `channel.create` | register IRC text channels (see [settings](#channel-creation-settings)) |
| `voice.create` | create voice channels |
| `voice.manage_any` | moderate/edit/delete any voice channel; makes the voice-token `role` `moderator` |
| `voice.bypass_locks` | join locked or full voice channels |

### irc (Ergo v2.19.1 oper capabilities, `irc.<capability>`)

`irc.kill`, `irc.ban`, `irc.nofakelag`, `irc.relaymsg`, `irc.vhosts`,
`irc.sajoin`, `irc.samode`, `irc.snomasks`, `irc.roleplay`, `irc.rehash`,
`irc.accreg`, `irc.chanreg`, `irc.history`, `irc.defcon`,
`irc.massmessage`, `irc.metadata`: exactly the capability names Ergo
v2.19.1 checks (`irc/commands.go`, `HasRoleCapab(s)`, `default.yaml`
oper-classes). Ergo has no `kick` or `die` capability (opers kick through
`samode`; `local_`/`oper:` prefixes are legacy aliases Ergo strips), so there
are no `irc.kick` / `irc.die`.

### Admin endpoint → permission

A request needs **any one** of the listed permissions, read from the
database on every request (never from the token).

| Endpoint | Permission |
|---|---|
| `GET /v1/admin/users`, `GET /v1/admin/users/{id}`, `GET /v1/admin/users/{id}/sessions` | `users.view` |
| `POST /v1/admin/users`, `POST …/{id}/password-reset`, `POST …/{id}/verification` | `users.manage` (+ `roles.manage` and the hierarchy for `role: admin\|owner`) |
| `POST /v1/admin/users/{id}/disable`, `…/enable`, `DELETE /v1/admin/sessions/{id}` | `users.moderate` or `users.manage` (+ outrank the user) |
| `PATCH /v1/admin/users/{id}` (`{role}`, 1.x) | `roles.manage` |
| `PUT /v1/admin/users/{id}/roles` | `roles.manage` |
| `GET/POST /v1/admin/invites`, `DELETE /v1/admin/invites/{id}` | `invites.manage` |
| `GET /v1/admin/audit` | `audit.view` |
| `GET /v1/admin/settings` | `admin.panel` or `settings.manage` |
| `PATCH /v1/admin/settings` | `settings.manage` |
| `/v1/admin/sso/providers…` (all) | `sso.manage` |
| `GET /v1/admin/permissions`, `GET /v1/admin/roles`, `GET /v1/admin/roles/{id}`, `GET /v1/admin/roles/{id}/members` | `admin.panel` |
| `POST /v1/admin/roles`, `PATCH`/`DELETE /v1/admin/roles/{id}`, `POST /v1/admin/roles/reorder` | `roles.manage` |

## Hierarchy

The Discord rule, with Owner on top:

- You can only **create, edit, delete, reorder, assign or remove** roles
  whose position is **strictly below your highest role**, and only move
  roles to positions below it.
- You can only **grant permissions you hold** (`403 permission_not_held`).
  Removing permissions is allowed.
- You can only act on **users whose highest role is below yours** (assign
  roles, disable/enable, revoke sessions, the 1.x role switch). You may
  change your own roles below your rank.
- **Owners bypass** all of it. `roles.owner` lets a non-Owner manage the
  Owner role itself (edit it, give it, take it); only an Owner can grant it.
- The **last Owner can't be removed** (`409 last_owner`). Role changes are
  serialised with a row lock, so two Owners demoting each other at once
  leave one Owner.

So an Admin (900) can create, edit and assign Moderator, Member and custom
roles below 900, but not create other Admins, edit the Admin role, or act on
other Admins; that takes an Owner. (In 1.x every admin could promote others.)

Violations are `403 role_hierarchy`.

## Admin API

All bodies are JSON. Roles come in the [model](#model) shape.

| Method & path | Body → response |
|---|---|
| `GET /v1/admin/roles` | → `{roles: [role]}`, most senior first, each with `member_count` |
| `GET /v1/admin/roles/{id}` | → `{role}` |
| `POST /v1/admin/roles` | `{name, color?, position?, permissions?, irc?: {whois_line?, vhost?, oper?}, hoist?, mentionable?}` → 201 `{role}` |
| `PATCH /v1/admin/roles/{id}` | any subset of the create fields → `{role}`. `null` clears `color`, `irc.whois_line`, `irc.vhost`. Optional `If-Match: <updated_at>` → `412 precondition_failed` if the role changed since |
| `DELETE /v1/admin/roles/{id}` | → 204; holders lose the role. `409 builtin_role` for built-ins |
| `POST /v1/admin/roles/reorder` | `{order: [role id, …]}` most senior first → `{roles}` (all roles) |
| `GET /v1/admin/roles/{id}/members?cursor=&limit=` | → `{users: [{id, username, display_name, disabled, assigned_at, assigned_by}], next_cursor}`; `limit` 1–200 (default 50), ordered by user id; for Member every account, with `assigned_*` `null` |
| `PUT /v1/admin/users/{id}/roles` | `{role_ids: [id, …]}` (replaces; Member's id is ignored) → `{roles: [{id, name, color, position}]}` |
| `GET /v1/admin/users/{id}` | adds `roles: [{id, name, color, position}]` and `permissions: [id, …]` (effective) |
| `GET /v1/admin/users` | each user also has `roles: [{id, name, color, position}]` |
| `GET /v1/admin/permissions` | → `{permissions: [{id, group, label, description}]}` |

`GET /v1/me` adds `roles` and `permissions` the same way.

**Reorder** takes any subset of the roles except Owner and Member. The
listed roles get their own current positions back in the new order; if
several shared a position (e.g. new roles all at `1`) they are spread out to
distinct ones (`[1,1,1]` → `3,2,1`). Unlisted roles don't move. Each moved
role must be below you before and after.

Errors: `400 invalid_request` (validation, unknown role or permission,
built-in rules), `403 forbidden` (missing permission), `403 role_hierarchy`,
`403 permission_not_held`, `404 not_found`, `409 role_name_taken`,
`409 builtin_role`, `409 last_owner`, `412 precondition_failed`.

**Audit events:** `role_created` (`meta.role_id`, `meta.role` snapshot),
`role_updated` (`meta.role_id`, `meta.name`, `meta.old` / `meta.new` with
the changed fields only; `meta.reorder: true` for reorders),
`role_deleted` (`meta.role`, `meta.member_count`) and `user_roles_changed`
(target = the user; `meta.old`, `meta.new`, `meta.added`, `meta.removed`
role ids). The 1.x `PATCH {role}` still also records `admin_role_changed`.

### Vhosts

`irc.vhost` is a template: static characters plus any number of
`{username}`. Templates are validated on write so that **every rendering is
a vhost Ergo accepts** with its defaults (`accounts.vhosts.valid-regexp`
`^[0-9A-Za-z.\-_/]+$`, `max-length` 64):

- static characters: letters, digits, `.`, `-`, `_`, `/`;
- at most 64 bytes with a 30-character username;
- not starting or ending with `.` or `/`, no `..` or `//`.

`{username}` is the account name lower-cased (ASCII), with the nick
characters Ergo rejects in vhosts (`[`, `]`, `\`, `` ` ``, `^`, `{`, `|`, `}`) replaced by `-`:
`Bob[x]` → `bob-x-`. Examples: `{username}.staff.boson.chat`,
`staff/{username}`, `users.boson.chat` (shared). Different accounts can end
up with the same vhost (`a[` and `a]`); vhosts are cosmetic, not identities.

## Public API

No authentication; rate-limited per IP (`RATE_LIMIT_PUBLIC_BURST` 60,
`RATE_LIMIT_PUBLIC_PER_MINUTE` 120) and `Cache-Control: public, max-age=60`.
For badges and colours in clients.

| Method & path | Response |
|---|---|
| `GET /v1/roles` | `{roles: [{id, name, color, position, hoist, mentionable}]}` (all roles incl. Member, most senior first). `ETag`; `If-None-Match` → 304 |
| `GET /v1/users/roles?username=a&username=b` | `{users: {"a": ["rol_…"], "b": []}}`. 1–100 names (repeat the parameter or comma-separate). Keys are the names **as requested**; lookups fold RFC 1459 case. Unknown accounts are absent. Only **visible** roles: hoisted or coloured, never Member. More than 100 → `400` |

## Tokens

Access token (aud `boson`) adds:

| Claim | |
|---|---|
| `roles` | assigned role names, most senior first, at most 20; omitted when none |
| `perms` | effective permission ids (always present) |
| `role` | 1.x: `admin` iff `perms` has `admin.panel`, else `user` |

Voice token (aud `quicvoice`) adds `roles` and `perms` restricted to the
**network** group (`channel.create`, `voice.create`, `voice.manage_any`,
`voice.bypass_locks`); `role` is `moderator` iff `voice.manage_any`, else
`speaker`. Tokens are snapshots: a change shows up at the next refresh
(≤ `ACCESS_TOKEN_TTL`). auth's own API never trusts them for permissions.

## Ergo integration

Internal listener, header `X-Internal-Token`.

### `GET /internal/v1/roles`

Every role with what Ergo needs to render oper classes:

```json
{"version": "5f0c…", "roles": [
  {"id": "rol_00000000000000000000000003", "name": "Moderator", "slug": "moderator", "color": "#3498db",
   "position": 500, "builtin": "moderator", "permissions": ["users.view", "…", "irc.history"],
   "irc": {"whois_line": "is a Moderator", "vhost": null, "oper": true, "oper_class": "moderator",
           "capabilities": ["kill", "ban", "nofakelag", "vhosts", "sajoin", "samode", "history"]},
   "hoist": true, "mentionable": false, "updated_at": "…"}
]}
```

`irc.whois_line` is the effective line (default applied), `oper_class` the
slug (or `null` when the role isn't an oper), `capabilities` the Ergo names.
`version` changes whenever any role changes and is also the `ETag`
(`"<version>"`); poll with `If-None-Match` to get `304` while nothing
changed. Suggested Ergo rendering: one `oper-classes` entry per role with
`oper: true` (`title` = name, `whois-line`, `capabilities`), no `extends`
(capabilities are already effective), then rehash when the version changes.

### `POST /internal/v1/verify-password` (SASL PLAIN)

Unchanged request. A successful response adds:

```json
{"ok": true, "user_id": "usr_…", "username": "Bob[x]",
 "irc": {"oper_class": "staff", "whois_line": "is boson staff", "vhost": "bob-x-.staff.boson.chat"},
 "roles": ["Staff", "Moderator"], "permissions": ["…"]}
```

`irc.oper_class` / `whois_line` come from the **most senior role that is an
oper**, `irc.vhost` (rendered) from the **most senior role with a vhost
template** (possibly Member). Each is `null` when no role supplies it.
Failures (`ok: false`) carry no `irc`.

### `GET /internal/v1/users/{username}/irc` (OAUTHBEARER / SSO logins)

```json
{"user_id": "usr_…", "username": "carl", "disabled": false,
 "irc": {"oper_class": null, "whois_line": null, "vhost": "users/carl"},
 "roles": [], "permissions": ["channel.create", "voice.create"]}
```

`username` is matched with RFC 1459 folding; `404 not_found` for unknown
accounts. `disabled` is reported, not refused: Ergo should not log a
disabled account in.

### `GET /internal/v1/roles/{id}/members` (RoleServ `WHO`)

The [admin API's members list](#admin-api) on the internal listener: same
query (`cursor`, `limit` 1–200) and response (`{users: [{id, username,
display_name, disabled, assigned_at, assigned_by}], next_cursor}`).

### `GET /internal/v1/irc/grants` (live changes)

Every **enabled** account whose `irc` object (as in verify-password) has a
non-null `oper_class` or `vhost`, by username (RFC 1459-folded):

```json
{"version": "42", "users": [
  {"username": "alice", "oper_class": "admin", "whois_line": "is a Network Administrator", "vhost": "staff/alice"},
  {"username": "dave", "oper_class": null, "whois_line": null, "vhost": "dj/dave"}]}
```

`ETag: "<version>"`; with `If-None-Match` and nothing changed, `304` costs
one single-row read. An account that drops out of the list (disabled,
deleted, lost its roles) should be de-opered and lose its vhost. A vhost
template on Member puts every enabled account in the list.

`version` is a counter (table `irc_grants_version`, migration 5) bumped by
database triggers on any write to `roles` or `user_roles`, on user creation
and deletion, and when a user's `username` or `disabled_at` changes, so
every path (admin API, acting API, CLI, SQL) moves it. The triggers are
deferred to commit and bump at most once per transaction; the version is
read before the data, so a body is never older than its ETag. Unrelated
changes (e.g. a role colour) may also bump it: pollers then refetch an
identical list.

### `GET /internal/v1/irc/accounts/removed` (deleted and disabled accounts)

A feed of account removals, so IRC can drop accounts that were deleted or
disabled by any path (admin API, CLI, SQL):

```
GET /internal/v1/irc/accounts/removed?since=<cursor>&limit=<n>
```

```json
{"accounts": [
  {"username": "alice", "reason": "deleted", "at": "2026-11-14T12:57:13.527378Z"},
  {"username": "bob", "reason": "disabled", "at": "2026-11-14T12:57:20.26056Z"}],
 "next": "3513.4"}
```

- `since`: the `next` of the previous response; empty or absent = from the
  beginning. The cursor is opaque (today `<txid>.<id>`); anything else is
  `400 invalid_request`.
- `limit`: 1–1000, default 500; otherwise `400 invalid_request`.
- `accounts`: in commit order, strictly after `since`, never `null`.
  `username` is the account name when it was removed, `at` is RFC 3339 UTC.
- `next`: pass it as `since` next time. With nothing new it equals `since`
  (`""` when `since` was empty). Fewer than `limit` entries does not mean
  caught up (filtered entries count against the limit); poll until `next`
  stops changing.

Entries that no longer apply are left out, but the cursor still moves past
them:

- `deleted`: omitted while an account with the same username (RFC 1459
  folding, as everywhere) exists again, so IRC never wipes a re-created
  account that belongs to someone else.
- `disabled`: omitted once the account is enabled again, or deleted (its
  `deleted` entry covers it). Disabling an already disabled account adds
  nothing.

Source: `irc_account_removals` (migration 7), filled by triggers on `users`
(`AFTER DELETE` → `deleted`; `disabled_at` going from `NULL` to a time →
`disabled`). Each row stores the user id, the username at the time and the
writing transaction's id (`xid8`). The feed is ordered by `(txid, id)` and
only returns rows from transactions older than every transaction still in
flight, so a slow transaction can never commit a row behind a cursor that
was already handed out. Rows older than 180 days are pruned by the hourly
cleanup; a poller that is offline longer than that should resynchronise.

IRC side (the stack's `boson-ergo` helper): for `deleted` it erases the
Ergo account, which also unregisters that account's channels; for
`disabled` it keeps the account and its channels, so re-enabling restores
everything (the account just can't log in meanwhile; idle channels still
expire under [`channel_expiry_days`](#channel-lifecycle-settings)).

## Acting API (RoleServ)

The [admin API](#admin-api) role writes, mirrored on the internal listener
under `/internal/v1/acting` for RoleServ, which acts **as** the IRC user
who sent the command:

- `X-Internal-Token: <INTERNAL_ACTING_TOKEN>`, a separate secret only
  RoleServ has. `INTERNAL_API_TOKEN` is **not** accepted (otherwise every
  internal client could act as anyone), and auth refuses to start with the
  two equal. With `INTERNAL_ACTING_TOKEN` unset the whole prefix is `404`.
  A wrong token is `401 unauthenticated`.
- `X-Acting-Account: <username>`: the Ergo account (= auth username, RFC
  1459 folding). Loaded like a session user: unknown or disabled →
  `403 forbidden`.
- `X-Acting-Via: roleserv` (optional, `[a-z0-9_-]{1,32}`, default
  `roleserv`): recorded as `meta.via` on the audit events, whose actor is the
  acting user.
- `X-Forwarded-For`: the IRC user's address, for the audit log (as on the
  rest of the internal API).

Permissions are read from the database and the [hierarchy](#hierarchy),
validation, error codes and audit events are exactly the admin API's.

| Method & path | Needs | Body → response |
|---|---|---|
| `GET /internal/v1/acting/me` | – | → `{username, permissions: [id, …]}` (effective) |
| `POST /internal/v1/acting/roles` | `roles.manage` | as `POST /v1/admin/roles` → 201 `{role}` |
| `PATCH /internal/v1/acting/roles/{id}` | `roles.manage` | as `PATCH /v1/admin/roles/{id}` → `{role}`; `null` clears |
| `DELETE /internal/v1/acting/roles/{id}` | `roles.manage` | → 204 |
| `PUT /internal/v1/acting/users/{user_id}/roles` | `roles.manage` | `{role_ids}` (replaces) → `{roles: [{id, name, color, position}]}` |

The user id comes from `GET /internal/v1/users/{username}/irc`. To avoid
lost updates when two people edit one role, send `If-Match: <updated_at>`
(the role's `updated_at` as last read, quoted or not) on `PATCH`: `412
precondition_failed` if the role changed since.

## Role channels (channel access and auto-join)

Discord-style: admins attach IRC channels to roles, and to **everyone**
(the built-in Member role; the API uses the role id `everyone` for it), and
mark channels **private**. RoleServ in the stack's Ergo helper enforces it
(stack `docs/roles.md`).

- **Private**: only members of a role that lists the channel may join (plus
  opers with `sajoin`, the channel founder and ChanServ access entries).
  A private channel listed on everyone is open to every logged-in account
  (RoleServ makes it `+R`), but not to guests.
- **Public**: anyone can join; the role listing only drives auto-join.
- **Auto-join** (`roles.channels.autojoin` in the stack config file, default
  off): RoleServ joins members to every channel their roles list with
  `autojoin: true`, when they log in and when they gain a role.
  `roles.channels.rejoin: login` (default) joins at every login, even after
  a `/part`; `once` only the first time a role gives the channel (losing and
  regaining the role counts as a first time again).

```yaml
roles:
  channels:
    autojoin: false   # ROLE_CHANNELS_AUTOJOIN
    rejoin: login     # ROLE_CHANNELS_REJOIN: login | once
```

Both keys are hot-reloaded. Channel names are stored the way Ergo
(`casemapping: ascii`) folds them: `#` and 1–63 printable ASCII characters
other than `,`, lower-cased.

### Admin API

| Method & path | Permission | |
|---|---|---|
| `GET /v1/admin/roles/{id}/channels` | `admin.panel` \| `roles.manage` | `{role_id, channels: [{channel, autojoin, private}]}`; `{id}` may be `everyone` (`role_id` is then `everyone`) |
| `PUT /v1/admin/roles/{id}/channels` | `roles.manage` + [hierarchy](#hierarchy) (the role must be below the caller's highest) | `{channels: [{channel, autojoin?}]}` (or a bare list; `autojoin` defaults to `true`) replaces the role's channels (≤ 100) → same as GET; audit `role_channels_updated` (`role_id, name, old, new, added, removed`) |
| `GET /v1/admin/channel-access` | `admin.panel` \| `roles.manage` | `{channels: [{channel, private, roles: [{id, name, autojoin}]}]}`: every channel listed on a role or marked private, by name; roles most senior first, Member as `{id: "everyone", name: "Everyone"}` |
| `PUT /v1/admin/channel-access` | `roles.manage` | `{channels: [{channel, private}]}` (or a bare list) replaces the whole list: the `private: true` entries become the private channels (≤ 500), every other channel is public → same as GET (public channels no role lists are omitted); audit `channel_access_updated` (`private, made_private, made_public`) |

`400 invalid_request` for a bad or duplicate channel name; `404` for an
unknown role. Deleting a role drops its channels.

### Public API

`GET /v1/me/channels` (Bearer) → `{channels: [{channel, private, autojoin,
via: [role names]}]}`: the channels the caller's roles give, `via` most
senior first (`Everyone` for Member), e.g. for "joined because of role X".

### Internal API (RoleServ)

All with `X-Internal-Token: $INTERNAL_API_TOKEN`.

- `GET /internal/v1/irc/channel-access` → `{version, autojoin, rejoin,
  channels: [{channel, private, everyone, accounts}]}`. `accounts` are the
  lower-cased names of the enabled accounts that may join a private channel
  (empty for public ones, and when `everyone` is true). `ETag` = version,
  `If-None-Match` → 304. The version is the [grants
  version](#get-internalv1ircgrants-live-changes) (which also bumps on any
  change to role channels or private channels) plus the two settings, so it
  changes whenever the feed or any account's auto-join list may have.
- `GET /internal/v1/irc/autojoin?account=` → `{account, enabled, rejoin,
  channels, pending}`: `channels` are every channel the account's roles
  (everyone's included) auto-join, `pending` those RoleServ hasn't auto-joined
  it to yet. Disabled accounts get none; unknown ones 404.
- `POST /internal/v1/irc/autojoin` `{account, channels}`: RoleServ joined the
  account to `channels` (kept only if the account still gets them; entries
  for channels it no longer gets are dropped) → the same object as the GET.

## quicvoiced

Read `perms` from the voice token: `voice.create` to create channels (subject
to [`voice_channel_creation`](#channel-creation-settings)),
`voice.manage_any` to moderate any channel, `voice.bypass_locks` to join
locked/full ones. The 1.x `role` claim (`moderator` with `voice.manage_any`)
keeps working.

## Channel creation settings

The network settings still decide the policy; permissions decide who
qualifies:

| Setting | Value | Who may create |
|---|---|---|
| `channel_creation` | `registered` | users with `channel.create` (Member has it, so every account unless an Owner takes it off Member) |
| | `admins` | users with `admin.panel` (the 1.x admins) |
| `voice_channel_creation` | `registered` | users with `voice.create` (Member has it) |
| | `founders` | the IRC channel's founder, if they have `voice.create`; plus anyone with `voice.manage_any` |
| | `admins` | users with `voice.manage_any` |

## Channel lifecycle settings

Two more network settings, also published on `GET /internal/v1/settings`
and `GET /v1/config` and enforced by IRC (Ergo):

| Setting | Default | Effect |
|---|---|---|
| `channel_auto_register` | `true` (`CHANNEL_AUTO_REGISTER`) | a logged-in user who creates a new channel by joining it gets it registered to their account (subject to `channel_creation`) |
| `channel_expiry_days` | `0` (`CHANNEL_EXPIRY_DAYS`) | registered channels with no joins or messages for this many days are unregistered; 0–3650, `0` = never |

Channels of deleted accounts are unregistered through the
[removed-accounts feed](#get-internalv1ircaccountsremoved-deleted-and-disabled-accounts).

## Guest access

`guest_access` (`GUEST_ACCESS`, default `true`) decides whether people can
use IRC without an account. Guests hold no roles, so they can chat but can't
register channels, use voice or get role-based modes, vhosts or oper. When an
admin sets it to `false`, IRC requires SASL login for every connection.

`guest_voice` (`GUEST_VOICE`, default `false`) additionally lets guests join
voice (and so video) under their unverified IRC nick, shown with a guest
badge: `POST /v1/voice/guest-token` mints a voice token with `sub`
`guest:<guest_id>`, `guest: true`, role `speaker` and empty `roles` / `perms`,
so guests can never create, manage or bypass. Nicks that belong to an account
(or are reserved) are refused. It has no effect while `guest_access` is off.

## Migrating from 1.x

Migration `000004_roles` creates `roles` and `user_roles`, seeds the four
built-ins and maps accounts:

- the **earliest-created** `role = 'admin'` account → **Owner**;
- any account named **`thelion`** (case-insensitive), whatever its role → **Owner**;
- every other admin → **Admin**;
- everyone else → nothing stored (Member).

`users.role` stays as a mirror for 1.x clients: auth keeps it `admin` iff the
user holds a role with `admin.panel` (Owner always counts), so `user.role`
in API responses and the `role` claim keep their meaning. The down migration
drops both tables and leaves `users.role` as it was last synced.

The 1.x write paths still work: `POST /v1/admin/users {role}` and
`auth user create --role` take `user | admin | owner` (Admin / Owner role),
and `PATCH /v1/admin/users/{id} {role}` / `auth user set-role` map `admin`
to "add Admin unless already admin-panel", `user` to "drop every role with
`admin.panel`", `owner` to "add Owner", all within the hierarchy.

CLI: `auth role list`, `auth user set-roles <user> [role name or id…]`
(replaces; none = Member only). The CLI acts as the system and bypasses the
hierarchy, but never removes the last Owner.
