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
- [Channel creation settings](#channel-creation-settings) · [Migrating from 1.x](#migrating-from-1x)

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
| `PATCH /v1/admin/roles/{id}` | any subset of the create fields → `{role}`. `null` clears `color`, `irc.whois_line`, `irc.vhost` |
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
`409 builtin_role`, `409 last_owner`.

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
