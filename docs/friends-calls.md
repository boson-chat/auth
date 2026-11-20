# Friends and private calls

Friends, blocks, privacy settings and private 1:1 voice/video calls for the
boson app. The auth service owns all of it: the data lives with the account,
the policy is decided here, and the other services trust it.

## Design in short

- **Data**: `friendships` (two rows per friendship, each with that side's
  "can call me anytime" switch), `friend_requests`, `user_blocks`,
  `privacy_settings` and `calls` (migration 12).
- **Policy** is decided on the server, from the callee's settings and their
  view of the caller (`internal/services/social/policy.go`). A client can't
  make anyone's app ring by lying.
- **Ringing** reaches open apps through a **long-poll event feed**,
  `GET /v1/events`, on this service. The app already sends every auth
  request through its API proxy, so this needed no new service, port,
  WebSocket or proxy rule, and it works the same on desktop, iOS and
  Android. A poll is held open for up to 25 s and answered as soon as
  something happens. Calls ring **only while the app is open**: no push,
  no CallKit; a call to someone whose app isn't polling is a missed call
  they see the next time they open it.
- **The call itself** is a quicvoice private call room `call:<call id>`
  (and the quicvideo room with the same id). quicvoiced lets a session in
  only with a voice token whose `rooms` claim names that room; this service
  mints those only for the call's two people once the call is answered
  (`POST /v1/voice/token` and the guest endpoint refuse `call:` rooms). The
  rooms are unlisted and gone when empty (quicvoice `docs/ROOMS.md`).
- **One process**: the event queues and "is their app open" are in memory,
  so this assumes a single auth replica (the stack runs one). Calls
  themselves are in Postgres, so a restart loses no state; apps re-sync from
  the snapshot their next poll gets.

## Who may call whom

Decided for each call from the **callee's** side:

| Situation | Result |
|---|---|
| The caller blocked the callee | refused, `you_blocked` |
| The callee blocked the caller | looks like an unanswered call to the caller (`unavailable`); the callee sees nothing, not even a missed call. The caller isn't told. |
| "Who can call me" = Nobody, and the caller isn't a friend the callee lets call anytime | refused, `calls_off` ("X isn't taking calls") |
| = Friends (the default) and not friends | refused, `friends_only` ("X only takes calls from friends") |
| = Everyone | anyone not blocked |
| Do not disturb, and not a friend who may call anytime | never rings; a missed call for the callee; `unavailable` for the caller |
| No app open (not polling) | likewise a missed call; `unavailable` for the caller |
| Otherwise | rings every open app of the callee for up to 45 s |

`GET /v1/users/{username}/relation` reports the same decision beforehand as
`call` (`ok` or a refusal reason) so the app can explain before anyone
presses Call. Blocks and Do not disturb read `ok` there.

Friend requests, from the recipient's side: the sender blocked them →
`you_blocked`; the recipient blocked the sender → stored **hidden** (the
sender sees "request sent", the recipient never sees it); the recipient had
already asked the sender → accepted at once; "Who can send me friend
requests" = Nobody → `requests_off`; = People in my servers → only someone
who shares an IRC channel with them right now (asked from Ergo's API with
`ERGO_API_URL` / `ERGO_API_TOKEN`; without those nobody passes),
else `requests_servers_only`; = Everyone (default) → sent.

Blocking removes the friendship and requests both ways and quietly ends a
call the blocked person is ringing with.

## Call states

`ringing` → `answered` → `ended`; `ringing` → `declined` (the caller shows
"busy") or `missed` (45 s with no answer, or the caller cancelled);
`unavailable` = never rang (blocked). Missed calls count until the callee
marks them seen. Answered calls nobody ended are closed after 12 h; finished
calls are deleted after 30 days.

## Event feed

`GET /v1/events?cursor=<cursor>` (bearer). Answer:

```json
{"cursor": "9f3a01c2.17", "reset": false, "events": [
  {"seq": 17, "type": "call.ring", "data": {"id": "cal_…", "room": "call:cal_…", "video": true,
   "state": "ringing", "direction": "incoming", "peer": {"user_id": "usr_…", "username": "kestrel", "display_name": ""},
   "created_at": "…", "expires_at": "…"}}]}
```

- The first poll (no cursor), or one with a cursor from before a restart or
  too old, comes back at once with `reset: true` and a `snapshot`:
  `{ringing: [call], missed: n, pending_requests: n}`. The app then reloads
  its friends list.
- Otherwise it returns as soon as there are events after the cursor, or
  empty after 25 s (`EVENTS_POLL_WAIT`). Poll again with the new cursor.
- Types: `call.ring` (a call for you, a call object), `call.update` (a
  call's new state, to both people and all their apps: answered elsewhere,
  declined, missed, ended), `friends` (lists changed: refetch), `missed`
  (`{count}`).
- An app counts as open while a poll waits or for 35 s after one ended.

## API

All bearer-authenticated, JSON. People are named by `username` (or
`user_id`) in bodies and by user id in paths.

| Method & path | |
|---|---|
| `GET /v1/friends` | `{friends, incoming, outgoing, blocked}`: lists of `{user_id, username, display_name, can_call_anytime, since}` (`can_call_anytime`: my switch for that friend) |
| `POST /v1/friends/requests` | `{username}` → the relation (below). `403 you_blocked\|requests_off\|requests_servers_only`, `404 user_not_found`, `400` self |
| `POST /v1/friends/requests/{user_id}/accept` | → 204; `404` without a request from them |
| `DELETE /v1/friends/requests/{user_id}` | decline theirs or cancel mine → 204 |
| `PATCH /v1/friends/{user_id}` | `{can_call_anytime}` → 204 |
| `DELETE /v1/friends/{user_id}` | unfriend (both ways) → 204 |
| `POST /v1/blocks` | `{username}` → 204 |
| `DELETE /v1/blocks/{user_id}` | → 204 |
| `GET /v1/users/{username}/relation` | `{user, relation: friend\|incoming\|outgoing\|blocked\|none, can_call_anytime, call: ok\|friends_only\|calls_off\|you_blocked}` |
| `GET`, `PATCH /v1/me/privacy` | `{calls: nobody\|friends\|everyone, do_not_disturb, friend_requests: nobody\|servers\|everyone}` (defaults friends / false / everyone) |
| `POST /v1/calls` | `{username, video}` → 201 `{call}` with `state` `ringing` or `unavailable`; `403 friends_only\|calls_off\|you_blocked`. A caller's earlier call still ringing stops. |
| `POST /v1/calls/{id}/accept` | callee → `{call, voice: {token, expires_in, room}}` |
| `POST /v1/calls/{id}/decline` | callee → `{call}` |
| `POST /v1/calls/{id}/cancel` | caller, while ringing → `{call}` (a missed call for the callee) |
| `POST /v1/calls/{id}/end` | either, hang up (cancels or declines while ringing) → `{call}` |
| `POST /v1/calls/{id}/token` | either, while answered → `{voice}` (rejoin) |
| `GET /v1/calls/missed` | `{count, calls}` unseen missed calls, newest first (≤ 50) |
| `POST /v1/calls/missed/seen` | → 204 |
| `GET /v1/events?cursor=` | the event feed (above) |

`409 call_over` when a call is no longer in the state the action needs.
Friend requests, blocks and calls share a per-account rate limit (burst 30,
30 a minute).

Internal listener: `GET /internal/v1/calls/check?from=<user id>&to=<user id>`
(`X-Internal-Token`) → `{result: ok | friends_only | calls_off | you_blocked |
unavailable}`: may `from` ring `to` right now (`unavailable` = blocked or Do
not disturb).

## Config

| Env | Default | |
|---|---|---|
| `ERGO_API_URL` | — | Ergo's HTTP API (`http://ergo:8089` in the stack), for "People in my servers" |
| `ERGO_API_TOKEN` | — | one of Ergo's `api.bearer-tokens` |
| `EVENTS_POLL_WAIT` | `25s` | how long an event poll waits; keep it under 30 s (the app's proxy timeout) |
