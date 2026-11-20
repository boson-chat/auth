-- Friends, blocks, privacy settings and private 1:1 calls (docs/friends-calls.md).

-- A friendship is two rows, one each way, so each side keeps its own
-- "can call me anytime" switch for the other.
CREATE TABLE friendships (
    user_id          text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    friend_id        text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- friend_id may ring user_id through Do not disturb and "Nobody".
    can_call_anytime boolean NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, friend_id),
    CHECK (user_id <> friend_id)
);
CREATE INDEX friendships_friend_idx ON friendships (friend_id);

CREATE TABLE friend_requests (
    from_id    text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    to_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Hidden: the recipient had blocked the sender. The sender sees it as
    -- sent and waiting; the recipient never sees it.
    hidden     boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (from_id, to_id),
    CHECK (from_id <> to_id)
);
CREATE INDEX friend_requests_to_idx ON friend_requests (to_id);

CREATE TABLE user_blocks (
    user_id    text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    blocked_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, blocked_id),
    CHECK (user_id <> blocked_id)
);
CREATE INDEX user_blocks_blocked_idx ON user_blocks (blocked_id);

-- No row = the defaults.
CREATE TABLE privacy_settings (
    user_id         text PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    calls           text NOT NULL DEFAULT 'friends' CHECK (calls IN ('nobody', 'friends', 'everyone')),
    do_not_disturb  boolean NOT NULL DEFAULT false,
    friend_requests text NOT NULL DEFAULT 'everyone' CHECK (friend_requests IN ('nobody', 'servers', 'everyone')),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE calls (
    id          text PRIMARY KEY, -- cal_<ULID>
    caller_id   text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    callee_id   text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    video       boolean NOT NULL DEFAULT false,
    -- ringing → answered → ended; ringing → declined | missed; unavailable
    -- never rang (the callee had blocked the caller).
    state       text NOT NULL CHECK (state IN ('ringing', 'answered', 'declined', 'missed', 'ended', 'unavailable')),
    -- The callee has seen this missed call.
    missed_seen boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    answered_at timestamptz,
    ended_at    timestamptz
);
CREATE INDEX calls_live_idx ON calls (state, created_at) WHERE state IN ('ringing', 'answered');
CREATE INDEX calls_missed_idx ON calls (callee_id, created_at DESC) WHERE state = 'missed' AND NOT missed_seen;
CREATE INDEX calls_caller_idx ON calls (caller_id, created_at DESC);
