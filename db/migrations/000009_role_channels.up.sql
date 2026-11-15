-- Role channels (Discord-style channel access): admins attach IRC channels
-- to roles (Member = "everyone"), and mark channels private. RoleServ (stack
-- Ergo helper) keeps private channels +i with an account invite exception
-- per allowed account, and auto-joins members (roles.channels.autojoin in
-- the stack config file).
--
-- Channel names are stored casefolded the way Ergo (casemapping: ascii)
-- folds them: ASCII lower case.
CREATE TABLE role_channels (
    role_id    text        NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    channel    text        NOT NULL CHECK (channel ~ '^#[!-~]{1,63}$' AND strpos(channel, ',') = 0 AND channel = lower(channel)),
    autojoin   boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, channel)
);
CREATE INDEX role_channels_channel_idx ON role_channels (channel);

-- Channels marked private: joinable only by members of a role that lists
-- them (plus opers with sajoin, the founder and ChanServ access entries).
-- A channel is public unless it has a row here with private = true.
CREATE TABLE channel_access (
    channel    text        PRIMARY KEY CHECK (channel ~ '^#[!-~]{1,63}$' AND strpos(channel, ',') = 0 AND channel = lower(channel)),
    private    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- rejoin: once: the channels RoleServ already auto-joined each account to,
-- so a /part sticks. Rows for channels the account no longer gets are
-- pruned, so losing and regaining a role auto-joins again.
CREATE TABLE irc_autojoined (
    user_id   text        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    channel   text        NOT NULL,
    joined_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, channel)
);

-- The IRC grants version (migration 5) also covers channel access: RoleServ
-- polls GET /internal/v1/irc/channel-access with it.
CREATE CONSTRAINT TRIGGER role_channels_irc_grants_version
    AFTER INSERT OR UPDATE OR DELETE ON role_channels
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bump_irc_grants_version();

CREATE CONSTRAINT TRIGGER channel_access_irc_grants_version
    AFTER INSERT OR UPDATE OR DELETE ON channel_access
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bump_irc_grants_version();
