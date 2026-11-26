-- evrd bridge accounts (BRIDGE_API_URL, docs/bridge.md).
--
-- Triggers on users (and nickserv_accounts) queue one bridge_outbox row
-- per change, in the changing transaction, so every path (API, CLI, SQL)
-- reaches the bridge and a bridge outage loses nothing. A worker pushes the
-- user's state at the time it runs and deletes the rows; failures are
-- retried with backoff. No password ever goes in here.

-- A single row. enabled is set by auth at startup (BRIDGE_API_URL and
-- BRIDGE_TOKEN set); while it's false the triggers queue nothing.
CREATE TABLE bridge_state (
    id                    boolean PRIMARY KEY DEFAULT true CHECK (id),
    enabled               boolean NOT NULL DEFAULT false,
    -- One replica runs a full sync at a time.
    reconcile_lease_until timestamptz,
    last_reconcile_at     timestamptz,
    last_reconcile_error  text
);
INSERT INTO bridge_state (id) VALUES (true);

CREATE TABLE bridge_outbox (
    id              bigserial   PRIMARY KEY,
    user_id         text        NOT NULL, -- no foreign key: the user may be gone
    -- The username before the change (an insert: the new one). If the
    -- user no longer has it (renamed, deleted), its bridge account goes.
    username        text        NOT NULL,
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    claimed_until   timestamptz,          -- a worker is pushing it
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX bridge_outbox_next_attempt_at_idx ON bridge_outbox (next_attempt_at);
CREATE INDEX bridge_outbox_user_id_idx ON bridge_outbox (user_id);

CREATE FUNCTION bridge_outbox_user_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT coalesce((SELECT enabled FROM bridge_state WHERE id), false) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        INSERT INTO bridge_outbox (user_id, username) VALUES (NEW.id, NEW.username);
    ELSE
        INSERT INTO bridge_outbox (user_id, username) VALUES (OLD.id, OLD.username);
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER users_bridge_outbox_insert_delete
    AFTER INSERT OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION bridge_outbox_user_changed();

CREATE TRIGGER users_bridge_outbox_update
    AFTER UPDATE OF username, email, display_name, disabled_at ON users
    FOR EACH ROW
    WHEN (OLD.username IS DISTINCT FROM NEW.username OR OLD.email IS DISTINCT FROM NEW.email
          OR OLD.display_name IS DISTINCT FROM NEW.display_name
          OR (OLD.disabled_at IS NULL) <> (NEW.disabled_at IS NULL))
    EXECUTE FUNCTION bridge_outbox_user_changed();

-- A NickServ link changes the nick and whether auth sends a login.
CREATE FUNCTION bridge_outbox_nickserv_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    uid text;
BEGIN
    IF NOT coalesce((SELECT enabled FROM bridge_state WHERE id), false) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN
        uid := OLD.user_id;
    ELSE
        uid := NEW.user_id;
    END IF;
    -- A user being deleted has no row any more; its own trigger queued it.
    INSERT INTO bridge_outbox (user_id, username) SELECT u.id, u.username FROM users u WHERE u.id = uid;
    RETURN NULL;
END
$$;

CREATE TRIGGER nickserv_accounts_bridge_outbox
    AFTER INSERT OR DELETE OR UPDATE OF account ON nickserv_accounts
    FOR EACH ROW EXECUTE FUNCTION bridge_outbox_nickserv_changed();
