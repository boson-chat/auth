-- Append-only feed for GET /internal/v1/irc/accounts/removed: one row per
-- account deletion or disable, written by triggers on users so every path
-- (admin API, CLI, SQL) is covered. username is the name at that moment;
-- user_id has no foreign key (the user may be gone).
--
-- Readers page by (txid, id) and only read rows from transactions older than
-- every in-flight one (txid < pg_snapshot_xmin(pg_current_snapshot())), so a
-- slow transaction's row can never commit "behind" a cursor already handed out.
CREATE TABLE irc_account_removals (
    id              bigserial   PRIMARY KEY,
    txid            xid8        NOT NULL DEFAULT pg_current_xact_id(),
    user_id         text        NOT NULL,
    username        text        NOT NULL,
    username_folded text        NOT NULL,
    reason          text        NOT NULL CHECK (reason IN ('deleted', 'disabled')),
    at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX irc_account_removals_txid_id_idx ON irc_account_removals (txid, id);
CREATE INDEX irc_account_removals_at_idx ON irc_account_removals (at);

-- TG_ARGV[0] is the reason.
CREATE FUNCTION record_irc_account_removal() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    u users;
BEGIN
    IF TG_OP = 'DELETE' THEN
        u := OLD;
    ELSE
        u := NEW;
    END IF;
    INSERT INTO irc_account_removals (user_id, username, username_folded, reason)
    VALUES (u.id, u.username, u.username_folded, TG_ARGV[0]);
    RETURN NULL;
END
$$;

CREATE TRIGGER users_irc_account_removed_delete
    AFTER DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION record_irc_account_removal('deleted');

CREATE TRIGGER users_irc_account_removed_disable
    AFTER UPDATE OF disabled_at ON users
    FOR EACH ROW
    WHEN (OLD.disabled_at IS NULL AND NEW.disabled_at IS NOT NULL)
    EXECUTE FUNCTION record_irc_account_removal('disabled');
