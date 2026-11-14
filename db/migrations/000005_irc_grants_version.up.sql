-- A counter for GET /internal/v1/irc/grants: it changes whenever any user's
-- IRC grants (oper class, WHOIS line, vhost) may have changed, i.e. on any
-- write to roles or user_roles, on user creation/deletion, and when a user
-- is renamed, disabled or enabled. Bumped by deferred triggers at commit, so
-- the counter row is always the last lock a transaction takes (no lock-order
-- inversions), and at most once per transaction.
CREATE TABLE irc_grants_version (
    id      boolean PRIMARY KEY DEFAULT true CHECK (id),
    version bigint  NOT NULL,
    -- The transaction that last bumped version (one bump per transaction).
    bumped_by xid8
);
INSERT INTO irc_grants_version (id, version) VALUES (true, 1);

CREATE FUNCTION bump_irc_grants_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE irc_grants_version SET version = version + 1, bumped_by = pg_current_xact_id()
    WHERE bumped_by IS DISTINCT FROM pg_current_xact_id();
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER roles_irc_grants_version
    AFTER INSERT OR UPDATE OR DELETE ON roles
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bump_irc_grants_version();

CREATE CONSTRAINT TRIGGER user_roles_irc_grants_version
    AFTER INSERT OR UPDATE OR DELETE ON user_roles
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bump_irc_grants_version();

CREATE CONSTRAINT TRIGGER users_irc_grants_version_insert_delete
    AFTER INSERT OR DELETE ON users
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bump_irc_grants_version();

CREATE CONSTRAINT TRIGGER users_irc_grants_version_update
    AFTER UPDATE OF username, disabled_at ON users
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (OLD.username IS DISTINCT FROM NEW.username OR OLD.disabled_at IS DISTINCT FROM NEW.disabled_at)
    EXECUTE FUNCTION bump_irc_grants_version();
