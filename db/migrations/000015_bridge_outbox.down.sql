DROP TRIGGER IF EXISTS nickserv_accounts_bridge_outbox ON nickserv_accounts;
DROP TRIGGER IF EXISTS users_bridge_outbox_update ON users;
DROP TRIGGER IF EXISTS users_bridge_outbox_insert_delete ON users;
DROP FUNCTION IF EXISTS bridge_outbox_nickserv_changed();
DROP FUNCTION IF EXISTS bridge_outbox_user_changed();
DROP TABLE IF EXISTS bridge_outbox;
DROP TABLE IF EXISTS bridge_state;
