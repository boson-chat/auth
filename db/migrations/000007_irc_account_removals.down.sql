DROP TRIGGER IF EXISTS users_irc_account_removed_disable ON users;
DROP TRIGGER IF EXISTS users_irc_account_removed_delete ON users;
DROP FUNCTION IF EXISTS record_irc_account_removal();
DROP TABLE IF EXISTS irc_account_removals;
