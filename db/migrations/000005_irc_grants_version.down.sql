DROP TRIGGER IF EXISTS users_irc_grants_version_update ON users;
DROP TRIGGER IF EXISTS users_irc_grants_version_insert_delete ON users;
DROP TRIGGER IF EXISTS user_roles_irc_grants_version ON user_roles;
DROP TRIGGER IF EXISTS roles_irc_grants_version ON roles;
DROP FUNCTION IF EXISTS bump_irc_grants_version();
DROP TABLE IF EXISTS irc_grants_version;
