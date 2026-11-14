-- users.role is kept in sync while roles exist, so dropping them leaves
-- every admin-panel user as role 'admin'.
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
