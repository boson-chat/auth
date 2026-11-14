-- Network roles (IRC-native): each maps to an Ergo oper class and an optional
-- vhost. Member is implicit for every user and never stored in user_roles.
CREATE TABLE roles (
    id             text PRIMARY KEY,
    name           citext NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 32),
    -- Lower-case name with spaces as '-': the Ergo oper class name.
    slug           text NOT NULL UNIQUE,
    color          text CHECK (color ~ '^#[0-9a-f]{6}$'),
    -- Higher = more senior. Owner 1000, Member 0, everything else 1..999.
    position       integer NOT NULL CHECK (position BETWEEN 0 AND 1000),
    builtin        text UNIQUE CHECK (builtin IN ('owner', 'admin', 'moderator', 'member')),
    permissions    jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(permissions) = 'array'),
    irc_whois_line text,             -- NULL = "is a(n) <name>"
    irc_vhost      text,             -- template, e.g. {username}.staff.boson.chat
    irc_oper       boolean NOT NULL DEFAULT false, -- explicit; any irc.* permission also makes an oper
    hoist          boolean NOT NULL DEFAULT false,
    mentionable    boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_id     text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id     text NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    assigned_by text REFERENCES users (id) ON DELETE SET NULL,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_roles_role_id_idx ON user_roles (role_id, user_id);

-- Built-ins have fixed ids so clients and other services can rely on them.
INSERT INTO roles (id, name, slug, color, position, builtin, permissions, hoist) VALUES
('rol_00000000000000000000000001', 'Owner', 'owner', '#f1c40f', 1000, 'owner',
 '["admin.panel","users.view","users.manage","users.moderate","invites.manage","settings.manage","sso.manage",
   "services.view","services.manage","audit.view","roles.manage","roles.owner","directory.manage",
   "channel.create","voice.create","voice.manage_any","voice.bypass_locks",
   "irc.kill","irc.ban","irc.nofakelag","irc.relaymsg","irc.vhosts","irc.sajoin","irc.samode","irc.snomasks",
   "irc.roleplay","irc.rehash","irc.accreg","irc.chanreg","irc.history","irc.defcon","irc.massmessage","irc.metadata"]', true),
('rol_00000000000000000000000002', 'Admin', 'admin', '#e74c3c', 900, 'admin',
 '["admin.panel","users.view","users.manage","users.moderate","invites.manage","settings.manage","sso.manage",
   "services.view","services.manage","audit.view","roles.manage","directory.manage",
   "channel.create","voice.create","voice.manage_any","voice.bypass_locks",
   "irc.kill","irc.ban","irc.nofakelag","irc.relaymsg","irc.vhosts","irc.sajoin","irc.samode","irc.snomasks",
   "irc.roleplay","irc.rehash","irc.accreg","irc.chanreg","irc.history","irc.defcon","irc.massmessage","irc.metadata"]', true),
('rol_00000000000000000000000003', 'Moderator', 'moderator', '#3498db', 500, 'moderator',
 '["users.view","users.moderate","invites.manage","audit.view",
   "channel.create","voice.create","voice.manage_any","voice.bypass_locks",
   "irc.kill","irc.ban","irc.nofakelag","irc.vhosts","irc.sajoin","irc.samode","irc.history"]', true),
('rol_00000000000000000000000004', 'Member', 'member', NULL, 0, 'member',
 '["channel.create","voice.create"]', false);

-- Existing admins: the earliest-created one (and thelion) become Owner, the
-- rest Admin. users.role stays as a compatibility mirror ('admin' iff the
-- user holds a role with admin.panel).
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, 'rol_00000000000000000000000001' FROM users u
WHERE u.id = (SELECT id FROM users WHERE role = 'admin' ORDER BY created_at, id LIMIT 1)
   OR u.username = 'thelion' -- citext: case-insensitive
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, 'rol_00000000000000000000000002' FROM users u
WHERE u.role = 'admin'
  AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.role_id = 'rol_00000000000000000000000001')
ON CONFLICT DO NOTHING;

UPDATE users SET role = 'admin'
WHERE role <> 'admin' AND id IN (SELECT user_id FROM user_roles WHERE role_id = 'rol_00000000000000000000000001');
