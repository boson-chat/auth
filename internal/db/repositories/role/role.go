// Package role is the roles / user_roles repository.
package role

import (
	"context"
	"errors"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Built-in roles (roles.builtin) and their fixed ids.
const (
	BuiltinOwner     = "owner"
	BuiltinAdmin     = "admin"
	BuiltinModerator = "moderator"
	BuiltinMember    = "member"

	OwnerID     = "rol_00000000000000000000000001"
	AdminID     = "rol_00000000000000000000000002"
	ModeratorID = "rol_00000000000000000000000003"
	MemberID    = "rol_00000000000000000000000004"

	OwnerPosition  = 1000
	MemberPosition = 0
)

// ErrNameTaken is returned when the name (or its slug) is already used.
var ErrNameTaken = errors.New("role name taken")

type Role struct {
	ID           string
	Name         string
	Slug         string
	Color        *string
	Position     int
	Builtin      *string
	Permissions  repositories.StringList
	IRCWhoisLine *string `gorm:"column:irc_whois_line"`
	IRCVhost     *string `gorm:"column:irc_vhost"`
	IRCOper      bool    `gorm:"column:irc_oper"`
	Hoist        bool
	Mentionable  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (Role) TableName() string { return "roles" }

// Is reports whether r is the given built-in.
func (r *Role) Is(builtin string) bool { return r.Builtin != nil && *r.Builtin == builtin }

// IsBuiltin reports whether r is any built-in role.
func (r *Role) IsBuiltin() bool { return r.Builtin != nil }

type UserRole struct {
	UserID     string
	RoleID     string
	AssignedBy *string
	AssignedAt time.Time
}

func (UserRole) TableName() string { return "user_roles" }

// Member is one holder of a role.
type Member struct {
	user.User  `gorm:"embedded"`
	AssignedAt *time.Time
	AssignedBy *string
}

// UserRoles is the roles of one user, looked up by username.
type UserRoles struct {
	UserID         string
	Username       string
	UsernameFolded string
	RoleIDs        []string
}

type RoleRepositoryImpl interface {
	// List returns every role, most senior first.
	List(ctx context.Context) ([]*Role, error)
	FindByID(ctx context.Context, id string) (*Role, error)
	// Lock serialises role changes (row lock on the Owner role; call inside WithTx).
	Lock(ctx context.Context) error
	Create(ctx context.Context, r *Role) error
	Save(ctx context.Context, r *Role) error
	Delete(ctx context.Context, id string) error
	// MemberCounts returns stored holders per role id (Member is not stored).
	MemberCounts(ctx context.Context) (map[string]int64, error)
	CountUsers(ctx context.Context) (int64, error)
	// ForUser returns the user's stored roles plus Member, most senior first.
	ForUser(ctx context.Context, userID string) ([]*Role, error)
	// RoleIDsForUsers returns the stored role ids of each user.
	RoleIDsForUsers(ctx context.Context, userIDs []string) (map[string][]string, error)
	UserIDsWithRole(ctx context.Context, roleID string) ([]string, error)
	CountHolders(ctx context.Context, roleID string) (int64, error)
	AddUserRoles(ctx context.Context, userID string, roleIDs []string, by *string, at time.Time) error
	RemoveUserRoles(ctx context.Context, userID string, roleIDs []string) error
	// Members lists holders by user id after afterUserID; for Member every user.
	Members(ctx context.Context, roleID string, member bool, afterUserID string, limit int) ([]*Member, error)
	// RolesByUsernames maps folded usernames to their users' stored role ids.
	RolesByUsernames(ctx context.Context, folded []string) ([]*UserRoles, error)
	// SyncLegacyRole sets users.role to 'admin' iff the user holds a role with
	// admin.panel (Owner always counts). nil userIDs = every user.
	SyncLegacyRole(ctx context.Context, userIDs []string) error
	// GrantsVersion is the IRC grants counter (migration 5), bumped by
	// triggers on every change to roles, user_roles and users' names or
	// disabled state.
	GrantsVersion(ctx context.Context) (int64, error)
	// EnabledUsersWithRoles returns enabled users with their stored role ids
	// (most senior first), ordered by folded username. With anyOf set, only
	// users holding at least one of those roles; with nil, every enabled user.
	EnabledUsersWithRoles(ctx context.Context, anyOf []string) ([]*UserRoles, error)
}

type RoleRepository struct {
	db *db.DB
}

func NewRoleRepository(d *db.DB) RoleRepositoryImpl {
	return &RoleRepository{db: d}
}

const order = "position DESC, created_at ASC, id ASC"

func (r *RoleRepository) List(ctx context.Context) ([]*Role, error) {
	var out []*Role
	err := r.db.Conn(ctx).Order(order).Find(&out).Error
	return out, err
}

func (r *RoleRepository) FindByID(ctx context.Context, id string) (*Role, error) {
	if id == "" {
		return nil, repositories.ErrNotFound
	}
	var out Role
	if err := r.db.Conn(ctx).Where("id = ?", id).First(&out).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &out, nil
}

func (r *RoleRepository) Lock(ctx context.Context) error {
	var out Role
	return r.db.Conn(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", OwnerID).First(&out).Error
}

func nameErr(err error) error {
	switch repositories.UniqueViolation(err) {
	case "":
		return err
	case "roles_name_key", "roles_slug_key":
		return ErrNameTaken
	default:
		return err
	}
}

func (r *RoleRepository) Create(ctx context.Context, role *Role) error {
	return nameErr(r.db.Conn(ctx).Create(role).Error)
}

// Save writes every column as given (UpdateColumns: GORM must not replace
// updated_at, which If-Match compares against what the caller saw).
func (r *RoleRepository) Save(ctx context.Context, role *Role) error {
	res := r.db.Conn(ctx).Model(&Role{}).Where("id = ?", role.ID).Select("*").Omit("id", "created_at").UpdateColumns(role)
	if res.Error != nil {
		return nameErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return nil
}

func (r *RoleRepository) Delete(ctx context.Context, id string) error {
	res := r.db.Conn(ctx).Where("id = ?", id).Delete(&Role{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return nil
}

func (r *RoleRepository) MemberCounts(ctx context.Context) (map[string]int64, error) {
	var rows []struct {
		RoleID string
		N      int64
	}
	if err := r.db.Conn(ctx).Model(&UserRole{}).Select("role_id, count(*) AS n").Group("role_id").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, row := range rows {
		out[row.RoleID] = row.N
	}
	return out, nil
}

func (r *RoleRepository) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.Conn(ctx).Model(&user.User{}).Count(&n).Error
	return n, err
}

func (r *RoleRepository) ForUser(ctx context.Context, userID string) ([]*Role, error) {
	var out []*Role
	err := r.db.Conn(ctx).
		Where("builtin = ? OR id IN (?)", BuiltinMember,
			r.db.Conn(ctx).Model(&UserRole{}).Select("role_id").Where("user_id = ?", userID)).
		Order(order).Find(&out).Error
	return out, err
}

func (r *RoleRepository) RoleIDsForUsers(ctx context.Context, userIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	var rows []UserRole
	err := r.db.Conn(ctx).Model(&UserRole{}).
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id IN ?", userIDs).
		Order("roles.position DESC, roles.created_at ASC, roles.id ASC").
		Select("user_roles.*").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.UserID] = append(out[row.UserID], row.RoleID)
	}
	return out, nil
}

func (r *RoleRepository) UserIDsWithRole(ctx context.Context, roleID string) ([]string, error) {
	var out []string
	err := r.db.Conn(ctx).Model(&UserRole{}).Where("role_id = ?", roleID).Order("user_id").Pluck("user_id", &out).Error
	return out, err
}

func (r *RoleRepository) CountHolders(ctx context.Context, roleID string) (int64, error) {
	var n int64
	err := r.db.Conn(ctx).Model(&UserRole{}).Where("role_id = ?", roleID).Count(&n).Error
	return n, err
}

func (r *RoleRepository) AddUserRoles(ctx context.Context, userID string, roleIDs []string, by *string, at time.Time) error {
	if len(roleIDs) == 0 {
		return nil
	}
	rows := make([]UserRole, 0, len(roleIDs))
	for _, id := range roleIDs {
		rows = append(rows, UserRole{UserID: userID, RoleID: id, AssignedBy: by, AssignedAt: at})
	}
	return r.db.Conn(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
}

func (r *RoleRepository) RemoveUserRoles(ctx context.Context, userID string, roleIDs []string) error {
	if len(roleIDs) == 0 {
		return nil
	}
	return r.db.Conn(ctx).Where("user_id = ? AND role_id IN ?", userID, roleIDs).Delete(&UserRole{}).Error
}

func (r *RoleRepository) Members(ctx context.Context, roleID string, member bool, afterUserID string, limit int) ([]*Member, error) {
	var out []*Member
	var q *gorm.DB
	if member {
		q = r.db.Conn(ctx).Table("users").Select("users.*, NULL::timestamptz AS assigned_at, NULL::text AS assigned_by")
	} else {
		q = r.db.Conn(ctx).Table("users").
			Joins("JOIN user_roles ur ON ur.user_id = users.id AND ur.role_id = ?", roleID).
			Select("users.*, ur.assigned_at, ur.assigned_by")
	}
	if afterUserID != "" {
		q = q.Where("users.id > ?", afterUserID)
	}
	err := q.Order("users.id ASC").Limit(limit).Scan(&out).Error
	return out, err
}

func (r *RoleRepository) RolesByUsernames(ctx context.Context, folded []string) ([]*UserRoles, error) {
	if len(folded) == 0 {
		return nil, nil
	}
	var users []*user.User
	if err := r.db.Conn(ctx).Where("username_folded IN ?", folded).Find(&users).Error; err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	byUser, err := r.RoleIDsForUsers(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]*UserRoles, 0, len(users))
	for _, u := range users {
		out = append(out, &UserRoles{UserID: u.ID, Username: u.Username, UsernameFolded: u.UsernameFolded, RoleIDs: byUser[u.ID]})
	}
	return out, nil
}

// legacyAdmin is true for a users row u that holds Owner or any role with
// admin.panel (Member counts for everyone).
const legacyAdmin = `(EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
	WHERE ur.user_id = users.id AND (r.builtin = 'owner' OR r.permissions @> '["admin.panel"]'))
 OR EXISTS (SELECT 1 FROM roles r WHERE r.builtin = 'member' AND r.permissions @> '["admin.panel"]'))`

func (r *RoleRepository) SyncLegacyRole(ctx context.Context, userIDs []string) error {
	if userIDs != nil && len(userIDs) == 0 {
		return nil
	}
	q := r.db.Conn(ctx).Model(&user.User{}).
		Where("role <> (CASE WHEN " + legacyAdmin + " THEN 'admin' ELSE 'user' END)")
	if userIDs != nil {
		q = q.Where("id IN ?", userIDs)
	}
	return q.UpdateColumn("role", gorm.Expr("CASE WHEN "+legacyAdmin+" THEN 'admin' ELSE 'user' END")).Error
}

func (r *RoleRepository) GrantsVersion(ctx context.Context) (int64, error) {
	var v int64
	err := r.db.Conn(ctx).Raw(`SELECT version FROM irc_grants_version`).Scan(&v).Error
	return v, err
}

func (r *RoleRepository) EnabledUsersWithRoles(ctx context.Context, anyOf []string) ([]*UserRoles, error) {
	if anyOf != nil && len(anyOf) == 0 {
		return nil, nil
	}
	q := r.db.Conn(ctx).Model(&user.User{}).Where("disabled_at IS NULL")
	if anyOf != nil {
		q = q.Where("id IN (?)", r.db.Conn(ctx).Model(&UserRole{}).Select("user_id").Where("role_id IN ?", anyOf))
	}
	var users []*user.User
	if err := q.Order("username_folded ASC, id ASC").Find(&users).Error; err != nil {
		return nil, err
	}
	out := make([]*UserRoles, 0, len(users))
	const batch = 1000
	for i := 0; i < len(users); i += batch {
		chunk := users[i:min(i+batch, len(users))]
		ids := make([]string, 0, len(chunk))
		for _, u := range chunk {
			ids = append(ids, u.ID)
		}
		byUser, err := r.RoleIDsForUsers(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, u := range chunk {
			out = append(out, &UserRoles{UserID: u.ID, Username: u.Username, UsernameFolded: u.UsernameFolded, RoleIDs: byUser[u.ID]})
		}
	}
	return out, nil
}
