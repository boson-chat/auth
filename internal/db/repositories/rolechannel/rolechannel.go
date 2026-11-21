// Package rolechannel is the role_channels / channel_access /
// irc_autojoined repository (migration 9).
package rolechannel

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	"gorm.io/gorm/clause"
)

// RoleChannel is a channel attached to a role.
type RoleChannel struct {
	RoleID    string
	Channel   string
	Autojoin  bool
	CreatedAt time.Time
}

func (RoleChannel) TableName() string { return "role_channels" }

// Access is a channel_access row (only private channels are stored).
type Access struct {
	Channel   string
	Private   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Access) TableName() string { return "channel_access" }

// Autojoined records that RoleServ auto-joined a user to a channel.
type Autojoined struct {
	UserID   string
	Channel  string
	JoinedAt time.Time
}

func (Autojoined) TableName() string { return "irc_autojoined" }

// Holder is an enabled user holding a role.
type Holder struct {
	RoleID         string
	UserID         string
	Username       string
	UsernameFolded string
}

type RoleChannelRepositoryImpl interface {
	// All returns every role channel by role id, then channel.
	All(ctx context.Context) ([]*RoleChannel, error)
	// ForRoles returns the channels of the given roles, by channel.
	ForRoles(ctx context.Context, roleIDs []string) ([]*RoleChannel, error)
	// ReplaceForRole makes list the role's channels.
	ReplaceForRole(ctx context.Context, roleID string, list []*RoleChannel) error
	// Private returns the private channels, by channel.
	Private(ctx context.Context) ([]*Access, error)
	// ReplacePrivate makes channels the private ones.
	ReplacePrivate(ctx context.Context, channels []string, at time.Time) error
	// EnabledHolders returns the enabled users holding any of roleIDs.
	EnabledHolders(ctx context.Context, roleIDs []string) ([]*Holder, error)
	// Autojoined returns the channels userID was auto-joined to.
	Autojoined(ctx context.Context, userID string) ([]string, error)
	// RecordAutojoined adds channels to userID's auto-joined set and drops
	// the entries not in keep.
	RecordAutojoined(ctx context.Context, userID string, channels, keep []string, at time.Time) error
	// EarliestOwner is the username of the enabled user who has held the
	// built-in Owner role longest ("" when there is none).
	EarliestOwner(ctx context.Context) (string, error)
}

type RoleChannelRepository struct {
	db *db.DB
}

func NewRoleChannelRepository(d *db.DB) RoleChannelRepositoryImpl {
	return &RoleChannelRepository{db: d}
}

func (r *RoleChannelRepository) All(ctx context.Context) ([]*RoleChannel, error) {
	var out []*RoleChannel
	err := r.db.Conn(ctx).Order("role_id, channel").Find(&out).Error
	return out, err
}

func (r *RoleChannelRepository) ForRoles(ctx context.Context, roleIDs []string) ([]*RoleChannel, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	var out []*RoleChannel
	err := r.db.Conn(ctx).Where("role_id IN ?", roleIDs).Order("channel, role_id").Find(&out).Error
	return out, err
}

func (r *RoleChannelRepository) ReplaceForRole(ctx context.Context, roleID string, list []*RoleChannel) error {
	keep := make([]string, 0, len(list))
	for _, c := range list {
		keep = append(keep, c.Channel)
	}
	q := r.db.Conn(ctx).Where("role_id = ?", roleID)
	if len(keep) > 0 {
		q = q.Where("channel NOT IN ?", keep)
	}
	if err := q.Delete(&RoleChannel{}).Error; err != nil {
		return err
	}
	if len(list) == 0 {
		return nil
	}
	// Existing rows keep created_at; only autojoin changes.
	return r.db.Conn(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "role_id"}, {Name: "channel"}},
		DoUpdates: clause.AssignmentColumns([]string{"autojoin"}),
		Where:     clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: "role_channels.autojoin IS DISTINCT FROM excluded.autojoin"}}},
	}).Create(&list).Error
}

func (r *RoleChannelRepository) Private(ctx context.Context) ([]*Access, error) {
	var out []*Access
	err := r.db.Conn(ctx).Where("private").Order("channel").Find(&out).Error
	return out, err
}

func (r *RoleChannelRepository) ReplacePrivate(ctx context.Context, channels []string, at time.Time) error {
	q := r.db.Conn(ctx).Model(&Access{})
	if len(channels) > 0 {
		q = q.Where("channel NOT IN ?", channels)
	} else {
		q = q.Where("true")
	}
	if err := q.Delete(&Access{}).Error; err != nil {
		return err
	}
	if len(channels) == 0 {
		return nil
	}
	rows := make([]Access, 0, len(channels))
	for _, c := range channels {
		rows = append(rows, Access{Channel: c, Private: true, CreatedAt: at, UpdatedAt: at})
	}
	return r.db.Conn(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
}

func (r *RoleChannelRepository) EnabledHolders(ctx context.Context, roleIDs []string) ([]*Holder, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	var out []*Holder
	err := r.db.Conn(ctx).Model(&role.UserRole{}).
		Joins("JOIN users ON users.id = user_roles.user_id AND users.disabled_at IS NULL").
		Where("user_roles.role_id IN ?", roleIDs).
		Select("user_roles.role_id, users.id AS user_id, users.username, users.username_folded").
		Order("users.username_folded, user_roles.role_id").Scan(&out).Error
	return out, err
}

func (r *RoleChannelRepository) Autojoined(ctx context.Context, userID string) ([]string, error) {
	var out []string
	err := r.db.Conn(ctx).Model(&Autojoined{}).Where("user_id = ?", userID).Order("channel").Pluck("channel", &out).Error
	return out, err
}

func (r *RoleChannelRepository) RecordAutojoined(ctx context.Context, userID string, channels, keep []string, at time.Time) error {
	q := r.db.Conn(ctx).Where("user_id = ?", userID)
	if len(keep) > 0 {
		q = q.Where("channel NOT IN ?", keep)
	}
	if err := q.Delete(&Autojoined{}).Error; err != nil {
		return err
	}
	if len(channels) == 0 {
		return nil
	}
	rows := make([]Autojoined, 0, len(channels))
	for _, c := range channels {
		rows = append(rows, Autojoined{UserID: userID, Channel: c, JoinedAt: at})
	}
	return r.db.Conn(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
}

func (r *RoleChannelRepository) EarliestOwner(ctx context.Context) (string, error) {
	var out []string
	err := r.db.Conn(ctx).Model(&role.UserRole{}).
		Joins("JOIN roles ON roles.id = user_roles.role_id AND roles.builtin = ?", role.BuiltinOwner).
		Joins("JOIN users ON users.id = user_roles.user_id AND users.disabled_at IS NULL").
		Order("user_roles.assigned_at, users.username_folded").Limit(1).Pluck("users.username", &out).Error
	if err != nil || len(out) == 0 {
		return "", err
	}
	return out[0], nil
}
