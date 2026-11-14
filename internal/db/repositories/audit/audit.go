// Package audit is the audit_log repository.
package audit

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
)

type Entry struct {
	ID string
	// UserID is the actor (or, for self-service events, the user concerned).
	UserID *string
	// TargetUserID is the user an admin action was about.
	TargetUserID *string
	Event        string
	IP           string
	Meta         repositories.JSONB
	At           time.Time
}

func (Entry) TableName() string { return "audit_log" }

// EntryView is an entry with the usernames of its actor and target.
type EntryView struct {
	Entry          `gorm:"embedded"`
	ActorUsername  *string
	TargetUsername *string
}

// Cursor is the keyset position (at, id) of the last entry of a page.
type Cursor struct {
	At time.Time
	ID string
}

// Filter selects entries, newest first.
type Filter struct {
	Events []string
	// ActorID matches user_id, TargetID matches target_user_id, and
	// AnyUserID matches either (everything about one user).
	ActorID   string
	TargetID  string
	AnyUserID string
	Since     *time.Time // at >= Since
	Until     *time.Time // at < Until
	After     *Cursor    // entries strictly older than this position
	Limit     int
}

type AuditRepositoryImpl interface {
	Create(ctx context.Context, e *Entry) error
	List(ctx context.Context, f Filter) ([]*EntryView, error)
}

type AuditRepository struct {
	db *db.DB
}

func NewAuditRepository(d *db.DB) AuditRepositoryImpl {
	return &AuditRepository{db: d}
}

func (r *AuditRepository) Create(ctx context.Context, e *Entry) error {
	return r.db.Conn(ctx).Create(e).Error
}

func (r *AuditRepository) List(ctx context.Context, f Filter) ([]*EntryView, error) {
	q := r.db.Conn(ctx).Table("audit_log AS a").
		Select("a.id, a.user_id, a.target_user_id, a.event, a.ip, a.meta, a.at, ua.username AS actor_username, ut.username AS target_username").
		Joins("LEFT JOIN users ua ON ua.id = a.user_id").
		Joins("LEFT JOIN users ut ON ut.id = a.target_user_id")
	if len(f.Events) > 0 {
		q = q.Where("a.event IN ?", f.Events)
	}
	if f.ActorID != "" {
		q = q.Where("a.user_id = ?", f.ActorID)
	}
	if f.TargetID != "" {
		q = q.Where("a.target_user_id = ?", f.TargetID)
	}
	if f.AnyUserID != "" {
		q = q.Where("(a.user_id = ? OR a.target_user_id = ?)", f.AnyUserID, f.AnyUserID)
	}
	if f.Since != nil {
		q = q.Where("a.at >= ?", *f.Since)
	}
	if f.Until != nil {
		q = q.Where("a.at < ?", *f.Until)
	}
	if f.After != nil {
		q = q.Where("(a.at, a.id) < (?, ?)", f.After.At, f.After.ID)
	}
	var out []*EntryView
	err := q.Order("a.at DESC, a.id DESC").Limit(f.Limit).Scan(&out).Error
	return out, err
}
