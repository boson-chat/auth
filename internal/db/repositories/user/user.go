// Package user is the users repository.
package user

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm/clause"
)

const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

var (
	ErrUsernameTaken = errors.New("username taken")
	ErrEmailTaken    = errors.New("email taken")
)

type User struct {
	ID              string
	Username        string
	UsernameFolded  string
	Email           *string
	EmailVerifiedAt *time.Time
	DisplayName     string
	// Role mirrors the roles for 1.x clients: admin iff the user holds a
	// role with admin.panel (kept in sync by the roles repository).
	Role       string
	DisabledAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	// Sign-in / activity history (admin-only): set on every new session and
	// (throttled) on session refresh. Nil = never (since this was tracked).
	// Read-only to GORM: only RecordSignIn / TouchActive write them.
	LastSignInAt     *time.Time `gorm:"->"`
	LastSignInMethod *string    `gorm:"->"`
	LastSignInIP     *string    `gorm:"->"`
	LastActiveAt     *time.Time `gorm:"->"`
}

func (User) TableName() string { return "users" }

func (u *User) Disabled() bool      { return u.DisabledAt != nil }
func (u *User) EmailVerified() bool { return u.EmailVerifiedAt != nil }
func (u *User) EmailOrEmpty() string {
	if u.Email == nil {
		return ""
	}
	return *u.Email
}

// List sort orders (all newest first; users never seen sort last).
const (
	SortCreated    = "created"
	SortLastActive = "last_active"
	SortLastSignIn = "last_sign_in"
)

// ValidSort reports whether s is a ListFilter.Sort value ("" = created).
func ValidSort(s string) bool {
	switch s {
	case "", SortCreated, SortLastActive, SortLastSignIn:
		return true
	}
	return false
}

// ListFilter selects users for admin listings.
type ListFilter struct {
	Query  string // substring of username or email
	Sort   string // SortCreated (default) | SortLastActive | SortLastSignIn
	Limit  int
	Offset int
}

type UserRepositoryImpl interface {
	Create(ctx context.Context, u *User) error
	FindByID(ctx context.Context, id string) (*User, error)
	// FindByIDForUpdate locks the row (call inside WithTx).
	FindByIDForUpdate(ctx context.Context, id string) (*User, error)
	FindByUsernameFolded(ctx context.Context, folded string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	SetEmailVerified(ctx context.Context, id string, at time.Time) error
	SetDisplayName(ctx context.Context, id, name string) error
	SetDisabled(ctx context.Context, id string, at *time.Time) error
	List(ctx context.Context, f ListFilter) ([]*User, int64, error)
	// RecordSignIn stores a successful sign-in (a new session) and counts it
	// as activity. Doesn't touch updated_at.
	RecordSignIn(ctx context.Context, id string, at time.Time, method, ip string) error
	// TouchActive sets last_active_at = at unless the stored value is newer
	// than at-minAge, so a busy user costs at most one write per minAge.
	// Reports whether it wrote.
	TouchActive(ctx context.Context, id string, at time.Time, minAge time.Duration) (bool, error)
}

type UserRepository struct {
	db *db.DB
}

func NewUserRepository(d *db.DB) UserRepositoryImpl {
	return &UserRepository{db: d}
}

func (r *UserRepository) Create(ctx context.Context, u *User) error {
	err := r.db.Conn(ctx).Create(u).Error
	switch repositories.UniqueViolation(err) {
	case "":
		return err
	case "users_email_key":
		return ErrEmailTaken
	default: // users_pkey can't collide (ULID); username / username_folded
		return ErrUsernameTaken
	}
}

func (r *UserRepository) first(ctx context.Context, query string, args ...any) (*User, error) {
	var u User
	if err := r.db.Conn(ctx).Where(query, args...).First(&u).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &u, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, repositories.ErrNotFound
	}
	return r.first(ctx, "id = ?", id)
}

func (r *UserRepository) FindByIDForUpdate(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, repositories.ErrNotFound
	}
	var u User
	err := r.db.Conn(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&u).Error
	if err != nil {
		return nil, repositories.NotFound(err)
	}
	return &u, nil
}

func (r *UserRepository) FindByUsernameFolded(ctx context.Context, folded string) (*User, error) {
	if folded == "" {
		return nil, repositories.ErrNotFound
	}
	return r.first(ctx, "username_folded = ?", folded)
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, repositories.ErrNotFound
	}
	return r.first(ctx, "email = ?", email) // citext: case-insensitive
}

func (r *UserRepository) update(ctx context.Context, id string, fields map[string]any) error {
	fields["updated_at"] = time.Now().UTC()
	res := r.db.Conn(ctx).Model(&User{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return nil
}

func (r *UserRepository) SetEmailVerified(ctx context.Context, id string, at time.Time) error {
	return r.update(ctx, id, map[string]any{"email_verified_at": at})
}

func (r *UserRepository) SetDisplayName(ctx context.Context, id, name string) error {
	return r.update(ctx, id, map[string]any{"display_name": name})
}

func (r *UserRepository) SetDisabled(ctx context.Context, id string, at *time.Time) error {
	return r.update(ctx, id, map[string]any{"disabled_at": at})
}

func (r *UserRepository) List(ctx context.Context, f ListFilter) ([]*User, int64, error) {
	q := r.db.Conn(ctx).Model(&User{})
	if s := strings.TrimSpace(f.Query); s != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s) + "%"
		q = q.Where("username ILIKE ? OR email ILIKE ?", like, like)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []*User
	err := q.Order(listOrder(f.Sort)).Limit(f.Limit).Offset(f.Offset).Find(&out).Error
	return out, total, err
}

func listOrder(sort string) string {
	switch sort {
	case SortLastActive:
		return "last_active_at DESC NULLS LAST, id DESC"
	case SortLastSignIn:
		return "last_sign_in_at DESC NULLS LAST, id DESC"
	default:
		return "created_at DESC, id DESC"
	}
}

func (r *UserRepository) RecordSignIn(ctx context.Context, id string, at time.Time, method, ip string) error {
	res := r.db.Conn(ctx).Exec(`UPDATE users SET last_sign_in_at = ?, last_sign_in_method = ?, last_sign_in_ip = ?,
		last_active_at = GREATEST(last_active_at, ?) WHERE id = ?`, at, method, ip, at, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return nil
}

func (r *UserRepository) TouchActive(ctx context.Context, id string, at time.Time, minAge time.Duration) (bool, error) {
	res := r.db.Conn(ctx).Exec(`UPDATE users SET last_active_at = ?
		WHERE id = ? AND (last_active_at IS NULL OR last_active_at <= ?)`, at, id, at.Add(-minAge))
	return res.RowsAffected > 0, res.Error
}
