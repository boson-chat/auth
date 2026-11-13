// Package user is the users repository.
package user

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
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
	Role            string
	DisabledAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
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

// ListFilter selects users for admin listings.
type ListFilter struct {
	Query  string // substring of username or email
	Limit  int
	Offset int
}

type UserRepositoryImpl interface {
	Create(ctx context.Context, u *User) error
	FindByID(ctx context.Context, id string) (*User, error)
	FindByUsernameFolded(ctx context.Context, folded string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	SetEmailVerified(ctx context.Context, id string, at time.Time) error
	SetDisplayName(ctx context.Context, id, name string) error
	SetRole(ctx context.Context, id, role string) error
	SetDisabled(ctx context.Context, id string, at *time.Time) error
	List(ctx context.Context, f ListFilter) ([]*User, int64, error)
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

func (r *UserRepository) SetRole(ctx context.Context, id, role string) error {
	return r.update(ctx, id, map[string]any{"role": role})
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
	err := q.Order("created_at DESC, id DESC").Limit(f.Limit).Offset(f.Offset).Find(&out).Error
	return out, total, err
}
